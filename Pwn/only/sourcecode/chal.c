#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <errno.h>
#include <seccomp.h>
#include <math.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>

struct context{
    char * ptr;
    size_t size;
    size_t sum;
};

struct context ctx;
char backdoor_flag;

void sandbox() {
    struct sock_filter filter[8];
    
    filter[0] = (struct sock_filter)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 4);
    filter[1] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 0, 5);
    filter[2] = (struct sock_filter)BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 0);
    filter[3] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, 0x40000000, 3, 0);
    filter[4] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 59, 2, 0);
    filter[5] = (struct sock_filter)BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 322, 1, 0);
    filter[6] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW);
    filter[7] = (struct sock_filter)BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL);
    
    struct sock_fprog prog;
    prog.len = 8;
    prog.filter = filter;
    
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
    
}

void initial(){
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    sandbox();
    alarm(60);
}

void main_menu(){
    puts("1.notes");
    puts("2.bookkeeping");
    puts("3.exit");
}

void note_menu(){
    puts("1.create");
    puts("2.delete");
    puts("3.save");
    puts("4.edit");
    puts("5.back");
}

void add(){

    if (ctx.sum >= 25)
    {
        puts("too many!!");
        return;
    }
    
    printf("size:");
    scanf("%lu",&ctx.size);
    if(ctx.size > 0x1000){
        puts("size too large");
        //ctx.size = 0;
        return;
    }

    ctx.ptr = (char*)malloc(ctx.size);
    if(!ctx.ptr){
        perror("malloc failed");
        return;
    }

    ctx.sum++;

    puts("create success");

}

void delete(){
    if(ctx.ptr){
        free(ctx.ptr);
        ctx.ptr = NULL;
        ctx.size = 0;
        ctx.sum--;
        puts("delete success");
    } else {
        puts("empty!!");
    }
}

// void show(){
//     if (ctx.ptr) {
//         printf("content:");
//         puts(ctx.ptr);
//     }
//     else {
//         puts("empty!!");
//     }
// }

void edit(){
    if (!ctx.ptr){
        printf("content: ");
        read(0, ctx.ptr, ctx.size);
        puts("edit success");
    } else {
        puts("empty!!");
    }
}

void save(){
    char filename[16];
    char buf[64];
    if (!ctx.ptr) {
        printf("no content needs to be saved!");
    }

    printf("filename: ");
    int len = read(0, filename, 12);
    filename[len] = '\0';

    int fd = open(filename, O_CREAT | O_RDWR, 0644);
    if(fd == -1){
        snprintf(buf, 64, "failed to open %s\n", filename);
        perror(buf);
        return ;
    }
    
    write(fd, ctx.ptr, ctx.size);
    snprintf(buf, 64, "write content[%s] to %s success", ctx.ptr, filename);
    puts(buf);
    close(fd);
}

void backdoor(){

    if(backdoor_flag){
        puts("You've got help");
        return;
    }

    backdoor_flag = 1;

    puts("maybe you need some help...");
    for(int i = 0; i < 6; i++){
        printf(".");
        usleep(200000);
    }
    //printf("\n1.run your code\n2.write anywhere\n3.get a gift\nMake a choice:");
    printf("\n1.run your code\n2.get a gift\nMake a choice:");

    int choice;
    scanf("%d", &choice);    

    if(choice == 1){
        void (*shellcode)() = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if(shellcode == MAP_FAILED){
            perror("mmap failed");
            return;
        }
        memmove(shellcode, "\x48\x31\xC0\x48\x31\xDB\x48\x31\xC9\x48\x31\xD2\x48\x31\xFF\x48\x31\xF6\x4D\x31\xC0\x4D\x31\xC9\x4D\x31\xD2\x4D\x31\xDB\x4D\x31\xE4\x4D\x31\xED\x4D\x31\xF6\x4D\x31\xFF\x48\x81\xC4\x78\x56\x34\x12\x48\x81\xC5\x78\x56\x34\x12", 56);
        printf("your code:");
        int len = read(0, shellcode + 56, 9);
        memmove(shellcode + 56 + len, "\x48\x81\xEC\x78\x56\x34\x12\x48\x81\xED\x78\x56\x34\x12\xC3", 15);
        (*shellcode)();
         munmap(shellcode, 0x1000);
         puts("run success");
    }
    else if (choice == 2){
        size_t rbp;
        asm volatile ("mov %%rbp, %0" : "=r"(rbp));
        size_t canary = *(unsigned long*)(rbp - 0x8);
        printf("your gift: %lx\n", canary);
    }    
}

void note(){
    int choice;
    while(1){
        note_menu();
        scanf("%d",&choice);
       switch(choice){
            case 1:
                // add
                add();
                break;
            case 2:
                // delete
                delete();
                break;
            case 3:
                // save
                save(); 
                break;
            case 4:
               // edit
                edit();
                break;
            case 5:
                //back
                return;
            default:
                puts("Invalid choice");
        }
    }
}

void bookkeeping(){
    puts("input:");
    double tokens[32];
    double sum = 0;
    int i = 0;
    while(i < 36){
        scanf("%lf",&tokens[i]);
        if(tokens[i] == 0)
            break;
        if (*(size_t*)&tokens[i] == 0x0D0E0A0D0B0E0E0F)
            backdoor();
        sum += tokens[i];
        i++;
    }
    printf("sum: %lf\n", sum); 
}

int main(int argc, char **argv)
{
    initial();
    
    int choice;
    while(1){
        main_menu();
        scanf("%d",&choice);
        switch(choice){
            case 1:
                note();
                break;
            case 2:
                bookkeeping();
                break;
            case 3:
                _exit(0);
            default:
                puts("Invalid choice");
        }
    }
    return 0;
}

