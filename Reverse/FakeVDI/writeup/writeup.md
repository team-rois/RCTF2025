### wp

题目分为客户端和服务端，需要两侧同时进行分析才能找到答案

#### Client - 登录前分析

题目C#部分有混淆，不过如果交给AI，基本上都能还原的差不多。不过还是建议使用[这个项目](https://github.com/MadMin3r/UnconfuserEx)进行还原，能够基本上还原成源代码的形式。

首先从类的名字中，能够找到比较特殊的`Avalonia`，可以知道这个程序是由这个框架编写而成。根据框架的特征，大部分主要的逻辑都会放在`ViewModel`和`Model`中。首先检查Login相关逻辑，可以找到几个有意思的点：

 - 程序出了用户名和密码，其实还允许我们修改ServerIP和ServerPort，甚至本地的Port。这个修改的点通过点击7次屏幕才会触发
 - 输入会检查用户名，但是只需要知道字符长度为13个字符，并且是a开头即可。并且要求密码长度为8个字节


我们在多次点击之后，确实出现了填写ip和端口的界面。之后我们就需要分析Server段的逻辑

#### Server - 登录逻辑分析


server部分没有反调试，可以直接上调试器辅助分析

通过`Login Failed`之类的字符，能够找到函数`sub_3D470`，确定这个函数中可能和登录有关。进一步分析可以找到登录逻辑在`sub_3F120`。

根据残留的符号可以推测，程序中可能存在多种加密方法，这几段相当于初始化程序加密的密钥

```rust

  alloc::raw_vec::handle_error::h18ec2e4e8895cf6e(1LL, 16LL, &off_CBF88);
  v11 = v10;
  *v10 = _mm_loadu_si128((const __m128i *)&xmmword_1D6E0);
  LODWORD(v632[0]) = 3;
  src[0].m128i_i64[0] = (__int64)"80f6650e827d164bdb1ba129543f06aea414c0e77e372cc49d29494ff9eeaf6c145818cff9512c9803a401b"；
  src[1] = (__m128i)2uLL;
  src[2].m128i_i64[0] = (__int64)v632;


  alloc::raw_vec::handle_error::h18ec2e4e8895cf6e(1LL, 8LL, &off_CBF88);
  v25 = (__int64)v24;
  *v24 = 'MYEMBDJF';
  v634[0].m128i_i32[0] = 3;
  src[0].m128i_i64[0] = (__int64)a1430e877a79866;
  src[0].m128i_i64[1] = 32LL;
  src[1] = (__m128i)2uLL;
  src[2].m128i_i64[0] = (__int64)v634;
```

总共有四段初始化的逻辑，而且根据我们输入的数据调试，可以发现程序最终会来到调用aes的逻辑部分:
```cpp
 memcpy(v67, a1, v42);
v507.m128i_i64[0] = v42;
v507.m128i_i64[1] = (__int64)v67;
v508 = v42;
if ( v47 != 16 )
goto LABEL_276;
v81 = v496;
if ( aes::autodetect::aes_intrinsics::STORAGE::h38d98e4b948bc3d2[0] == 1
|| aes::autodetect::aes_intrinsics::STORAGE::h38d98e4b948bc3d2[0] == 255
&& (unsigned __int8)aes::autodetect::aes_intrinsics::init_get::init_inner::hcbb30da97e9a2afc() )
{
_$LT$aes..ni..Aes128Enc$u20$as$u20$crypto_common..KeyInit$GT$::new::h285605b036447c56(v634, v46);
aes::ni::aes128::inv_expanded_keys::h694c9fdcf6748c38(&v633[11], v634);
memcpy(v633, v634, 0xB0uLL);
v81 = v496;
memcpy(src, v633, 0x160uLL);
}
```

之后会和一个内存中内置变量进行比较，变量正好来自于之前初始化的逻辑。于是我们可以写出解密脚本:
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def aes_decrypt_cbc(key: bytes, ciphertext: bytes,iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC,iv=iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    return plaintext


key = b"SKygB9j6Odefxq2W"
iv = b"FHwewU_SSNSXi3hu"
cipher = bytes.fromhex("134432739c43fbc956367f49e25b6c0c")
print(aes_decrypt_cbc(key,cipher, iv))

```
得到用户名为`adm1niStrat0r`

直接调试，可以发现程序最终会生成一大堆hash表，但是只会取出`3deac81ae94603bf18ab1b70f48fa77f`这个hash值。然后在[这个网站](https://www.somd5.com/)能够解开，得到密码为
```
P@sswOrd
```

不过如果此时尝试登录，会发现用户端报错，提示network error。进一步分析逻辑会发现，服务端会验证客户端的请求发起有端口要求。这里可以选择patch服务端或者客户端，都能继续逻辑。



之后可以选择分析用户端或者服务端。这里继续分析服务端。可以看到后续逻辑会接受来自客户端的数据，然后根据一个什么值，传入后，进行RC4解密，关键函数就是`sub_4E360`。调试后会发现，这一段数据中

 - 使用的key来自于之前从服务端往客户端发送的一个数据，这个数据是由之前的用户名和密码一起算出来的，这里可以将其定义为`session_id`。这个值为`4659270777073628827`
 - 使用key解开的数据，如果使用数据包抓包后，可以发现是一个bmp文件

这些bmp文件就是一开始在`server`目录中的`res`加载，并且用session_id解开的数据。于是我们可以知道

 - 当我们登录成功后，就会产生一个`session_id`，这个`session_id`会成为本地的几个图片的密钥


#### Server - 路径分析

在我们返回图片之前，有一段逻辑
```rust
if ( (unsigned __int8)sub_4D9F0(v102, v103, v93) && sub_4DCD0(v102, v103, v104) )
{
    *(_QWORD *)&v112 = &off_CBDE8; // You conquered the grid of 81 trials!\n
    *((_QWORD *)&v112 + 1) = 1LL;
    v113.m256i_i64[0] = 8LL;
    *(_OWORD *)&v113.m256i_u64[1] = 0LL;
    std::io::stdio::_print::h87d04f1826f04caf(&v112);
}
```

其中`sub_4D9F0`函数分析以后，可以知道，这段逻辑和之前的路径有关。这里面包含一个hash函数，会将我们当前的路径算一个hash:
```cpp
  if ( (unsigned __int64)xmmword_D4530 >= qword_D4568 )
    core::panicking::panic_bounds_check::h5443494609ce8457(xmmword_D4530, qword_D4568, &off_CC628, v7);
  if ( ((int)v3 ^ (unsigned __int64)(v8 << 32) ^ (0x9E3779B97F4A7C15LL * v9)) == *(_QWORD *)(qword_D4560
                                                                                           + 8 * xmmword_D4530) )
  {
    a1 = (__int64 *)(xmmword_D4530 + 1);
    *(_QWORD *)&xmmword_D4530 = xmmword_D4530 + 1;
    DWORD2(xmmword_D4530) = v5;
    HIDWORD(xmmword_D4530) = v4;
  }
```

根据动态调试，可以找到这些hash值。然后根据逻辑可以分析得到，此处计算的是**前进方向向量**的hash值，于是可以还原成这样:
```
//起点(0,0)
(1,0), // (1,0)
(-1,0), // (0,0)
(-1,0), // (-1,0)
(1,0), // (0,0)
(0,1), // (0,1)
(1,0), // (1,1)
(1,0), // (2,1) 
(0,1), // (2,2) 
(0,1), // (2,3) 
(1,0), // (3,3) 
(0,-1), // (3,2) 
(-1,0), // (2,2)
```


#### Client - 渲染路径

回到客户端，会发现我们输入`wsad`就可以实现上下左右的移动。并且我们之前在Client Login逻辑中，就会发现一个会用session_id异或的逻辑
```C#
// 7. 登录成功！
// [Restored] 使用获取的会话密钥解密一个静态数据块
LoginViewModel.XorDecrypt(DrawImage.Data, this._sessionKey);

// [Restored] 通知主窗口切换视图，并传入TCP连接和密钥
this._mainWindowViewModel.ShowMainView(tcpclientWrapper, this._sessionKey);
```
在移动过程中，我们会发现server返回的图片会被计算一个hash值，然后反复与这个目标值进行异或。结合server端的逻辑，不难想到要按照指定的方式移动我们的角色。

然而，我们可以知道，程序本质上并没有移动角色，而是画了角色在不同坐标上的图，而且**图片显然是缺失了的**。于是能猜到，题目可能是需要我们**手动绘制目标图片**。（结合提示 99 81难，暗示这里其实是9x9的tile组成的）。根据其他图片，可以知道每次角色移动的距离是相同的。于是可以写出一个重新渲染角色移动的脚本。

这里给出一个可以移动角色的脚本
```python
from PIL import Image
import numpy as np

def move_object(img_path, object_pos, out_path, dx, dy, tile_size=64, bg_color=(255,255,255)):
    # 打开原始图像并保留原始 DPI 信息
    img = Image.open(img_path).convert("RGB")
    dpi = img.info.get("dpi", (96, 96))  # 如果原图没有dpi信息，默认96
    arr = np.array(img)

    # 找对象位置
    # object_pos = (4,4)
    if object_pos is None:
        print("没有检测到对象！")
        return

    row, col = object_pos
    print(f"检测到对象在格子 row={row}, col={col}")

    # 裁剪出对象
    x, y = col * tile_size, row * tile_size
    obj = arr[y:y+tile_size, x:x+tile_size].copy()

    # 清空原位置
    arr[y:y+tile_size, x:x+tile_size] = bg_color

    # 新位置
    new_x = x + dx * tile_size
    new_y = y + dy * tile_size
    if new_x < 0 or new_y < 0 or new_x+tile_size > arr.shape[1] or new_y+tile_size > arr.shape[0]:
        print("移动超出边界！")
        return

    arr[new_y:new_y+tile_size, new_x:new_x+tile_size] = obj

    # 保存，带上原始DPI信息
    Image.fromarray(arr).save(out_path, format="BMP", dpi=dpi)
    print(f"已保存到 {out_path}，保持原始 DPI = {dpi}")


move_object("00.bmp", (4,4), "3m2.bmp", dx=3, dy=-2, tile_size=64, bg_color=(64,151,64))
```

之后我们就能画出我们需要的目标图片。之后我们可以将图片加密放到服务端，又或者手动算出hash值之后，用于解密。最终可以得到答案:  

![](./img/flag.jpg)  

