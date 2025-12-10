# RePairing

## 附件
- `attachments/RePairing.zip`
- `env/`：附件内容解压后的运行目录。

## 题目简介
构造可重随机化的 pairing 加密服务。密文 `(c1,c2,c3)` 对随机数 `t` 线性依赖，可把随机性移到 `t+s`，因此可对挑战密文合法重随机化后调用 decrypt oracle，获得相同明文的 `KDF(M)` 并恢复 FLAG。

## Writeup
- `writeup/RCTF-suansuan.md`
