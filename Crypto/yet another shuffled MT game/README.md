# yet another shuffled MT game

## 附件
- `attachments/yet another shuffled MT game.zip`
- `env/`：原附件已解压，可直接运行。

## 题目简介
仅给定 16400 个确定性输出，MT19937 内部状态不足，输出再经 shuffle 打乱。需要审计 Sage 中 PY-MT 的懒初始化流程，通过构造可预测的 GMP-MT 输出，锁定 PY-MT 的 128 位种子后才能恢复 shuffle 结果，再进一步求解 GMP-MT 种子。

## Writeup
- `writeup/RCTF-suansuan.md`
