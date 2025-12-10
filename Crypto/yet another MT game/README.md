# yet another MT game

## 附件
- `attachments/yet another MT game.zip`：官方原始附件。
- `env/`：已将附件解压后的环境，便于直接复现。

## 题目简介
SageMath 使用 GMP-MT 与 PY-MT 两套 PRNG。本题利用 Sage 在 `random_matrix(Zmod(2**n), n_leak)` 中对 26 位以内模数调用 GMP-MT 的行为，结合泄露的低位，恢复 GMP-MT19937 的完整内部状态并还原种子。

## Writeup
- `writeup/RCTF-suansuan.md`
