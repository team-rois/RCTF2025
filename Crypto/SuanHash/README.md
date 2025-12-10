# SuanHash

## 附件
- `attachments/SuanHash.zip`
- `env/`：解压后的题目脚本与数据。

## 题目简介
SuanHash 仿照 sponge 结构，但 `_core()` 在挤出阶段将状态几乎全部暴露：输出的高 64 位直接等于状态高半，低 64 位则是上一状态低位与本块低 64 位的线性组合。因此两条单块消息即可恢复状态差 Δ，再构造下一块输入 `B xor Δ` 形成完全相同的 mixed，从而产生碰撞。

## Writeup
- `writeup/RCTF-suansuan.md`
