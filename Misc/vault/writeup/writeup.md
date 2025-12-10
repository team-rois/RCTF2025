## this is a writeup

1. 题目使用了ottersec 的sui ctf framework，题目本身代码不多，主要是模拟一个合约在现实世界种可能存在的问题，合约里面预埋了一些漏洞，但是主要解题的漏洞还是 因为vault_coin 里面 public share了 treasury_cap 导致任意用户拿到treasury_cap 可以任意铸币。 空投后即可购买flag。

2. 作为solve 主要是弄明白 framework 的 传入的一些 object，将其归位。 对于没有接触过类似framework的ctf玩家来说还是具有挑战性的。