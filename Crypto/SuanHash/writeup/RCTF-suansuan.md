### SuanHash (10 solves)

SuanHash 是一个仿 sponge 的结构，本来 sponge 应该在挤出阶段确保 capacity 部分永不泄露，否则破坏安全性。但 `_core()` 挤出实现把状态几乎全部暴露了出来。

SuanHash 的最终输出，其实就是内部状态的高 64 位直接输出，低 64 位则是“最后一次吸收运算中 mixed 的低 64 位”再异或内部状态的低 64 位。mixed 的低位 = （上一状态的低 64 位）异或（本次块的低 64 位）。因此，单块消息的输出结构是：

- high = U1（吸收完该块后的状态高 64 位）

- low = (L0 xor B_low) xor L1（其中 L0/L1 是吸收前/吸收后的状态低 64 位，B_low 是该消息块的低 64 位）

对于单块消息，这就是一个线性函数：输出的高半是真实的 U1；输出的低半是 L0 xor B_low xor L1。块的低 64 位 B_low 是我们完全知道的（因为填充规则固定），输出 (high, low) 是服务端给的，因此两条单块消息的输出，使我们可以直接推回它们吸收后的状态差分 S1 xor S2。方法就是：高 64 位的差分直接等于 high1 xor high2；低 64 位的差分可以由 (low1 xor B1_low) xor (low2 xor B2_low) 计算出来，因为它等于 L1 xor L2。于是我们完全恢复了吸收一块后的状态差分 Δ = (Δ_hi, Δ_lo)。

有了这个 Δ，后续的碰撞是直接成立的。假设第一条消息吸收完第一块后状态是 S1，第二条消息吸收完第一块后状态是 S2，那么它们满足 S1 xor S2 = Δ。我们希望第二块让它们在进入置换（AES）之前的 mixed 完全一致。mixed1 = S1 xor B，mixed2 = S2 xor B'，要 mixed1 = mixed2，就必须让 B' = B xor Δ。这样 mixed2 = S2 xor (B xor Δ) = S2 xor (B xor S1 xor S2) = S1 xor B = mixed1。于是这两个 mixed 输入相同，AES 输出当然相同，吸收后的最终状态也相同，挤出阶段的输出自然相同，从而得到碰撞。
