### yet another MT game (5 solves)

> 本题的灵感来自之前 CTF 比赛中 sagemath 中伪随机数生成器导致的一些非预期解，比如 2024 N1CTF 的 [M4sTeriX](https://github.com/hash-hash/My-CTF-Challenges/tree/main/n1ctf%202024/M4sTeriX) 的非预期。于是我对 sagemath 的伪随机数生成器的设计进行了简单审计，有了这两道题。

Sagemath 的伪随机数生成器基本与 python 一致，均使用了 MT19937 算法，其核心逻辑在文件 [sage/misc/randstate.pyx](https://github.com/sagemath/sage/blob/209ae4c3a438d27f552bde829cbe91edde488578/src/sage/misc/randstate.pyx) 中定义，可以知道，Sagemath 中存在两个 MT 随机数生成器，其中一个是 C++ 中 GMP 实现的 MT19937，它对应全局的 `current_randstate` 变量，另一个是 python 的 MT 随机数生成器，它对应 `current_randstate().python_random()`，基于 python 原生的 `random.Random` 类，而 `set_random_seed(int.from_bytes(secret, 'big'))` 实际上初始化了 GMP 的 MT 随机数生成器，它会触发 `current_randstate` 的 [初始化](https://github.com/sagemath/sage/blob/209ae4c3a438d27f552bde829cbe91edde488578/src/sage/misc/randstate.pyx#L540):

```python
    mpz_init(mpz_seed)
    mpz_set_pylong(mpz_seed, seed)
    gmp_randseed(self.gmp_state, mpz_seed)
    mpz_clear(mpz_seed)
```

本题需要恢复 GMP-MT19937 的随机数种子，不只局限于 sagemath 的源码，本题有两个点需要详细审计的：

1. GMP-MT19937 的种子初始化：参考源码 [rand/randmts.c#L108](https://github.com/alisw/GMP/blob/2bbd52703e5af82509773264bfbd20ff8464804f/rand/randmts.c#L108)，核心逻辑是 [mangle_seed](https://github.com/alisw/GMP/blob/2bbd52703e5af82509773264bfbd20ff8464804f/rand/randmts.c#L38), 即 19937 比特的初始状态由 `POW(SEED, E, P)` 生成，写成 python 即：

   ``` python
   import gmpy2
   
   WARM_UP = 2000
   N = 624
   M = 396
   MAX_MT_POWER = 2**19937
   E = 1074888996
   GE = 12 # GCD(E, MAX_MT_POWER - 20023 - 1)
   D = pow(E//GE, -1, MAX_MT_POWER - 20023 - 1)
   
   def mangle_seed(seed, e=1074888996):
       # GMP's mangle_seed function
       # https://github.com/alisw/GMP/blob/2bbd52703e5af82509773264bfbd20ff8464804f/rand/randmts.c#L37
       # Calculate (b^e) mod (2^n-k) for e=1074888996, n=19937 and k=20023,
       return int(gmpy2.powmod(seed, e, MAX_MT_POWER - 20023))
   
   def randseed_mt_state(seed: int):
       seed = seed % (MAX_MT_POWER - 20027) + 2
       seed = mangle_seed(seed)
       mt_state = [0] * 624
       for i in range(1, N):
           mt_state[i] = seed & 0xFFFFFFFF
           seed >>= 32
       mt_state[0] = seed * 0x80000000
       # mt_state[N - 1] = seed2
       assert seed == 0 or seed == 1, f"Invalid case: {seed = }"
       return mt_state
   
   def randseed_gmp_mt(seed: int, warm_up= WARM_UP):
       mt_state = randseed_mt_state(seed)
       for i in range(warm_up//N):
           mt_state = twist(mt_state)
       prng = random.Random()
       prng.setstate((3, tuple(mt_state + [(warm_up + 1) % N]), None))
       return prng
   ```

   	这里需要求解一个类似 RSA 的问题，然后有限域开根。

2. sagemath 中的 `random_matrix(Zmod(2**n_bit), n_leak).list()` 调用的 prng 取决于环的大小，当 `n_bit <= 26` 时，调用的是 GMP 的 MT 随机数生成器，而当 `n_bit > 26` 时，调用的是 python 的 MT 随机数生成器。因此如果想要恢复 GMP 的 MT 随机数生成器的状态，必须保证 `n_bit <= 26`。这部分代码审计起来比较麻烦，可以参考 [sage_prng_tester.py](https://github.com/tl2cents/Public-CTF-Challenges/blob/master/rctf2025/yet-another-mt-game-v1/sage_prng_tester.py) 中的测试代码，在本地测试一些 sage 的随机 oracle 调用的是哪个 PRNG。

综上，一个比较好的选择是取模数 $2^{16}$，刚好泄露低 16 比特，总计可以泄露 16 × 1246 = 19936 比特，而且这些方程的线性空间是满秩的（即秩 19936），最后只需要穷举一比特。还需要注意的一个点是必须精确对齐 MT 的内部状态，直接恢复 Seed，因为恢复种子需要在 19937 比特的有限域上开根，该计算非常慢，穷举初始 MT 状态的偏移的计算量比较大。如果 GMP 源码审计得比较清楚的话，预先进行一个 WARM-UP 的操作就能对齐 MT 内部状态，然后通过 maple 的板子 [gf2bv](https://github.com/maple3142/gf2bv/tree/master/gf2bv) 就能很方便地求解出这题，详情参考 [exp.py](https://github.com/tl2cents/Public-CTF-Challenges/tree/master/rctf2025/yet-another-mt-game-v1) 的实现。

> 忘记卡种子的长度了，所以最后恢复种子可以直接在整数上开根 `gmpy2.iroot(seed12, 12)`，没必要在有限域上开根。

EXP 等已归档至 [GitHub 仓库](https://github.com/tl2cents/Public-CTF-Challenges/tree/master/rctf2025/yet-another-mt-game-v1)。
