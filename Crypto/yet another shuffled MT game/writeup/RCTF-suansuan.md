### yet another shuffled MT game (2 solves)

本题只给了 16400 个确定性的输出，而 MT19937 的内部状态有 19968 位（仅 19937 位是有效的），因此无法直接逆推出完整的状态。超出该界限之后，MT19937 的输出完全被 shuffle 操作打乱，无法直接利用。尽管 `random_matrix` 在环参数比较小时使用的是 GMP-MT，shuffle 使用的 PY-MT，它们互不影响，从而 shuffle 后的汉明重量可以提供一些整数环上的方程，但是在限制了 3 次交互的情况下，泄漏的汉明重量信息肯定不足以恢复未知的近 3000 比特。

这题后面的思路需要了解一些 sage 的机制，核心在于 sagemath 中 GMP-MT 和 PY-MT 的初始化的逻辑。经过审计我们发现，从 sagemath 中加载的 shuffle，它底层状态依赖于 `current_randstate().python_random()`，也就是 PY-MT:

```python
# https://github.com/sagemath/sage/blob/develop/src/sage/misc/prandom.py#L61
from sage.misc.randstate import current_randstate
def _pyrand():
    # ...
    return current_randstate().python_random()

def shuffle(x):
    # ...
    return _pyrand().shuffle(x)
```

注意到这个 PY-MT 的[初始化逻辑](https://github.com/sagemath/sage/blob/209ae4c3a438d27f552bde829cbe91edde488578/src/sage/misc/randstate.pyx#L568) 如下：

```python
    def python_random(self, cls=None, seed=None):
        if cls is None:
            cls = DEFAULT_PYTHON_RANDOM

        if type(self._python_random) is cls:
            return self._python_random

        from sage.rings.integer_ring import ZZ
        rand = cls()
        if seed is None:
            rand.seed(long(ZZ.random_element(long(1)<<128)))
        else:
            rand.seed(long(seed))
        self._python_random = rand
        return rand
```

从上面的逻辑看，PY-MT 初始化遵循 Lazy Initialization 模式：只要我们从没有调用过 PY-MT 相关的随机数操作，那么 PY-MT 就不会被初始化。因此，`set_random_seed` 只初始化 GMP-MT，而 PY-MT 不会马上初始化，而是**等到第一次调用 PY-MT 相关函数的时候才会初始化**，具体操作是从 GMP-MT 的输出中读取 128 比特随机数作为种子，即 `ZZ.random_element(1<<128)`。在已经有 16400 确定性方程的情况，我们是能预测一些后续的输出的，只要能够使得 `IS_BROKEN=True` 第一次调用 shuffle 时，PY-MT 的 128 比特种子能够被我们预测到，那么后面所有的 shuffle 我们都能恢复，得到真实的方程。然后就是与第一问类似的思路，恢复初始的 seed。关键点在于：

> **如何选择泄露的模式，使得 python 的 MT19937 的种子能够被我们预测到，这个可预测的位置怎么求？**

本题没有过多卡这个过程的参数，具体来说在本地固定泄露的比特数和数量，求解方程，然后测试能够预测出哪些后续比特即可，这个预测的过程可以通过部分高斯消元实现。我的 exp 选择了直接用新的 kernel space 的基来重新定义 MT19937 的状态，即先根据前 16400 个确定性方程 $Mx = y$，求一个特解 s 以及 $M$ 的核空间基 $k_1,k_2,...,k_r$，然后整个 MT19937 的状态向量可以如下表示：

$$
x = s + \sum_{i}^{r} c_i k_i
$$

其中 $`c_i \in \mathbb{F}_2`$。后续所有向量都可以表示为 $`x`$ 的线性函数，也即 $`C = (c_1, c_2, \ldots, c_{r})`$ 的线性函数。

模拟后续 MT-19937 的线性操作，只要后续输出比特是一个关于 $`C = (c_1, c_2, \ldots, c_{r})`$ 的常量多项式，那么它就是一个确定性的输出，可以被预测到。然后我们就可以尝试找到一个偏移，使得触发 PY-MT 的初始化时，`ZZ.random_element(1<<128)` 的输出全部都是确定性（连续 128 比特输出）。这里还需要审计的一个点是 `ZZ.random_element(1<<128)` 会额外消耗 32 比特 [sage/src/sage/rings/integer_ring.pyx](https://github.com/sagemath/sage/blob/5c8d9e9a75a734068e9c11f682b0b1bede6814a9/src/sage/rings/integer_ring.pyx#L801)，然后再取 128 随机比特，因此 PY-MT 的初始化会用掉 160 比特随机数（GMP-MT 进行 5 次 temper），但是种子只有 128 比特。EXP 使用 maple 的板子 [gf2bv](https://github.com/maple3142/gf2bv/tree/master/gf2bv)，将 MT19937 状态定义成核向量空间的线性组合，就能够很好地模拟上述线性操作以及判断某个位置的 MT19937 的输出比特是否是常数。

#### 非预期解法

本题的比赛上的两个解（Nu1l 和 N0wayBack）都是非预期解法，但是核心思想是类似的，需要完整恢复 PY-MT 的状态。不同点在于，第一步先拿 16400 比特的 PY-MT 的输出，因为 python 的 MT19937 的种子初始化比较简单，这些方程可以直接恢复出 PY-MT 的种子，从而预测出后续的 shuffle，之后我们再拿 GMP-MT 的输出，就能构建确定性的方程了。在限制方程数量的条件下，Python 的随机数种子恢复可以参考 [python_random_breaker.py](https://github.com/Aeren1564/CTF_Library/blob/master/CTF_Library/Cryptography/MersenneTwister/python_random_breaker.py)。

EXP 等已归档至 [GitHub 仓库](https://github.com/tl2cents/Public-CTF-Challenges/tree/master/rctf2025/yet-another-mt-game-v2)。
