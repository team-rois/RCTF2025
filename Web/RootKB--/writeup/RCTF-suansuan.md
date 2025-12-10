### RootKB && RootKB\-\-

本题考查对 [MaxKB](https://github.com/1Panel-dev/MaxKB/tree/v2) 最新版本 v2.3.1 的 0day 挖掘。要求选手在默认 Docker 环境下，通过后台权限实现 sandbox 逃逸，最终获取到容器内的 **root 权限**。

#### 解法一：chown 跟随符号链接

我最后一次审计该项目时，最新版本为 **v2.3.0**。核心漏洞位于 `apps/common/utils/tool_code.py`：

```python
def _exec_sandbox(self, _code, _id):
        exec_python_file = f'{self.sandbox_path}/execute/{_id}.py'
        with open(exec_python_file, 'w') as file:
            file.write(_code)
            os.system(f"chown {self.user}:root {exec_python_file}")
        kwargs = {'cwd': BASE_DIR}
        subprocess_result = subprocess.run(
            ['su', '-s', python_directory, '-c', "exec(open('" + exec_python_file + "').read())", self.user],
            text=True,
            capture_output=True, **kwargs)
        os.remove(exec_python_file)
        return subprocess_result
```

关键在于：[GNU coreutils 文档](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html#index-_002d_002ddereference-2) 明确指出，`chown` 默认会跟随 symlink 并修改其目标文件。


因此，只需利用 race condition 在执行过程中让 `exec_python_file` 成为一个 symlink，即可让 `chown` 操纵系统中任意文件的所有权，通过篡改 `/etc/passwd` 实现 root 提权。

#### 解法二：LD_PRELOAD 劫持

比赛开始前两天，MaxKB 发布了 **v2.3.1**，并修复了两个相关漏洞。官方的修复策略是在执行 Python 代码前，通过 `LD_PRELOAD` 注入自定义的 `sandbox.so` 以限制网络操作：

```python
kwargs['env'] = {
    'LD_PRELOAD': f'{self.sandbox_path}/sandbox.so',
}
```

然而这又引入了新的攻击面。

`ToolExecutor` 在初始化时会**递归对 `self.sandbox_path` 做 chown**，使得整个沙箱目录在沙箱用户权限下是可写的。攻击者可以直接覆写 `sandbox.so`，自定义任意 LD_PRELOAD Hook，在 su 执行时劫持 libc 函数，提权获得 root。

#### 解法三：SSRF to RCE

由于 v2.3.1 出现了新的非预期解法，比赛在 +12 小时时放出 **v2.3.0** 的挑战 `RootKB--`。不过绝大多数选手仍然没有走解法一的路线。v2.3.0 -> v2.3.1 修复的 CVE，提示了选手可以通过 SSRF 访问内部数据库服务。而恰好：

- 除 sandbox 被降权外，**Postgres 与 Redis 均以 root 启动**；
- 题目环境干净，仅对官方镜像追加了 flag 文件，**Postgres 和 Redis 均使用默认口令**。

于是问题转化为：如何通过 SSRF 利用 Postgres / Redis 的 root 权限，实现对 `/root/flag` 的读取？类似的利用手法在今年的 QWB 中出现过。

当然这一解法其实也适用于 **v2.3.1**，因为他的 SSRF 修复实在是过于土味，很容易被绕过（
