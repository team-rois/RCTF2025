## 题目信息

本题是一个摄影师分享平台，用户可以注册账号、上传照片、发布作品等。目标是获取 `/superadmin.php` 页面中的 FLAG。



## 漏洞分析

### 1. 目标分析

查看 `public/superadmin.php` 文件：

```php
<?php
require_once __DIR__ . '/../app/config/autoload.php';

Auth::init();

$user_types = config('user_types');

if (Auth::check() && Auth::type() < $user_types['admin']) {
    echo getenv('FLAG') ?: 'RCTF{test_flag}';
}else{
    header('Location: /');
}
```

要获取 FLAG，需要满足两个条件：
1. `Auth::check()` 返回 true（已登录）
2. `Auth::type() < $user_types['admin']`（用户类型小于 0）

查看配置文件 `app/config/config.php`：

```php
'user_types' => [
    'admin' => 0,
    'auditor' => 1,
    'user' => 2
],
```

普通用户的 type 为 2，需要让 `Auth::type()` 返回值小于 0。



### 2. SQLite JOIN 字段覆盖

查看 `app/middlewares/Auth.php` 的第 11-13 行：

```php
if (isset($_SESSION['user_id'])) {
    self::$user = User::findById($_SESSION['user_id']);
}
```

再看 `app/models/User.php` 的 `findById` 方法：

```php
public static function findById($userId) {
    return DB::table('user')
        ->leftJoin('photo', 'user.background_photo_id', '=', 'photo.id')
        ->where('user.id', '=', $userId)
        ->first();
}
```

**关键问题：** [SQLite3Result::fetchArray Doesn't Handle Join Statement Properly · Issue #20300 · php/php-src](https://github.com/php/php-src/issues/20300)

该方法使用了 LEFT JOIN 将 `user` 表和 `photo` 表连接起来（通过用户的背景图片 ID）查询所有字段，**当 JOIN 查询存在同名字段时，后面 JOIN 的表的字段会覆盖前面表的字段**。

- `user` 表有 `type` 字段（存储用户类型：0=admin, 1=auditor, 2=user）
- `photo` 表也有 `type` 字段（存储图片的 MIME 类型，如 "image/jpeg"）

当用户设置了背景图片后，`findById` 方法返回的结果中，`type` 字段会被 `photo.type` 覆盖



### 3.图片伪造Type

查看 `app/controllers/PhotoController.php` 的上传逻辑：

```php
$file = [
    'name' => $files['name'][$i],
    'type' => $files['type'][$i],  // 从 $_FILES 获取，可被伪造
    'tmp_name' => $files['tmp_name'][$i],
    'error' => $files['error'][$i],
    'size' => $files['size'][$i]
];

// ...

$result = Photo::create([
    'user_id' => Auth::id(),
    'original_filename' => $file['name'],
    'saved_filename' => $savedFilename,
    'type' => $file['type'],  // 直接使用客户端提供的 type
    // ...
]);
```

关键点：照片的 `type` 字段直接从 `$_FILES['photos']['type']` 获取，而这个值可以被客户端伪造！





## 攻击思路

攻击步骤：
1. 注册并登录一个普通账号
2. 上传一张照片，**将照片的 MIME type 设置为负数**（如 `-1`）
3. 将这张照片设置为个人背景图
4. 访问 `/superadmin.php`，此时 `Auth::type()` 会返回 `-1`，满足 `< 0` 的条件，成功获取 FLAG



