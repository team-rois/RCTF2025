# photographer

## 附件
- `attachments/photographer.zip`
- `env/`：PHP 照片分享站点源码与 SQLite 数据库。

## 题目简介
`User::findById` 用 JOIN 拉取背景图，`photo.type` 会覆盖 `user.type`；上传时 MIME type 直接信任客户端。上传一张 type=-1 的图片并设为背景后，`Auth::type()` 变为 -1，满足 `/superadmin.php` 的低权限校验读取 FLAG。

## Writeup
- `writeup/README.md`
