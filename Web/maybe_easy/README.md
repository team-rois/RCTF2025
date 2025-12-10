# maybe_easy

## 附件
- `attachments/maybe_easy.jar`
- `env/`：`docker-compose.yml` 与 `maybe_easy.tar` 环境镜像。
- `POC/`：`jndiserver.jar` 与 `Poc.java` 演示利用。
- `sourcecode/maybe_easy.jar`

## 题目简介
基于 Hessian2 反序列化的利用链挖掘，需在给定 jar 中寻找可控的 `InvocationHandler` 链路并结合自建 JNDI 服务触发 RCE。

## Writeup
- `writeup/README.md`
