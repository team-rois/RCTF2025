#!/bin/sh

echo "[INFO] 启动 Koishi 主进程..."
yarn start &

sleep 5

cd /tmp

yarn add ws
echo "[INFO] 启动 WebSocket 后台任务..."
rm /koishi/114514.txt
node /tmp/ws_status.js

# 保持前台进程（防止容器退出）
wait -n
