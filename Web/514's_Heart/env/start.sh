#!/bin/sh
set -e

echo "启动 Koishi..."
yarn start &
YARN_PID=$!


# 清理启动脚本
rm /start123123.sh

# 等待主进程结束
wait $YARN_PID

