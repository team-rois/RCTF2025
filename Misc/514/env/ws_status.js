/**
 * ws_status.js
 * Koishi WebSocket 后台监控 + 自动修复脚本
 * 每 10 秒检查一次 plugins，按初始状态强制保持一致
 */

const WebSocket = require('ws');

const WS_URL = 'ws://127.0.0.1:5140/status';
let ws;
let pendingResolve = null;

// 记录启动时获取的初始配置（程序启动后第一次 reload 获取）
let initialConfig = null;

/* ---------------- 工具函数 ---------------- */

function deepEqual(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

function parseGroupName(group) {
  // return group.startsWith("group:") ? group.replace(/^group:/, "") : "";
  return group.replace(/^group:/, "");
}

function diffPlugins(initial, current) {
  const added = [];
  const changed = [];
  const removed = [];

  const iPlugins = initial.plugins || {};
  const cPlugins = current.plugins || {};

  /* 所有 group:xxx 的组 */
  const initialGroups = Object.keys(iPlugins).filter(g => g.startsWith("group:"));
  const currentGroups  = Object.keys(cPlugins).filter(g => g.startsWith("group:"));

  /* 所有非 group 的顶级 plugins（group=""） */
  const initialRootPlugins = Object.keys(iPlugins).filter(g => !g.startsWith("group:"));
  const currentRootPlugins  = Object.keys(cPlugins).filter(g => !g.startsWith("group:"));

  /* ========== 处理 group 内部插件 ========== */

  for (const groupKey of currentGroups) {
    const group = groupKey.replace(/^group:/, "");
    const curGroupItems = cPlugins[groupKey];
    const initGroupItems = iPlugins[groupKey] || {};

    // 当前有的插件
    for (const key in curGroupItems) {
      const curVal = curGroupItems[key];
      const initVal = initGroupItems[key];

      if (initVal === undefined) {
        added.push({ group, key });
      } else if (!deepEqual(curVal, initVal)) {
        changed.push({ group, key, value: initVal });
      }
    }

    // initial 有但 current 没有的插件（被删除）
    for (const key in initGroupItems) {
      if (!(key in curGroupItems)) {
        removed.push({ group, key, value: initGroupItems[key] });
      }
    }
  }

  /* ========== 处理 group="" 的顶级插件 ========== */

  for (const key of currentRootPlugins) {
    const curVal = cPlugins[key];
    const initVal = iPlugins[key];

    if (initVal === undefined) {
      added.push({ group: "", key });
    } else if (!deepEqual(curVal, initVal)) {
      changed.push({ group: "", key, value: initVal });
    }
  }

  for (const key of initialRootPlugins) {
    if (!(key in cPlugins)) {
      removed.push({ group: "", key, value: iPlugins[key] });
    }
  }

  return { added, changed, removed };
}


/* ---------------- WebSocket 发送消息 ---------------- */

function sendMessageAwaitSecondData(msg) {
  return new Promise((resolve, reject) => {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      return reject(new Error('WebSocket 未连接'));
    }

    pendingResolve = resolve;
    ws.send(JSON.stringify(msg));
  });
}

/* ---------------- 处理配置检查与修复 ---------------- */

async function checkAndFixConfig() {
  try {
    const response = await sendMessageAwaitSecondData({
      id: "reload_check",
      type: "manager/reload",
      args: ["", "screenshot:lsan28", {}]
    });

    const current = response?.body?.value;

    if (!current || !current.plugins) {
      console.warn("未获取到有效配置，跳过检查");
      return;
    }

    // 第一次运行 → 记录初始配置
    if (!initialConfig) {
      console.log("初始化 baseline 配置完成");
      initialConfig = current;
      return;
    }

    const { added, changed, removed } = diffPlugins(initialConfig, current);

    /* --- 删除新增 --- */
    for (const p of added) {
      console.log(`删除新增插件: group=${p.group}, key=${p.key}`);
      await sendMessageAwaitSecondData({
        id: `remove_${p.key}`,
        type: "manager/remove",
        args: [p.group, p.key]
      });
    }

    /* --- 恢复变动 --- */
    for (const p of changed) {
      console.log(`恢复变更插件: group=${p.group}, key=${p.key}`);
      await sendMessageAwaitSecondData({
        id: `restore_change_${p.key}`,
        type: "manager/reload",
        args: [p.group, p.key, p.value]
      });
    }

    /* --- 恢复被删除 --- */
    for (const p of removed) {
      console.log(`恢复被删除插件: group=${p.group}, key=${p.key}`);
      await sendMessageAwaitSecondData({
        id: `restore_deleted_${p.key}`,
        type: "manager/reload",
        args: [p.group, p.key, p.value]
      });
    }

  } catch (err) {
    console.error("检查配置失败:", err);
  }
}

/* ---------------- WebSocket 连接管理 ---------------- */

function connectWS() {
  ws = new WebSocket(WS_URL);

  ws.on('open', () => {
    console.log("WebSocket 已连接");
  });

  ws.on('message', (data) => {
    let parsed = null;
    try {
      parsed = JSON.parse(data.toString());
    } catch {}

    if (parsed && parsed.type === 'data' && pendingResolve) {
      pendingResolve(parsed);
      pendingResolve = null;
    }
  });

  ws.on('close', () => {
    console.log("WebSocket 已断开，3 秒后重连...");
    setTimeout(connectWS, 3000);
  });

  ws.on('error', (err) => {
    console.error("WebSocket 错误:", err);
  });
}

/* ---------------- 定时任务 ---------------- */

connectWS();
setInterval(checkAndFixConfig, 10000);   // 每 10 秒检查
