const WebSocket = require('ws');
const deepEqual = require('fast-deep-equal');

const WS_URL = 'ws://127.0.0.1:5140/status';
const INTERVAL = 15000; // 15秒

// 初始配置（完整配置）
const initialConfig = {
  "plugins": {
    "group:server": {
      "server:yrt4za": { "port": 5140, "maxPort": 5149 },
      "~server-satori:4a5c8c": {},
      "~server-temp:in16cp": {}
    },
    "group:basic": {
      "~admin:tnisa7": {},
      "~bind:07uqcj": {},
      "commands:fcfz9r": {} ,
      "help:tj2694": {} ,
      "http:c3980a": {} ,
      "~inspect:bep4w8": {},
      "locales:10cpca": {} ,
      "rate-limit:9enlml": {}
    },
    "group:console": {
      "actions:12nvqa": {} ,
      "analytics:j8afpj": {} ,
      "~auth:hfi7d9": { "admin": { "password": "royYFYwxQel8iZK+0ztjGw==NPYRAZTlWuW+Yx/8ZAVNXQ==" } },
      "config:ab6k8s": {} ,
      "console:n2unsp": { "open": false } ,
      "insight:blbpmd": {},
      "market:734ssq": { "search": { "endpoint": "https://gitee.com/shangxueink/koishi-registry-aggregator/raw/gh-pages/market.json" } } ,
      "notifier:fjhc7z": {},
      "oobe:pblvay": {} ,
      "sandbox:a8395u": {} ,
      "status:mgd9ai": {} ,
      "theme-vanilla:zw7dvu": {}
    },
    "group:storage": {
      "~database-mongo:e4iopx": { "database": "koishi" },
      "~database-mysql:sqfsc4": { "database": "koishi" },
      "~database-postgres:yixoph": { "database": "koishi" },
      "database-sqlite:l9px0e": { "path": "data/koishi.db" },
      "assets-local:9psdxd": {}
    },
    "group:adapter": {
      "~adapter-dingtalk:nt9ml6": {},
      "adapter-discord:cm64td": {
        "token": "xYmaPePXtVsUQWGY74db1t4iq1Ojqas8xJjIkQHxiFYx7Oi8GrwOxqegcRbERkLuN9i5d1hbJAMzc2UVZkzsq8jsJ8EPl+VunX5qCM9cVhyZqB3F5W+cuvfdc4XZOWowrrFaIg/ofYJw9uPENah7/Q==3WD1TcLcp2eo4Sy4u/T4wg==",
        "intents": ["DIRECT_MESSAGES"]
      },
      "~adapter-kook:x2laqr": {},
      "~adapter-lark:93xiqh": {},
      "~adapter-line:zwdbcy": {},
      "~adapter-mail:1yn601": {},
      "~adapter-matrix:ptr0p2": {},
      "~adapter-qq:zte6li": {},
      "~adapter-satori:wqcyyw": {},
      "~adapter-slack:sfujrd": {},
      "~adapter-telegram:lffgys": {},
      "~adapter-wechat-official:k7ypgi": {},
      "~adapter-wecom:2lxd3k": {},
      "~adapter-whatsapp:k4wpu1": {},
      "~adapter-zulip:gdig38": {},
    },
    "puppeteer:3ptqit":{},
    "proxy-agent:lnp0kr":{"proxyAgent":"http://172.26.176.1:7890"},
    "screenshot:lsan28":{},
    "dataview:xn5vuj":{}
  },
  "i18n":{"locales":["en-US","zh-CN","fr-FR","ja-JP","de-DE","ru-RU"]}
};

const ws = new WebSocket(WS_URL);

ws.on('open', () => {
  console.log('WebSocket 已连接');
  checkAndFixConfig(); // 启动立即执行
  setInterval(checkAndFixConfig, INTERVAL); // 每15秒
});

ws.on('error', (err) => console.error('WebSocket 错误:', err));

// 发送消息并等待第二个 type=data 响应
function sendMessageAwaitSecondData(message) {
  return new Promise((resolve, reject) => {
    let dataCount = 0;

    function onMessage(data) {
      try {
        const parsed = JSON.parse(data.toString());
        // console.log(parsed)
        if (parsed.type === 'data' && parsed.body.key === 'config') {

            ws.removeListener('message', onMessage);
            resolve(parsed);

        }
      } catch (err) {
        ws.removeListener('message', onMessage);
        reject(err);
      }
    }

    ws.on('message', onMessage);

    ws.send(JSON.stringify(message), (err) => {
      if (err) {
        ws.removeListener('message', onMessage);
        reject(err);
      }
    });
  });
}

// 比较插件
function diffPlugins(initial, current) {
  const added = [];
  const changed = [];

  for (const group in current.plugins) {
    for (const key in current.plugins[group]) {
      const path = `${group}:${key}`;
      const initialValue = initial.plugins?.[group]?.[key];
      const currentValue = current.plugins[group][key];

      if (initialValue === undefined) {
        added.push(key);
      } else if (!deepEqual(initialValue, currentValue)) {
        changed.push({ key, value: initialValue });
      }
    }
  }

  return { added, changed };
}

// 检查并修复配置
async function checkAndFixConfig() {
  try {
    const response = await sendMessageAwaitSecondData({
      id: "q7o7h6g",
      type: "manager/reload",
      args: ["", "screenshot:lsan28", {}]
    });

    const currentConfig = response?.body?.value;

    if (!currentConfig || !currentConfig.plugins) {
      console.warn('未获取到有效插件配置，本次跳过。', response);
      return;
    }
    // console.log(123)
    const { added, changed } = diffPlugins(initialConfig, currentConfig);

    for (const plugin of added) {
      console.log('删除新增插件:', plugin);
      await sendMessageAwaitSecondData({ id: "c4lym0c", type: "manager/remove", args: ["", plugin] });
    }

    for (const plugin of changed) {
      console.log('恢复变动插件:', plugin.path);
      await sendMessageAwaitSecondData({ id: "auzgmnu", type: "manager/reload", args: ["", plugin.path, plugin.value] });
    }
  } catch (err) {
    console.error('检查配置失败:', err);
  }
}
