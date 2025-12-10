<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>hyperFun~</title>
    <script src="static/crypto-js.min.js"></script>
    <style>
        :root {
            --blue: #2563eb;
            --green: #16a34a;
            --purple: #7e22ce;
            --gray: #6b7280;
        }

        * { box-sizing: border-box; }
        body {
            font-family: "Segoe UI", "PingFang SC", sans-serif;
            background: linear-gradient(135deg, #dbeafe, #ede9fe);
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }

        .card {
            background: white;
            width: 360px;
            padding: 36px 30px;
            border-radius: 18px;
            box-shadow: 0 10px 35px rgba(0,0,0,0.12);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            animation: fadeIn 0.5s ease;
        }

        .card:hover {
            transform: translateY(-4px);
            box-shadow: 0 14px 40px rgba(0,0,0,0.16);
        }

        h2 { margin-bottom: 22px; color: #111827; font-size: 24px; text-align: center; }
        h3 { color: #374151; margin: 15px 0 8px; font-weight: 500; text-align: left; }

        input {
            width: 100%;
            padding: 11px 12px;
            margin: 10px 0;
            border: 1px solid #d1d5db;
            border-radius: 10px;
            font-size: 15px;
            line-height: 1.5;
            transition: all 0.3s;
            display: block;
        }

        input:focus {
            border-color: var(--blue);
            box-shadow: 0 0 0 3px rgba(37,99,235,0.2);
            outline: none;
        }

        button {
            width: 100%;
            padding: 12px;
            border: none;
            border-radius: 10px;
            color: white;
            font-size: 16px;
            cursor: pointer;
            transition: all 0.25s;
            margin-top: 14px;
            display: block;
        }

        button:hover {
            transform: scale(1.03);
            box-shadow: 0 6px 15px rgba(0,0,0,0.1);
        }

        .btn-login { background: var(--blue); }
        .btn-register { background: var(--green); }
        .btn-download { background: var(--purple); }
        .btn-logout { background: var(--gray); }

        p { margin-top: 14px; font-size: 14px; text-align: center; color: #555; }
        .link { color: var(--blue); cursor: pointer; text-decoration: none; }
        .link:hover { text-decoration: underline; }

        .fade { animation: fadeIn 0.6s ease; }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* Toast 提示框样式 */
        .toast {
            position: fixed;
            top: 40px;
            left: 50%;
            transform: translateX(-50%);
            background: rgba(37,99,235,0.95);
            color: #fff;
            padding: 14px 24px;
            border-radius: 12px;
            font-size: 15px;
            font-weight: 500;
            box-shadow: 0 6px 20px rgba(0,0,0,0.15);
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.4s, transform 0.4s;
            z-index: 9999;
        }
        .toast.show {
            opacity: 1;
            transform: translate(-50%, 0);
        }
        .toast.error {
            background: rgba(220,38,38,0.95);
        }
        .toast.success {
            background: rgba(22,163,74,0.95);
        }
    </style>
</head>
<body>
<div class="card" id="app">

    <div id="loginPage">
        <h2>hyperFun~</h2>
        <input type="text" id="loginUsername" placeholder="username">
        <input type="password" id="loginPassword" placeholder="password">
        <button class="btn-login" onclick="handleSubmit('login')">Login</button>
        <p>Are you new here? <a class="link" onclick="showRegister()">Register</a></p>
    </div>

    <div id="registerPage" style="display:none;">
        <h2>Register to enjoy!</h2>
        <input type="text" id="regUsername" placeholder="username">
        <input type="password" id="regPassword" placeholder="password">
        <button class="btn-register" onclick="handleSubmit('register')">Register</button>
        <p>Already have an account? <a class="link" onclick="showLogin()">Login</a></p>
    </div>

    <div id="dashboardPage" style="display:none;">
        <h2 id="welcomeText"></h2>
        <div id="adminPanel" style="display:none;">
            <h3>File Download Debug</h3>
            <input type="text" id="filename" placeholder="enter the filename">
            <button class="btn-download" onclick="handleDownload()">Download</button>
        </div>
        <button class="btn-logout" onclick="logout()">Logout</button>
    </div>

</div>

<script>
    let currentUser = "";
    let isAdmin = false;
    let cachedKey = null; // AES key 缓存

    function setMessage(msg, type = "info") {
        if (!msg) return;
        const oldToast = document.querySelector(".toast");
        if (oldToast) oldToast.remove();

        const toast = document.createElement("div");
        toast.className = `toast ${type}`;
        toast.innerText = msg;
        document.body.appendChild(toast);

        setTimeout(() => toast.classList.add("show"), 50);

        setTimeout(() => {
            toast.classList.remove("show");
            setTimeout(() => toast.remove(), 400);
        }, 3000);
    }

    function fadeTo(pageId) {
        document.querySelectorAll("#app > div").forEach(el => el.style.display = "none");
        const target = document.getElementById(pageId);
        target.style.display = "";
        target.classList.add("fade");
        setTimeout(() => target.classList.remove("fade"), 600);
        window.location.hash = pageId;
    }

    function showLogin() { fadeTo("loginPage"); }
    function showRegister() { fadeTo("registerPage"); }
    function showDashboard(username) {
        currentUser = username;
        isAdmin = username === "admin";
        document.getElementById("welcomeText").innerText = "Welcome~ " + username + "！";
        document.getElementById("adminPanel").style.display = isAdmin ? "" : "none";
        fadeTo("dashboardPage");

        // 保存登录状态
        localStorage.setItem("currentUser", currentUser);
    }


    function logout() {
        currentUser = "";
        isAdmin = false;
        showLogin();
    }

    async function getAesKey() {
        if (cachedKey) return cachedKey;
        try {
            const res = await fetch(`/api/get_aes_key`, { method: "GET" });
            const data = await res.json();
            if (res.ok && data.key) {
                cachedKey = CryptoJS.enc.Base64.parse(data.key);
                return cachedKey;
            } else {
                setMessage(data.message || "Failed to get AES key", "error");
                return null;
            }
        } catch (err) {
            setMessage("error:" + err.message, "error");
            return null;
        }
    }

    async function encrypt(data) {
        return new Promise(async resolve => {
            let value = JSON.stringify(data);
            const key = await getAesKey();
            if (!key) { resolve(""); return; }

            const iv = CryptoJS.lib.WordArray.random(16);
            const encrypted = CryptoJS.AES.encrypt(value, key, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
            const encryptedBase64 = encrypted.ciphertext.toString(CryptoJS.enc.Base64);
            const ivBase64 = iv.toString(CryptoJS.enc.Base64);

            const mac = CryptoJS.HmacSHA256(ivBase64 + encryptedBase64, key);
            const macHex = mac.toString(CryptoJS.enc.Hex);

            const payload = JSON.stringify({ iv: ivBase64, value: encryptedBase64, mac: macHex });
            resolve(btoa(payload));
        });
    }

    async function handleSubmit(type) {
        setMessage("");
        const username = type === "login"
            ? document.getElementById("loginUsername").value.trim()
            : document.getElementById("regUsername").value.trim();
        const password = type === "login"
            ? document.getElementById("loginPassword").value.trim()
            : document.getElementById("regPassword").value.trim();

        if (!username || !password) {
            setMessage("username or password cannot be empty!", "error");
            return;
        }

        const encrypted = await encrypt({ username, password });
        if (!encrypted) return;

        try {
            const res = await fetch(`/api/${type}`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ data: encrypted })
            });
            const data = await res.json();

            if (res.ok){
                setMessage(data.message || "success", "success");
                showDashboard(data.username || username);
            }else {
                setMessage(data.message || "failed", "error");
            }

        } catch (err) {
            setMessage("error:" + err.message, "error");
        }
    }

    async function handleDownload() {
        const filename = document.getElementById("filename").value.trim();
        if (!filename) {
            setMessage("please enter the filename", "error");
            return;
        }
        try {
            const res = await fetch(`/api/debug?option=read_file&filename=${encodeURIComponent(filename)}`);
            if (res.ok){
                const blob = await res.blob();
                const a = document.createElement("a");
                a.href = URL.createObjectURL(blob);
                a.download = filename;
                a.click();
                URL.revokeObjectURL(a.href);
                setMessage("download successfully!", "success");
            }else {
                const data = await res.json();
                setMessage(data.message || "download failed~", "error");
            }

        } catch (err) {
            setMessage("error:" + err.message, "error");
        }
    }

    // 根据 URL hash 自动显示页面
    window.addEventListener("hashchange", () => {
        const page = window.location.hash.replace("#", "");
        if (page === "loginPage") showLogin();
        else if (page === "registerPage") showRegister();
        else if (page === "dashboardPage" && currentUser) showDashboard(currentUser);
        else showLogin();
    });

    // 初始化页面
    const savedUser = localStorage.getItem("currentUser");
    if (savedUser) {
        showDashboard(savedUser); // 直接显示dashboard
    } else if (window.location.hash) {
        window.dispatchEvent(new Event("hashchange"));
    } else {
        showLogin();
    }

</script>
</body>
</html>
