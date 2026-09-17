---
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: e9402fbbdd875a4359af4b0210d1baa1_94a154b0b22611f197a3525400248c00
    ReservedCode1: 70NpADczbFzp9MKzb4/NwLc53Xz58fGLXtEd/MPqZNPuPcxRfnH9q616zdnXk7o7dCTojQU8Ll1dw7voYRSCE9zFbUzBPQOpdHlsyI/L1KIXTfPhBg/EYH+FijZVQKsflhiPQOsVSxuSMJXjCjYq7h1rMRSwdxKjNAo9kpXarAh5pHyt4zmjyy7EIOs=
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: e9402fbbdd875a4359af4b0210d1baa1_94a154b0b22611f197a3525400248c00
    ReservedCode2: 70NpADczbFzp9MKzb4/NwLc53Xz58fGLXtEd/MPqZNPuPcxRfnH9q616zdnXk7o7dCTojQU8Ll1dw7voYRSCE9zFbUzBPQOpdHlsyI/L1KIXTfPhBg/EYH+FijZVQKsflhiPQOsVSxuSMJXjCjYq7h1rMRSwdxKjNAo9kpXarAh5pHyt4zmjyy7EIOs=
---



# 加密聊天室（Secure Chatroom）

轻量级网页聊天室：**Node.js + Express + Socket.IO + 纯 JS 加密库（@noble 系列）**，浏览器端加密不依赖 Web Crypto API（无需 HTTPS），服务端无数据库依赖（轻量 JSON 文件持久化）。

- 访问网址即可加入，支持填写任意服务器地址加入其它服务器
- **账号体系（仿微软无密码）**：注册仅需用户名+邮箱（无验证码、不发邮件）+密码；登录支持「用户名/邮箱+密码」或「设备密钥」两种方式；Socket.IO 握手携带登录 token 校验，防止绕过登录页直连后端
- **设备密钥**：登录后在账号设置页为本机生成随机设备密钥（32 字节 hex，仅展示一次），之后可用它免密码登录；服务端仅存 scrypt 加盐哈希，不存明文
- 每个房间独立密码，服务端以 **SHA-256 加盐哈希**存储（每房间随机盐，格式 `salt:hash`）
- 每个聊天室有**唯一房间号**：加入时填写房间号，房间不存在且密码正确时自动创建；房间号由用户/创建者指定，不支持自定义修改已存在的房间号
- 群聊消息使用 **AES-256-GCM**（密钥由房间密码经 PBKDF2 派生）加密传输
- 私聊使用 **ECDH (P-256)** 密钥协商派生双方共享 AES-256 密钥加密，仅双方可见；**只有加好友后才能私聊**
- 好友关系持久化（`data/friends.json`，双向写入），好友列表在加入房间时下发
- 前后端端口拆分：前端显示界面 **3000** 端口，后端存储/聊天服务 **3001** 端口
- 服务端**只存储/转发密文，不解密**，防窃听
- 不支持头像，轻量设计减轻服务器负担

---

## 1. 目录结构

```
chatroom/
├── package.json          # 依赖与启动脚本（npm start）
├── start.js              # 并行启动 web.js（前端 3000）与 server.js（后端 3001）
├── server.js             # 后端服务：Socket.IO + 账号系统 + 设备密钥 + 密码哈希 + 房间管理 + 好友管理
├── public/
│   ├── web.js            # 前端服务：Express 静态托管 public（3000 端口）
│   ├── index.html        # 登录页 + 注册页 + 账号设置页 + 加入页 + 聊天页
│   ├── vendor/
│   │   ├── socket.io.js  # Socket.IO 客户端（自 node_modules 复制，供 3000 静态托管）
│   │   └── noble.js      # @noble 系列加密库（esbuild 打包单文件）
│   ├── crypto.js         # 加密封装：PBKDF2 / AES-256-GCM / ECDH（基于 noble）
│   └── app.js            # 前端主逻辑
├── data/                 # 运行时自动生成：users.json / rooms.json / friends.json
└── .gitignore
```

---

## 2. 快速开始

### 2.1 环境要求

- Node.js **16+**（推荐 18 LTS 或更高）

### 2.2 安装依赖

```bash
npm install
```

### 2.3 启动

```bash
npm start
# 或自定义端口
PORT=8080 npm start        # 自定义前端端口（Linux / macOS）
$env:PORT=8080; npm start  # 自定义前端端口（Windows PowerShell）
$env:PORT=8080; $env:BACKEND_PORT=8081; npm start  # 同时自定义前后端端口
```

启动后控制台输出：

```
✔ 前端页面已启动：http://localhost:3000
✔ 后端聊天服务已启动：http://localhost:3001
```

浏览器访问 `http://localhost:3000`（前端显示界面），**首次需先注册账号**（用户名 + 邮箱 + 密码，无验证码、不发邮件），注册成功自动登录进入加入页；已注册用户可直接用「用户名/邮箱 + 密码」登录，或使用**设备密钥**免密码登录。进入加入页后填写 **服务器地址（默认当前站点主机名 + 3001 后端端口）+ 房间号 + 昵称 + 房间密码** 即可加入；房间不存在且密码正确时自动创建。

### 2.4 账号体系与设备密钥

- **注册**：仅需用户名、邮箱（格式校验，不发送验证码/邮件）、密码（最短 4 位）与确认密码；服务端校验用户名/邮箱唯一，密码以 scrypt 加盐哈希（`salt:hash`）存入 `data/users.json`，**不存明文**。
- **登录（方式 A）**：用户名或邮箱 + 密码 → 返回登录 token。
- **设备密钥（方式 B，免密码）**：登录后进入「账号设置」页，点击「新增设备密钥」生成 **32 字节随机 hex 密钥（仅展示一次，请妥善保存）**，服务端仅存该密钥的加盐哈希；之后在登录页切换到「设备密钥登录」粘贴密钥即可登录。设置页可查看已绑定密钥（创建时间/脱敏尾号）并支持删除单个。
- **会话**：登录 token 由服务端内存 `Map<token, username>` 管理（重启失效），前端存 `sessionStorage`（`chatroom_token` / `chatroom_username`）；Socket.IO 握手 `auth.token` 缺失/无效直接拒绝连接（提示「请先登录」），无法绕过登录页直连后端。

> 端口说明：**3000 = 前端页面**（`public/web.js`，静态托管），**3001 = 后端聊天服务**（`server.js`，Socket.IO + 存储）。`npm start` 通过 `start.js` 并行启动两个进程。后端已内置手写 CORS 中间件（允许所有来源、GET/POST/DELETE、Content-Type/Authorization，处理 OPTIONS 预检），3000 页面可跨端口调用 3001 的账号 API。

---

## 3. 使用说明

### 3.0 注册 / 登录 / 设备密钥

- **注册**：打开页面默认显示登录页，点击「注册一个」切换到注册卡。填写用户名、邮箱（仅格式校验，不发送验证码/邮件）、密码（最短 4 位）与确认密码；两次密码不一致或邮箱格式错误时前端直接拦截。注册成功自动登录并进入加入页。
- **登录（方式 A）**：用户名或邮箱 + 密码 → `POST /api/auth/login` 返回 `{ok:true, token, username}`，token 写入 `sessionStorage`（`chatroom_token`），进入加入页（昵称输入框默认填充登录用户名）。
- **登录（方式 B，设备密钥）**：登录卡点击「使用设备密钥登录」，粘贴设备密钥即可免密码登录；服务端按账号下绑定的密钥哈希逐项校验。
- **账号设置**：加入页头部点击「账号设置」进入设置页，展示用户名/邮箱，可「新增设备密钥」（返回 32 字节随机 hex，仅展示一次，服务端仅存哈希）与「删除单个设备密钥」；设置页可返回加入页。
- **会话与握手**：加入时 Socket.IO 握手自动携带 `auth.token`，服务端校验缺失/无效直接拒绝连接（`connect_error: 请先登录`）；房间号/昵称/房间密码校验保留。

### 3.1 加入 / 创建房间

| 字段 | 说明 |
|---|---|
| 服务器地址 | 默认填当前站点地址；修改后可加入**其他服务器**（需对方服务器与本项目相同） |
| 房间号 | 要加入的房间号；不存在且密码正确时自动创建该房间 |
| 昵称 | 加入时设置，房间内展示（不支持头像） |
| 房间密码 | 加入已有房间时校验；创建新房间时作为该房间密码（服务端仅存 SHA-256 加盐哈希） |

> 房间号一旦创建即固定，聊天室内不支持修改房间号。

### 3.2 群聊与私聊

- **群聊**：输入消息按 Enter 发送，同房间所有人可见（密文经服务端转发，各端解密）。
- **私聊**：**必须先加好友**。在线用户列表中，好友显示「私聊」、非好友显示「＋加好友」；点击「＋加好友」发送好友请求，对方确认后双方成为好友。好友之间点击「私聊」即可发起，第一次私聊会触发 ECDH 密钥协商，协商成功后消息仅双方可解密。私聊时顶部出现紫色「私聊中」提示条，点击 ✕ 结束私聊。

### 3.3 好友功能

- 好友关系以昵称为单位，**双向写入**并持久化到 `data/friends.json`（格式 `{ roomId: { nick: [好友nick数组] } }`）。
- 加入房间时服务端下发 `friends:list`，前端据此区分好友/非好友。
- 收到好友请求时弹确认框：接受（`friend:accept`）/ 拒绝（`friend:reject`）。
- **服务端强制校验**：`chat:private` 处理前校验双方为好友（`areFriends`），非好友拒绝并回发 `chat:private_denied`（提示"请先添加对方为好友"），即使绕过前端也无法私聊非好友。

### 3.4 浏览器兼容

加密全部在浏览器端以**纯 JS**（@noble 系列）完成，不依赖 Web Crypto API，因此**无需 HTTPS / localhost**，公网 HTTP 环境同样可用。已支持所有主流浏览器：Chrome / Edge / Firefox / Safari。

---

## 4. 加密流程说明（README 必读）

### 4.1 密码存储（服务端）

```
账号密码 / 设备密钥（scrypt 加盐，Node 内置 crypto.scryptSync）：
  salt = randomBytes(16).hex          # 每账号/每设备密钥独立随机盐
  hash = scrypt(secret, salt, 64).hex # 加盐哈希，格式 salt:hash 拆分为两项
  存储 users.json：{ username: { username, email, salt, hash, deviceKeys: [{id,salt,hash,createdAt}], createdAt } }
  严禁明文；登录时重新计算比对（timingSafeEqual 恒定时间比较）

创建房间：
  salt = randomBytes(16).hex         # 每房间独立随机盐
  hash = SHA256(salt + password)     # 加盐哈希
  存储 rooms.json：{ roomId: { id, salt, hash, createdAt } }   # 格式 salt:hash 可拆分为两项

加入房间：
  服务端用请求携带的密码重新计算 SHA256(存储salt + 输入密码)
  与存储 hash 比对，一致才允许进入；不一致拒绝连接
```

### 4.2 群聊消息加密（浏览器端）

```
密钥派生：房间密码 + 确定性盐 → PBKDF2(iterations=100000, SHA-256) → AES-256 密钥
         盐 = SHA-256(房间号) 前 16 字节，同房间所有客户端派生一致
消息发送：明文 → AES-256-GCM(iv=12B随机, tag=128bit) → {ciphertext, iv, tag}(base64) → Socket.IO
消息接收：Socket.IO → AES-256-GCM 解密 → 明文
服务端行为：仅校验密文结构并转发，不持有密钥，不解密
```

> 同房间用户使用同一密码，因此都能派生相同密钥解密群聊；密码错误的人无法通过服务端验证进入房间。

### 4.3 私聊加密（浏览器端，ECDH P-256）

```
1. 双方各生成 ECDH P-256 密钥对，公钥经服务端转发交换（握手事件 private:handshake）
2. 各自用「我的私钥 + 对方公钥」算出共享密钥（ECDH）
3. 共享密钥经 HKDF(SHA-256, 上下文=双方ID) 派生 AES-256 密钥
4. 之后私聊消息用该 AES 密钥 AES-256-GCM 加密，服务端仅按目标 socket 转发密文
   —— 仅通信双方能解密，房间内其他人及服务端均无法读取
```

### 4.4 防窃听特性小结

- 传输层：消息均以密文在 Socket.IO 上传输，抓包无法还原内容
- 服务端：不保存聊天记录（群聊与私聊均不落库），只持久化房间元数据与密码哈希
- 完整性：AES-256-GCM 自带认证标签，篡改密文会解密失败并提示

---

## 5. 部署说明

### 5.1 局域网访问（同一局域网内）

1. 查询本机 IP：

```bash
ipconfig        # Windows，找 IPv4 地址，如 192.168.1.100
```

2. 启动服务后，同局域网设备浏览器访问：

```
http://192.168.1.100:3000        # 前端页面
```

> 注意：浏览器加载页面后会连接 **3001 后端端口**（Socket.IO），因此防火墙/安全组需同时放行 **3000 与 3001** 两个端口，否则页面能打开但无法加入聊天室。
> 加密在浏览器本地完成（纯 JS 库），不依赖安全上下文，HTTP 环境下同样可用，无需额外配置 HTTPS。

### 5.2 公网访问（简单方式）

- 云服务器（阿里云/腾讯云/轻量服务器等）放行 **3000 与 3001** 两个端口（安全组 + 系统防火墙），直接访问 `http://公网IP:3000`（加密纯 JS 实现，HTTP 即可用；如需防窃听建议套 HTTPS）。
- 或用内网穿透工具（frp / ngrok / cpolar）将本机 **3000 与 3001** 两个端口都映射到公网（页面端口 + Socket.IO 后端端口）。

### 5.3 反向代理部署（可选：HTTPS 防窃听）

以 **Nginx + Let's Encrypt** 为例：

```nginx
# /etc/nginx/sites-available/chatroom
server {
    listen 443 ssl;
    server_name chat.example.com;

    ssl_certificate     /etc/letsencrypt/live/chat.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/chat.example.com/privkey.pem;

    # 前端页面 → 3000
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Socket.IO 后端 → 3001
    location /socket.io/ {
        proxy_pass http://127.0.0.1:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name chat.example.com;
    return 301 https://$host$request_uri;
}
```

```bash
sudo certbot --nginx -d chat.example.com   # 签发证书
sudo systemctl reload nginx
npm start                                  # 并行启动前端 3000 与后端 3001
```

> WebSocket 升级头（`Upgrade` / `Connection: upgrade`）必须转发，否则 Socket.IO 无法建立长连接。若后端部署在远程主机，前端「服务器地址」需填 `https://chat.example.com`（经反代转发到 3001）。

### 5.4 进程守护（生产环境）

```bash
# 使用 pm2
npm i -g pm2
pm2 start start.js --name chatroom
pm2 save && pm2 startup
```

---

## 6. 数据文件说明

| 文件 | 内容 | 备注 |
|---|---|---|
| `data/users.json` | 用户名 → `{ username, email, salt, hash, deviceKeys: [{id,salt,hash,createdAt}], createdAt }` | 运行时自动创建；密码与设备密钥仅存 scrypt 加盐哈希（`salt:hash`），不存明文 |
| `data/rooms.json` | 房间号 → `{ id, salt, hash, createdAt }` | 运行时自动创建；密码仅存 `salt:hash`，不存明文 |
| `data/friends.json` | 房间号 → 昵称 → 好友昵称数组（双向写入） | 运行时自动创建；用于私聊好友校验 |
| `data/*.tmp` | 写盘原子性临时文件 | 自动管理 |

---

## 7. 安全提示

- 房间密码即群聊密钥的来源：**请使用高强度密码**，弱密码可被字典攻击。
- 私聊密钥协商（ECDH）依赖首次公钥交换，未接入身份认证，理论上存在中间人风险；在可信服务器部署可显著降低该风险。
- 本项目为轻量学习/内部使用设计，如需企业级安全请补充 TLS 双向认证、速率限制、审计日志等。
*（内容由AI生成，仅供参考）*
*（内容由AI生成，仅供参考）*
