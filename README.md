

# 加密聊天室（Secure Chatroom）

轻量级网页聊天室：**Node.js + Express + Socket.IO + Web Crypto API**，浏览器端原生 JS 零第三方依赖，服务端无数据库依赖（轻量 JSON 文件持久化）。

- 访问网址即可加入，支持填写任意服务器地址加入其它服务器
- 每个房间独立密码，服务端以 **SHA-256 加盐哈希**存储（每房间随机盐，格式 `salt:hash`）
- 每个聊天室有**唯一房间号**：加入时填写房间号，房间不存在且密码正确时自动创建；房间号由用户/创建者指定，不支持自定义修改已存在的房间号
- 群聊消息使用 **AES-256-GCM**（密钥由房间密码经 PBKDF2 派生）加密传输
- 私聊使用 **ECDH (P-256)** 密钥协商派生双方共享 AES-256 密钥加密，仅双方可见
- 服务端**只存储/转发密文，不解密**，防窃听
- 不支持头像，轻量设计减轻服务器负担

---

## 1. 目录结构

```
chatroom/
├── package.json          # 依赖与启动脚本（npm start）
├── server.js             # 服务端：Express + Socket.IO + 密码哈希 + 房间管理
├── .gitignore
├── data/                 # 运行时自动生成：rooms.json（房间与密码哈希）
└── public/               # 前端静态资源（零第三方依赖）
    ├── index.html        # 加入页 + 聊天页
    ├── crypto.js         # Web Crypto 封装：PBKDF2 / AES-256-GCM / ECDH
    └── app.js            # 前端主逻辑
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
PORT=8080 npm start        # Linux / macOS
$env:PORT=8080; npm start  # Windows PowerShell
```

启动后控制台输出：

```
✔ 加密聊天室已启动：http://localhost:3000
```

浏览器访问 `http://localhost:3000`，填写 **服务器地址（默认当前站点）+ 房间号 + 昵称 + 房间密码** 即可加入；房间不存在且密码正确时自动创建。

---

## 3. 使用说明

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
- **私聊**：点击右侧在线用户列表中的「私聊」发起；第一次私聊会触发 ECDH 密钥协商，协商成功后消息仅双方可解密。私聊时顶部出现紫色「私聊中」提示条，点击 ✕ 结束私聊。

### 3.3 浏览器兼容

Web Crypto API 需运行在**安全上下文**（HTTPS 或 localhost）。已支持：Chrome / Edge / Firefox / Safari 15+。局域网 HTTP 直连仅在 localhost 可用；局域网/公网访问请按第 5 节配置 HTTPS 反向代理，或在浏览器高级设置中临时允许不安全源（不推荐）。

---

## 4. 加密流程说明（README 必读）

### 4.1 密码存储（服务端）

```
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
密钥派生：房间密码 + 随机盐 → PBKDF2(iterations=100000, SHA-256) → AES-256 密钥
         盐在首次进入房间时随机生成并缓存在 sessionStorage（会话级）
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
http://192.168.1.100:3000
```

> 注意：Web Crypto 在非 localhost 的 **HTTP** 下会被浏览器禁用。局域网 HTTP 场景下加密 API 将不可用（页面会提示需要 HTTPS）。因此局域网访问建议按 5.3 配置 HTTPS，或在本机（localhost）使用。

### 5.2 公网访问（简单方式）

- 云服务器（阿里云/腾讯云/轻量服务器等）放行 `3000` 端口（安全组 + 系统防火墙），直接访问 `http://公网IP:3000`（同样建议套 HTTPS）。
- 或用内网穿透工具（frp / ngrok / cpolar）将本机 `3000` 端口映射到公网域名。

### 5.3 反向代理部署（推荐：HTTPS 使 Web Crypto 在局域网/公网可用）

以 **Nginx + Let's Encrypt** 为例：

```nginx
# /etc/nginx/sites-available/chatroom
server {
    listen 443 ssl;
    server_name chat.example.com;

    ssl_certificate     /etc/letsencrypt/live/chat.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/chat.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:3000;
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
node server.js                             # 服务端监听 127.0.0.1:3000 即可
```

> WebSocket 升级头（`Upgrade` / `Connection: upgrade`）必须转发，否则 Socket.IO 无法建立长连接。

### 5.4 进程守护（生产环境）

```bash
# 使用 pm2
npm i -g pm2
pm2 start server.js --name chatroom
pm2 save && pm2 startup
```

---

## 6. 数据文件说明

| 文件 | 内容 | 备注 |
|---|---|---|
| `data/rooms.json` | 房间号 → `{ id, salt, hash, createdAt }` | 运行时自动创建；密码仅存 `salt:hash`，不存明文 |
| `data/rooms.json.tmp` | 写盘原子性临时文件 | 自动管理 |

---

## 7. 安全提示

- 房间密码即群聊密钥的来源：**请使用高强度密码**，弱密码可被字典攻击。
- 私聊密钥协商（ECDH）依赖首次公钥交换，未接入身份认证，理论上存在中间人风险；在可信服务器部署可显著降低该风险。
- 本项目为轻量学习/内部使用设计，如需企业级安全请补充 TLS 双向认证、速率限制、审计日志等。
*（内容由AI生成，仅供参考）*
