/**
 * 轻量加密聊天室服务端（后端服务：存储与聊天）
 * 技术栈：Node.js + Express + Socket.IO
 *
 * 端口拆分（v2）：
 *  - 前端显示界面由 public/web.js 托管（默认 3000 端口）
 *  - 本服务只负责 Socket.IO 聊天、房间密码、rooms.json 存储（默认 3001 端口）
 *
 * 设计原则：
 *  - 无数据库依赖：用户 data/users.json、房间密码 data/rooms.json、好友关系 data/friends.json 轻量 JSON 持久化
 *  - 账号准入：注册仅需用户名+邮箱+密码（无验证码），密码与设备密钥均 scrypt 加盐哈希存储（格式 salt:hash）；登录支持密码或设备密钥，Socket.IO 握手校验登录 token
 *  - 设备密钥：账号设置页可新增/删除；服务端仅存哈希，明文只展示一次（32 字节随机 hex）
 *  - 消息加密：服务端只存储/转发密文，不解密（AES-256-GCM / ECDH 均在浏览器端完成）
 *  - 好友准入：只有互为好友的用户才能私聊（data/friends.json 双向持久化）
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');

const PORT = process.env.PORT || 3001;
const DATA_DIR = process.pkg ? path.join(path.dirname(process.execPath), 'data') : path.join(__dirname, 'data');
const ROOMS_FILE = path.join(DATA_DIR, 'rooms.json');
const FRIENDS_FILE = path.join(DATA_DIR, 'friends.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

/* ------------------------------------------------------------------ */
/* 房间数据持久化（轻量 JSON 文件）                                     */
/* ------------------------------------------------------------------ */

function loadRooms() {
  try {
    if (fs.existsSync(ROOMS_FILE)) {
      const raw = fs.readFileSync(ROOMS_FILE, 'utf8');
      const data = JSON.parse(raw);
      if (data && typeof data === 'object' && !Array.isArray(data)) {
        return data;
      }
    }
  } catch (e) {
    console.error('[rooms] 读取房间数据失败，将重建:', e.message);
  }
  return {};
}

let rooms = loadRooms();

function saveRooms() {
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    const tmp = ROOMS_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(rooms, null, 2), 'utf8');
    fs.renameSync(tmp, ROOMS_FILE);
  } catch (e) {
    console.error('[rooms] 保存房间数据失败:', e.message);
  }
}

/* ------------------------------------------------------------------ */
/* 好友关系持久化：{ roomId: { nick: [好友nick数组] } }                 */
/* ------------------------------------------------------------------ */

function loadFriends() {
  try {
    if (fs.existsSync(FRIENDS_FILE)) {
      const raw = fs.readFileSync(FRIENDS_FILE, 'utf8');
      const data = JSON.parse(raw);
      if (data && typeof data === 'object' && !Array.isArray(data)) {
        return data;
      }
    }
  } catch (e) {
    console.error('[friends] 读取好友数据失败，将重建:', e.message);
  }
  return {};
}

let friends = loadFriends();

function saveFriends() {
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    const tmp = FRIENDS_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(friends, null, 2), 'utf8');
    fs.renameSync(tmp, FRIENDS_FILE);
  } catch (e) {
    console.error('[friends] 保存好友数据失败:', e.message);
  }
}

/** 获取某用户在房间内的好友 nick 数组 */
function getFriendNicks(roomId, nick) {
  const roomFriends = friends[roomId];
  if (!roomFriends || !roomFriends[nick]) return [];
  return roomFriends[nick];
}

/** 判断 roomId 房间内 nickA 与 nickB 是否为好友（双向校验） */
function areFriends(roomId, nickA, nickB) {
  const list = getFriendNicks(roomId, nickA);
  return Array.isArray(list) && list.includes(nickB);
}

/** 双向写入好友关系：nickA <-> nickB */
function addFriend(roomId, nickA, nickB) {
  if (!friends[roomId]) friends[roomId] = {};
  if (!friends[roomId][nickA]) friends[roomId][nickA] = [];
  if (!friends[roomId][nickB]) friends[roomId][nickB] = [];
  if (!friends[roomId][nickA].includes(nickB)) friends[roomId][nickA].push(nickB);
  if (!friends[roomId][nickB].includes(nickA)) friends[roomId][nickB].push(nickA);
  saveFriends();
}

/* ------------------------------------------------------------------ */
/* 账号系统：注册/登录 token（内存 Map，重启失效）+ users.json 持久化   */
/* ------------------------------------------------------------------ */

function loadUsers() {
  try {
    if (fs.existsSync(USERS_FILE)) {
      const raw = fs.readFileSync(USERS_FILE, 'utf8');
      const data = JSON.parse(raw);
      if (data && typeof data === 'object' && !Array.isArray(data)) {
        return data;
      }
    }
  } catch (e) {
    console.error('[users] 读取用户数据失败，将重建:', e.message);
  }
  return {};
}

let users = loadUsers();

function saveUsers() {
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    const tmp = USERS_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(users, null, 2), 'utf8');
    fs.renameSync(tmp, USERS_FILE);
  } catch (e) {
    console.error('[users] 保存用户数据失败:', e.message);
  }
}

/** 查找用户：按用户名或邮箱（均唯一） */
function findUser(account) {
  const key = String(account || '').trim();
  if (!key) return null;
  const lower = key.toLowerCase();
  for (const u of Object.values(users)) {
    if (u.username && u.username.toLowerCase() === lower) return u;
    if (u.email && u.email.toLowerCase() === lower) return u;
  }
  return null;
}

/** 生成密钥哈希：scrypt 加盐，返回 { salt, hash } */
function hashSecret(secret) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(secret), salt, 64).toString('hex');
  return { salt, hash };
}

/** 校验密钥：与存储的 salt/hash 比对（恒定时间比较防时序攻击） */
function verifySecret(secret, salt, hash) {
  if (!salt || !hash) return false;
  const candidate = crypto.scryptSync(String(secret), salt, 64).toString('hex');
  const a = Buffer.from(candidate, 'hex');
  const b = Buffer.from(hash, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/** 按设备密钥查找账号（遍历所有用户绑定的设备密钥） */
function findUserByDeviceKey(deviceKey) {
  const key = String(deviceKey || '').trim();
  if (!key) return null;
  for (const u of Object.values(users)) {
    const keys = Array.isArray(u.deviceKeys) ? u.deviceKeys : [];
    for (const dk of keys) {
      if (verifySecret(key, dk.salt, dk.hash)) return u;
    }
  }
  return null;
}

// 登录 token：内存 Map<token, username>（服务重启失效）
const tokenSessions = new Map();

function createSession(username) {
  const token = crypto.randomBytes(24).toString('hex');
  tokenSessions.set(token, username);
  return token;
}

function getSessionUser(token) {
  if (!token) return null;
  return tokenSessions.get(String(token)) || null;
}

/** 从 Authorization: Bearer <token> 解析登录用户（API 鉴权用） */
function getAuthUser(req) {
  const auth = req.headers && req.headers.authorization;
  if (!auth || !/^Bearer\s+/i.test(auth)) return null;
  const token = auth.replace(/^Bearer\s+/i, '').trim();
  const username = getSessionUser(token);
  if (!username || !users[username]) return null;
  return users[username];
}

/* ------------------------------------------------------------------ */
/* 房间密码哈希：SHA-256 加盐（每房间随机盐），格式 salt:hash           */
/* ------------------------------------------------------------------ */

function createRoomRecord(roomId, password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.createHash('sha256').update(salt + password).digest('hex');
  return {
    id: String(roomId),
    salt,
    hash,
    createdAt: Date.now(),
  };
}

function verifyPassword(password, record) {
  if (!record || !record.salt || !record.hash) return false;
  const hash = crypto.createHash('sha256').update(record.salt + password).digest('hex');
  return hash === record.hash;
}

/* ------------------------------------------------------------------ */
/* HTTP + WebSocket 服务（仅后端，不做静态托管）                        */
/* ------------------------------------------------------------------ */

const app = express();

// 手写 CORS 中间件：允许跨端口页面（3000）调用本服务 API（3001），不引额外依赖
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// 解析 JSON body（登录接口使用）
app.use(express.json());

// 健康检查（后端 3001 端口）
app.get('/api/health', (req, res) => {
  res.json({ ok: true, rooms: Object.keys(rooms).length, time: Date.now() });
});

// 登录状态查询：未带 token 时告知需要登录；带有效 token 时返回当前账号信息
app.get('/api/auth/status', (req, res) => {
  const user = getAuthUser(req);
  if (user) {
    return res.json({ required: true, ok: true, user: { username: user.username, email: user.email } });
  }
  return res.json({ required: true });
});

/** 邮箱格式校验（前端同样校验，服务端兜底） */
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || '').trim());
}

// 注册：body { username, email, password }，用户名/邮箱唯一，密码最短 4 位
app.post('/api/auth/register', (req, res) => {
  const username = (req.body && req.body.username != null) ? String(req.body.username).trim() : '';
  const email = (req.body && req.body.email != null) ? String(req.body.email).trim() : '';
  const password = (req.body && req.body.password != null) ? String(req.body.password) : '';
  if (!username || !email || !password) {
    return res.json({ ok: false, error: '用户名、邮箱、密码均不能为空' });
  }
  if (!isValidEmail(email)) {
    return res.json({ ok: false, error: '邮箱格式不正确' });
  }
  if (password.length < 4) {
    return res.json({ ok: false, error: '密码最短 4 位' });
  }
  const lowerName = username.toLowerCase();
  const lowerEmail = email.toLowerCase();
  for (const u of Object.values(users)) {
    if (u.username && u.username.toLowerCase() === lowerName) {
      return res.json({ ok: false, error: '用户名已被注册' });
    }
    if (u.email && u.email.toLowerCase() === lowerEmail) {
      return res.json({ ok: false, error: '邮箱已被注册' });
    }
  }
  const user = {
    username,
    email,
    ...hashSecret(password), // salt / hash：scrypt 加盐哈希，格式 salt:hash，严禁明文
    deviceKeys: [],
    createdAt: Date.now(),
  };
  users[username] = user;
  saveUsers();
  const token = createSession(username);
  return res.json({ ok: true, token, username });
});

// 登录：body { account, password }（密码登录）或 { deviceKey }（设备密钥登录）
app.post('/api/auth/login', (req, res) => {
  const body = req.body || {};
  // 方式 A：设备密钥直接登录
  if (body.deviceKey != null && String(body.deviceKey).trim()) {
    const deviceKey = String(body.deviceKey).trim();
    const user = findUserByDeviceKey(deviceKey);
    if (!user) {
      return res.json({ ok: false, error: '设备密钥无效或已删除' });
    }
    const token = createSession(user.username);
    return res.json({ ok: true, token, username: user.username, loginMode: 'deviceKey' });
  }
  // 方式 B：用户名或邮箱 + 密码
  const account = String(body.account || '').trim();
  const password = String(body.password || '');
  if (!account || !password) {
    return res.json({ ok: false, error: '请输入账号（用户名或邮箱）与密码，或使用设备密钥登录' });
  }
  const user = findUser(account);
  if (!user || !verifySecret(password, user.salt, user.hash)) {
    return res.json({ ok: false, error: '账号或密码错误' });
  }
  const token = createSession(user.username);
  return res.json({ ok: true, token, username: user.username, loginMode: 'password' });
});

// 账号设置 - 新增设备密钥：生成 32 字节随机 hex，仅本次返回明文，服务端只存加盐哈希
app.post('/api/device-keys', (req, res) => {
  const user = getAuthUser(req);
  if (!user) return res.status(401).json({ ok: false, error: '请先登录' });
  const id = crypto.randomBytes(8).toString('hex');
  const key = crypto.randomBytes(32).toString('hex');
  const { salt, hash } = hashSecret(key);
  if (!Array.isArray(user.deviceKeys)) user.deviceKeys = [];
  user.deviceKeys.push({ id, salt, hash, createdAt: Date.now() });
  saveUsers();
  return res.json({ ok: true, id, key, createdAt: Date.now() });
});

// 账号设置 - 列出已绑定设备密钥（脱敏尾号 + 创建时间，不回传密钥本身）
app.get('/api/device-keys', (req, res) => {
  const user = getAuthUser(req);
  if (!user) return res.status(401).json({ ok: false, error: '请先登录' });
  const keys = Array.isArray(user.deviceKeys) ? user.deviceKeys : [];
  const list = keys.map((dk) => ({
    id: dk.id,
    tail: String(dk.hash).slice(-6),
    createdAt: dk.createdAt,
  }));
  return res.json({ ok: true, keys: list });
});

// 账号设置 - 删除单个设备密钥
app.delete('/api/device-keys/:id', (req, res) => {
  const user = getAuthUser(req);
  if (!user) return res.status(401).json({ ok: false, error: '请先登录' });
  const id = String(req.params.id || '');
  if (!Array.isArray(user.deviceKeys)) user.deviceKeys = [];
  const idx = user.deviceKeys.findIndex((dk) => dk.id === id);
  if (idx === -1) {
    return res.json({ ok: false, error: '设备密钥不存在' });
  }
  user.deviceKeys.splice(idx, 1);
  saveUsers();
  return res.json({ ok: true });
});

const server = http.createServer(app);
const io = new Server(server, {
  maxHttpBufferSize: 1e6, // 限制单条消息体积（1MB），减轻负担
  cors: { origin: true, credentials: true }
});

/** 内存在线会话表：socketId -> { nick, roomId } */
const sessions = new Map();

/** 房间在线人数统计 */
function roomCount(roomId) {
  let n = 0;
  for (const s of sessions.values()) {
    if (s.roomId === roomId) n++;
  }
  return n;
}

/** 向房间广播用户列表（仅昵称，无头像） */
function broadcastUsers(roomId) {
  const users = [];
  for (const [sid, s] of sessions.entries()) {
    if (s.roomId === roomId) users.push({ id: sid, nick: s.nick });
  }
  io.to(roomId).emit('users:update', users);
}

/** 广播房间人数变化 */
function broadcastRoomStats() {
  io.emit('rooms:stats', Object.fromEntries(
    Object.keys(rooms).map((rid) => [rid, roomCount(rid)])
  ));
}

io.use((socket, next) => {
  // 握手阶段校验①：必须携带有效登录 token（未登录/无效 token 拒绝）
  const handshakeAuth = socket.handshake.auth || {};
  const token = handshakeAuth.token || '';
  if (!getSessionUser(token)) {
    return next(new Error('请先登录'));
  }
  // 握手阶段校验②：加入必须携带房间号、昵称、密码
  const { roomId, nick, password } = handshakeAuth;
  if (!roomId || !nick || !password) {
    return next(new Error('缺少加入参数（房间号 / 昵称 / 密码）'));
  }
  if (String(roomId).length > 64) return next(new Error('房间号过长'));
  if (String(nick).length > 32) return next(new Error('昵称过长（最多32字符）'));
  if (String(password).length > 128) return next(new Error('密码过长'));

  // 房间已存在 → 校验密码哈希
  if (rooms[roomId]) {
    if (!verifyPassword(password, rooms[roomId])) {
      return next(new Error('房间密码错误'));
    }
  } else {
    // 房间不存在：校验密码强度（弱密码拒绝自动创建，防止误建房）
    if (String(password).length < 4) {
      return next(new Error('房间不存在，且密码过短（至少 4 位）无法创建'));
    }
    // 房间不存在且密码满足最低强度 → 自动创建（每房间随机盐）
    rooms[roomId] = createRoomRecord(roomId, password);
    saveRooms();
  }
  next();
});

io.on('connection', (socket) => {
  const { roomId, nick } = socket.handshake.auth;
  const myNick = String(nick);
  const myRoomId = String(roomId);

  socket.join(myRoomId);
  sessions.set(socket.id, { nick: myNick, roomId: myRoomId });

  socket.emit('joined', {
    roomId: myRoomId,
    nick: myNick,
    you: socket.id,
    online: roomCount(myRoomId)
  });

  // 下发当前用户的好友列表（好友 nick 数组）
  socket.emit('friends:list', getFriendNicks(myRoomId, myNick));

  // 通知同房间其他用户
  socket.to(myRoomId).emit('system', {
    type: 'join',
    nick: myNick,
    text: `${myNick} 加入了房间`,
    time: Date.now()
  });

  broadcastUsers(myRoomId);
  broadcastRoomStats();

  /* ---------------- 群聊：仅转发密文，服务端不解密 ---------------- */
  socket.on('chat:room', (payload) => {
    const s = sessions.get(socket.id);
    if (!s || s.roomId !== myRoomId) return;
    // 校验密文结构，防脏数据
    if (!payload || typeof payload.ciphertext !== 'string' ||
        typeof payload.iv !== 'string' || typeof payload.tag !== 'string') {
      return;
    }
    socket.to(myRoomId).emit('chat:room', {
      from: s.nick,
      fromId: socket.id,
      ciphertext: payload.ciphertext,
      iv: payload.iv,
      tag: payload.tag,
      time: Date.now()
    });
  });

  /* ---------------- 私聊：仅好友之间，仅双方可见，服务端仅转发密文 -------------- */
  socket.on('chat:private', (payload) => {
    const s = sessions.get(socket.id);
    if (!s || s.roomId !== myRoomId) return;
    const target = sessions.get(payload.to);
    if (!target || target.roomId !== myRoomId) return; // 仅允许私聊同房间用户
    if (!payload || typeof payload.ciphertext !== 'string' ||
        typeof payload.iv !== 'string' || typeof payload.tag !== 'string') {
      return;
    }
    // 好友校验：必须互为好友才能私聊
    if (!areFriends(myRoomId, s.nick, target.nick)) {
      socket.emit('chat:private_denied', {
        to: target.nick,
        reason: '请先添加对方为好友'
      });
      return;
    }
    const msg = {
      from: s.nick,
      fromId: socket.id,
      to: target.nick,
      toId: payload.to,
      ciphertext: payload.ciphertext,
      iv: payload.iv,
      tag: payload.tag,
      time: Date.now()
    };
    io.to(payload.to).emit('chat:private', msg);
    socket.emit('chat:private', msg); // 回显给发送方（服务端不落库，无记录可查）
  });

  /* ---------------- 好友：请求 / 接受 / 拒绝 ---------------- */
  socket.on('friend:request', (payload) => {
    const s = sessions.get(socket.id);
    if (!s || s.roomId !== myRoomId) return;
    const target = sessions.get(payload.to);
    if (!target || target.roomId !== myRoomId) return; // 仅可添加同房间用户
    if (target.nick === s.nick) return; // 不能添加自己
    io.to(payload.to).emit('friend:request', {
      from: s.nick,
      fromId: socket.id
    });
  });

  socket.on('friend:accept', (payload) => {
    const s = sessions.get(socket.id);
    if (!s || s.roomId !== myRoomId) return;
    const target = sessions.get(payload.to);
    if (!target || target.roomId !== myRoomId) return; // 双方必须同房间
    if (target.nick === s.nick) return;
    // 双向写入好友关系并持久化
    addFriend(myRoomId, s.nick, target.nick);
    // 向双方通知：friend:added 携带对方 nick
    io.to(payload.to).emit('friend:added', { nick: s.nick });
    socket.emit('friend:added', { nick: target.nick });
  });

  socket.on('friend:reject', (payload) => {
    const s = sessions.get(socket.id);
    if (!s || s.roomId !== myRoomId) return;
    const target = sessions.get(payload.to);
    if (!target || target.roomId !== myRoomId) return;
    // 向发起方通知被拒绝
    io.to(payload.to).emit('friend:rejected', { nick: s.nick });
  });

  /* ---------------- 断线清理 ---------------- */
  socket.on('disconnect', () => {
    const s = sessions.get(socket.id);
    if (!s) return;
    sessions.delete(socket.id);
    if (s.roomId === myRoomId) {
      socket.to(myRoomId).emit('system', {
        type: 'leave',
        nick: s.nick,
        text: `${s.nick} 离开了房间`,
        time: Date.now()
      });
      broadcastUsers(myRoomId);
      broadcastRoomStats();
    }
  });

  socket.on('error', (err) => {
    console.error('[socket] 连接错误:', err.message);
  });
});

server.listen(PORT, () => {
  console.log(`✔ 后端聊天服务已启动：http://localhost:${PORT}`);
  console.log(`  前端页面请访问 http://localhost:3000（由 public/web.js 托管）`);
  console.log(`  当前已持久化房间数：${Object.keys(rooms).length}`);
  console.log(`  当前已注册用户数：${Object.keys(users).length}`);
  console.log(`  账号体系：注册仅需用户名+邮箱+密码（无验证码），登录后 token 校验；用户数据持久化于 data/users.json（密码 scrypt 加盐哈希）。`);
});
