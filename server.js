/**
 * 轻量加密聊天室服务端
 * 技术栈：Node.js + Express + Socket.IO
 *
 * 设计原则：
 *  - 无数据库依赖：房间与密码数据以轻量 JSON 文件持久化（data/rooms.json）
 *  - 密码准入：SHA-256 加盐哈希存储（格式 salt:hash），每房间独立随机盐
 *  - 消息加密：服务端只存储/转发密文，不解密（AES-256-GCM / ECDH 均在浏览器端完成）
 *  - 轻量：单进程、内存会话表，减少服务器负担
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const ROOMS_FILE = path.join(DATA_DIR, 'rooms.json');

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
/* 密码哈希：SHA-256 加盐（每房间随机盐），格式 salt:hash               */
/* ------------------------------------------------------------------ */

function createRoomRecord(roomId, password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.createHash('sha256').update(salt + password).digest('hex');
  return {
    id: String(roomId),
    salt,
    hash,
    createdAt: Date.now(),
    // 服务端仅保存必要的元数据（在线人数由内存会话表实时统计，不落盘）
  };
}

function verifyPassword(password, record) {
  if (!record || !record.salt || !record.hash) return false;
  const hash = crypto.createHash('sha256').update(record.salt + password).digest('hex');
  return hash === record.hash;
}

/* ------------------------------------------------------------------ */
/* HTTP + WebSocket 服务                                                */
/* ------------------------------------------------------------------ */

const app = express();
app.use(express.static(path.join(__dirname, 'public')));

// 健康检查
app.get('/api/health', (req, res) => {
  res.json({ ok: true, rooms: Object.keys(rooms).length, time: Date.now() });
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
  // 握手阶段校验：加入必须携带房间号、昵称、密码
  const { roomId, nick, password } = socket.handshake.auth || {};
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

  socket.join(roomId);
  sessions.set(socket.id, { nick: String(nick), roomId: String(roomId) });

  socket.emit('joined', {
    roomId: String(roomId),
    nick: String(nick),
    you: socket.id,
    online: roomCount(roomId)
  });

  // 通知同房间其他用户
  socket.to(roomId).emit('system', {
    type: 'join',
    nick: String(nick),
    text: `${nick} 加入了房间`,
    time: Date.now()
  });

  broadcastUsers(roomId);
  broadcastRoomStats();

  /* ---------------- 群聊：仅转发密文，服务端不解密 ---------------- */
  socket.on('chat:room', (payload) => {
    const s = sessions.get(socket.id);
    if (!s || s.roomId !== roomId) return;
    // 校验密文结构，防脏数据
    if (!payload || typeof payload.ciphertext !== 'string' ||
        typeof payload.iv !== 'string' || typeof payload.tag !== 'string') {
      return;
    }
    socket.to(roomId).emit('chat:room', {
      from: s.nick,
      fromId: socket.id,
      ciphertext: payload.ciphertext,
      iv: payload.iv,
      tag: payload.tag,
      time: Date.now()
    });
  });

  /* ---------------- 私聊：仅双方可见，服务端仅转发密文 -------------- */
  socket.on('chat:private', (payload) => {
    const s = sessions.get(socket.id);
    if (!s || s.roomId !== roomId) return;
    const target = sessions.get(payload.to);
    if (!target || target.roomId !== roomId) return; // 仅允许私聊同房间用户
    if (!payload || typeof payload.ciphertext !== 'string' ||
        typeof payload.iv !== 'string' || typeof payload.tag !== 'string') {
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

  /* ---------------- 断线清理 ---------------- */
  socket.on('disconnect', () => {
    const s = sessions.get(socket.id);
    if (!s) return;
    sessions.delete(socket.id);
    if (s.roomId === roomId) {
      socket.to(roomId).emit('system', {
        type: 'leave',
        nick: s.nick,
        text: `${s.nick} 离开了房间`,
        time: Date.now()
      });
      broadcastUsers(roomId);
      broadcastRoomStats();
    }
  });

  socket.on('error', (err) => {
    console.error('[socket] 连接错误:', err.message);
  });
});

server.listen(PORT, () => {
  console.log(`✔ 加密聊天室已启动：http://localhost:${PORT}`);
  console.log(`  局域网访问：http://<本机IP>:${PORT}（详见 README）`);
  console.log(`  当前已持久化房间数：${Object.keys(rooms).length}`);
});
