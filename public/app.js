/**
 * app.js — 前端主逻辑（原生 JS，零第三方依赖）
 *
 * 流程：
 *  1. 用户填写服务器地址 / 房间号 / 昵称 / 密码 → 点击加入
 *  2. 从服务器地址解析出 WebSocket 地址，建立 Socket.IO 连接（握手带 auth）
 *  3. 连接成功后派生房间 AES 密钥（PBKDF2），进入聊天
 *  4. 群聊：AES-256-GCM 加密后发送；服务端转发密文，本端解密展示
 *  5. 私聊：ECDH P-256 密钥协商 → 双方共享 AES 密钥 → 加密私聊消息
 */
'use strict';

(() => {
  // 仅支持安全上下文（https 或 localhost）
  if (!window.isSecureContext) {
    document.body.innerHTML = '<div style="padding:40px;text-align:center">Web Crypto API 需要 HTTPS 或 localhost 环境。局域网/公网访问请配置 HTTPS 反向代理（见 README）。</div>';
    return;
  }

  const $ = (id) => document.getElementById(id);

  /* ---------------- 状态 ---------------- */
  const state = {
    socket: null,
    roomId: null,
    nick: null,
    roomKey: null,          // 群聊 AES 密钥
    myId: null,
    users: new Map(),       // id -> { nick, publicKeyB64 }
    ecdhKeys: new Map(),    // id -> { keyPair, publicKeyB64 }
    privateKeys: new Map(), // id -> AES key（与对方协商好的）
    privateTarget: null     // 当前私聊对象 id
  };

  /* ---------------- 页面元素 ---------------- */
  const joinPage = $('joinPage');
  const chatPage = $('chatPage');
  const joinBtn = $('joinBtn');
  const joinError = $('joinError');
  const msgInput = $('msgInput');
  const sendBtn = $('sendBtn');
  const messagesEl = $('messages');
  const usersListEl = $('usersList');
  const privateBar = $('privateBar');
  const privateTargetEl = $('privateTarget');
  const onlineBadge = $('onlineBadge');

  /* ---------------- 小工具 ---------------- */
  function showError(text) {
    joinError.textContent = text;
    joinError.classList.add('show');
  }
  function hideError() {
    joinError.classList.remove('show');
  }
  function fmtTime(ts) {
    const d = new Date(ts);
    const p = (n) => String(n).padStart(2, '0');
    return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  }
  function esc(s) {
    return String(s).replace(/[&<>"']/g, c => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
  }

  /* ---------------- 消息渲染 ---------------- */
  function addMessage(opts) {
    const div = document.createElement('div');
    div.className = 'msg ' + (opts.cls || '');
    const meta = document.createElement('div');
    meta.className = 'meta';
    meta.innerHTML = esc(opts.nick || '') +
      (opts.tag ? `<span class="tag">${esc(opts.tag)}</span>` : '') +
      ` · ${fmtTime(opts.time || Date.now())}`;
    const body = document.createElement('div');
    body.textContent = opts.text;
    div.appendChild(meta);
    div.appendChild(body);
    messagesEl.appendChild(div);
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }

  function addSystem(text) {
    const div = document.createElement('div');
    div.className = 'msg system';
    div.textContent = text;
    messagesEl.appendChild(div);
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }

  /* ---------------- 用户列表渲染 ---------------- */
  function renderUsers() {
    usersListEl.innerHTML = '';
    for (const [id, u] of state.users) {
      const item = document.createElement('div');
      item.className = 'user-item' + (id === state.myId ? ' self' : '');
      const dot = document.createElement('span');
      dot.className = 'dot';
      item.appendChild(dot);
      const name = document.createElement('span');
      name.textContent = u.nick;
      item.appendChild(name);
      if (id === state.myId) {
        const tip = document.createElement('span');
        tip.className = 'priv-tip';
        tip.textContent = '（我）';
        item.appendChild(tip);
      } else {
        const tip = document.createElement('span');
        tip.className = 'priv-tip';
        tip.textContent = '私聊';
        item.appendChild(tip);
        item.title = '点击发起私聊';
        item.addEventListener('click', () => startPrivate(id));
      }
      usersListEl.appendChild(item);
    }
  }

  /* ---------------- 私聊 ---------------- */
  async function startPrivate(targetId) {
    const target = state.users.get(targetId);
    if (!target || targetId === state.myId) return;
    // 若尚未与对方协商密钥，先发起 ECDH 握手
    if (!state.privateKeys.has(targetId)) {
      if (!state.ecdhKeys.has(state.myId)) {
        state.ecdhKeys.set(state.myId, await CryptoChat.ecdhGenerate());
      }
      const myKey = state.ecdhKeys.get(state.myId);
      state.socket.emit('private:handshake', {
        to: targetId,
        publicKey: myKey.publicKeyB64,
        nonce: CryptoChat.randomId()
      });
    }
    state.privateTarget = targetId;
    privateTargetEl.textContent = target.nick;
    privateBar.classList.add('show');
    msgInput.placeholder = `私聊 ${target.nick}（仅双方可见）...`;
    msgInput.focus();
  }

  function stopPrivate() {
    state.privateTarget = null;
    privateBar.classList.remove('show');
    msgInput.placeholder = '输入消息，Enter 发送';
  }

  /* ---------------- 发送 ---------------- */
  async function sendCurrent() {
    const text = msgInput.value.trim();
    if (!text) return;
    const target = state.privateTarget;
    if (target) {
      // 私聊：需要已协商密钥
      const key = state.privateKeys.get(target);
      if (!key) {
        addSystem('私聊密钥尚未协商完成，请稍候再试');
        return;
      }
      const enc = await CryptoChat.aesEncrypt(key, text);
      state.socket.emit('chat:private', { to: target, ...enc });
    } else {
      // 群聊
      const enc = await CryptoChat.aesEncrypt(state.roomKey, text);
      state.socket.emit('chat:room', enc);
      addMessage({ nick: state.nick, text, cls: 'mine' });
    }
    msgInput.value = '';
    msgInput.focus();
  }

  /* ---------------- Socket.IO 连接与事件 ---------------- */
  function connect() {
    const serverAddr = $('serverAddr').value.trim().replace(/\/+$/, '');
    const wsUrl = serverAddr.replace(/^http/, 'ws');
    const socket = io(wsUrl, {
      auth: {
        roomId: state.roomId,
        nick: state.nick,
        password: state.password
      },
      transports: ['websocket', 'polling']
    });
    state.socket = socket;

    socket.on('connect_error', (err) => {
      joinBtn.disabled = false;
      showError('无法加入：' + (err.message || '连接失败') + '（请检查服务器地址与密码）');
    });

    socket.on('joined', async (data) => {
      state.myId = data.you;
      state.roomId = data.roomId;
      hideError();
      joinPage.style.display = 'none';
      chatPage.classList.add('active');
      $('roomBadge').textContent = '房间 ' + data.roomId;
      $('nickBadge').textContent = '昵称：' + data.nick;
      onlineBadge.textContent = '在线 ' + data.online;
      addSystem(`已进入房间 ${data.roomId}，开始安全会话`);
      // 派生群聊密钥
      try {
        const { roomKey } = await CryptoChat.deriveRoomKey(data.roomId, state.password);
        state.roomKey = roomKey;
      } catch (e) {
        addSystem('房间密钥派生失败：' + e.message);
      }
    });

    // 群聊消息（密文）
    socket.on('chat:room', async (msg) => {
      if (msg.fromId === state.myId) return; // 群聊不显示自己（本地已回显）
      const plain = await CryptoChat.aesDecrypt(state.roomKey, msg);
      if (plain === null) {
        addMessage({ nick: msg.from, text: '[无法解密的消息 —— 密码不一致或密文被篡改]', cls: 'theirs' });
      } else {
        addMessage({ nick: msg.from, text: plain, cls: 'theirs' });
      }
    });

    // 私聊密文（发送方也会收到回显，据此在本地显示）
    socket.on('chat:private', async (msg) => {
      const isMine = msg.fromId === state.myId;
      const peerId = isMine ? msg.toId : msg.fromId;
      const key = state.privateKeys.get(peerId);
      let plain = null;
      if (key) plain = await CryptoChat.aesDecrypt(key, msg);
      if (plain === null) {
        plain = '[私聊消息无法解密]';
      }
      addMessage({
        nick: isMine ? `我 → ${msg.to}` : msg.from,
        text: plain,
        cls: 'private ' + (isMine ? 'mine' : 'theirs'),
        tag: '🔒 私聊',
        time: msg.time
      });
    });

    // ECDH 握手
    socket.on('private:handshake', async (data) => {
      const from = state.users.get(data.fromId);
      if (!from) return;
      // 生成/复用我方密钥对
      if (!state.ecdhKeys.has(state.myId)) {
        state.ecdhKeys.set(state.myId, await CryptoChat.ecdhGenerate());
      }
      const myKey = state.ecdhKeys.get(state.myId);
      if (!data.publicKey) return;
      const aesKey = await CryptoChat.ecdhDeriveSharedKey(
        myKey.keyPair, data.publicKey,
        `private-${[state.myId, data.fromId].sort().join('-')}`
      );
      state.privateKeys.set(data.fromId, aesKey);
      // 回复我方公钥（若对方已发来公钥则完成握手）
      state.socket.emit('private:handshake', {
        to: data.fromId,
        publicKey: myKey.publicKeyB64,
        nonce: CryptoChat.randomId()
      });
      addSystem(`已与 ${from.nick} 建立私聊加密通道`);
    });

    // 用户列表
    socket.on('users:update', (users) => {
      state.users.clear();
      const map = new Map(users.map(u => [u.id, { nick: u.nick }]));
      for (const [id, u] of map) {
        const prev = state.users.get(id);
        state.users.set(id, { nick: u.nick, publicKeyB64: prev?.publicKeyB64 });
      }
      renderUsers();
      onlineBadge.textContent = '在线 ' + users.length;
      // 若正在私聊的用户已离开，结束私聊
      if (state.privateTarget && !map.has(state.privateTarget)) {
        addSystem('私聊对象已离开');
        stopPrivate();
      }
    });

    socket.on('system', (data) => {
      addSystem(data.text);
    });

    socket.on('disconnect', () => {
      addSystem('与服务器断开连接');
    });
  }

  /* ---------------- 加入按钮 ---------------- */
  joinBtn.addEventListener('click', () => {
    const serverAddr = $('serverAddr').value.trim();
    const roomId = $('roomId').value.trim();
    const nick = $('nick').value.trim();
    const password = $('password').value;

    if (!serverAddr) return showError('请填写服务器地址');
    if (!/^https?:\/\/.+/i.test(serverAddr)) return showError('服务器地址需以 http:// 或 https:// 开头');
    if (!roomId) return showError('请填写房间号');
    if (!nick) return showError('请填写昵称');
    if (!password) return showError('请填写房间密码（房间不存在时将用它创建）');

    state.roomId = roomId;
    state.nick = nick;
    state.password = password;
    joinBtn.disabled = true;
    connect();
  });

  // Enter 发送
  msgInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') sendCurrent();
  });
  sendBtn.addEventListener('click', sendCurrent);

  // 退出
  $('leaveBtn').addEventListener('click', () => {
    if (state.socket) state.socket.disconnect();
    location.reload();
  });
  // 结束私聊
  $('privateClose').addEventListener('click', stopPrivate);

  // 默认服务器地址 = 当前站点地址
  $('serverAddr').value = location.origin || ('http://' + location.host);
})();
