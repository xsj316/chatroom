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
  // 纯 JS 加密库（@noble 系列）无需 HTTPS / localhost，公网 HTTP 亦可用
  if (!window.NobleCrypto) {
    document.body.innerHTML = '<div style="padding:40px;text-align:center">加密库未加载：请确认页面正确引入了 /vendor/noble.js 与 /crypto.js。</div>';
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
    privateTarget: null,    // 当前私聊对象 id
    friendNicks: new Set(), // 当前用户的好友昵称集合
    pendingFriend: null     // 待处理的好友请求 { from, fromId }
  };

  /* ---------------- 页面元素 ---------------- */
  const loginPage = $('loginPage');
  const loginCard = $('loginCard');
  const registerCard = $('registerCard');
  const toRegisterLink = $('toRegisterLink');
  const toLoginLink = $('toLoginLink');
  const loginAccount = $('loginAccount');
  const loginPassword = $('loginPassword');
  const loginBtn = $('loginBtn');
  const loginError = $('loginError');
  const pwdLoginSection = $('pwdLoginSection');
  const dkLoginSection = $('dkLoginSection');
  const loginDeviceKey = $('loginDeviceKey');
  const dkLoginBtn = $('dkLoginBtn');
  const dkLoginError = $('dkLoginError');
  const loginSubTitle = $('loginSubTitle');
  const toDeviceKeyLink = $('toDeviceKeyLink');
  const toPasswordLink = $('toPasswordLink');
  const toRegisterLink2 = $('toRegisterLink2');
  const regUsername = $('regUsername');
  const regEmail = $('regEmail');
  const regPassword = $('regPassword');
  const regPassword2 = $('regPassword2');
  const registerBtn = $('registerBtn');
  const registerError = $('registerError');
  const joinPage = $('joinPage');
  const openSettingsBtn = $('openSettingsBtn');
  const settingsPage = $('settingsPage');
  const settingsBackBtn = $('settingsBackBtn');
  const setUsername = $('setUsername');
  const setEmail = $('setEmail');
  const genDeviceKeyBtn = $('genDeviceKeyBtn');
  const newDkBox = $('newDkBox');
  const newDkKey = $('newDkKey');
  const newDkCloseBtn = $('newDkCloseBtn');
  const dkList = $('dkList');
  const settingsError = $('settingsError');
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
  const friendRequestBar = $('friendRequestBar');
  const friendRequestText = $('friendRequestText');

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

  /* ---------------- 登录 / 注册（账号体系，仿微软风格） ---------------- */
  function showLoginError(text) {
    loginError.textContent = text;
    loginError.classList.add('show');
  }
  function hideLoginError() {
    loginError.classList.remove('show');
  }
  function showRegisterError(text) {
    registerError.textContent = text;
    registerError.classList.add('show');
  }
  function hideRegisterError() {
    registerError.classList.remove('show');
  }
  /** 后端登录 API 基础地址：端口拆分架构，固定为当前站点 host + 3001 */
  function resolveBackendBase() {
    return location.protocol + '//' + location.hostname + ':3001';
  }
  function isValidEmail(s) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(s || '').trim());
  }
  /** 登录/注册成功：保存 token 与用户名，隐藏认证页并显示加入页（昵称默认填充用户名） */
  function showJoinPage() {
    hideLoginError();
    hideRegisterError();
    loginPage.style.display = 'none';
    joinPage.style.display = 'flex';
    $('serverAddr').value = resolveBackendBase();
    $('nick').value = sessionStorage.getItem('chatroom_username') || '';
  }
  async function doLogin() {
    const account = (loginAccount.value || '').trim();
    const password = loginPassword.value || '';
    if (!account) return showLoginError('请输入用户名或邮箱');
    if (!password) return showLoginError('请输入密码');
    const backend = resolveBackendBase();
    loginBtn.disabled = true;
    hideLoginError();
    try {
      const resp = await fetch(backend + '/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ account, password })
      });
      const data = await resp.json();
      if (data && data.ok === true && data.token) {
        sessionStorage.setItem('chatroom_token', data.token);
        sessionStorage.setItem('chatroom_username', data.username || account);
        showJoinPage();
      } else {
        showLoginError((data && data.error) || '登录失败');
      }
    } catch (e) {
      showLoginError('无法连接登录服务器：' + e.message);
    } finally {
      loginBtn.disabled = false;
    }
  }
  /** 设备密钥直接登录（方式 B） */
  function showDkLoginError(text) {
    dkLoginError.textContent = text;
    dkLoginError.classList.add('show');
  }
  function hideDkLoginError() {
    dkLoginError.classList.remove('show');
  }
  function switchToDeviceKeyMode() {
    pwdLoginSection.style.display = 'none';
    dkLoginSection.style.display = 'block';
    loginSubTitle.textContent = '使用设备密钥免密码登录';
    hideLoginError();
    hideDkLoginError();
    loginDeviceKey.focus();
  }
  function switchToPasswordMode() {
    dkLoginSection.style.display = 'none';
    pwdLoginSection.style.display = 'block';
    loginSubTitle.textContent = '使用用户名或邮箱登录加密聊天室';
    hideLoginError();
    hideDkLoginError();
  }
  async function doDeviceKeyLogin() {
    const deviceKey = (loginDeviceKey.value || '').trim();
    if (!deviceKey) return showDkLoginError('请输入设备密钥');
    const backend = resolveBackendBase();
    dkLoginBtn.disabled = true;
    hideDkLoginError();
    try {
      const resp = await fetch(backend + '/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ deviceKey })
      });
      const data = await resp.json();
      if (data && data.ok === true && data.token) {
        sessionStorage.setItem('chatroom_token', data.token);
        sessionStorage.setItem('chatroom_username', data.username || '');
        switchToPasswordMode();
        showJoinPage();
      } else {
        showDkLoginError((data && data.error) || '设备密钥登录失败');
      }
    } catch (e) {
      showDkLoginError('无法连接登录服务器：' + e.message);
    } finally {
      dkLoginBtn.disabled = false;
    }
  }

  /* ---------------- 账号设置页（设备密钥管理） ---------------- */
  function showSettingsError(text) {
    settingsError.textContent = text;
    settingsError.classList.add('show');
  }
  function hideSettingsError() {
    settingsError.classList.remove('show');
  }
  /** 带 token 的 API 请求封装：GET / POST / DELETE */
  async function apiFetch(path, opts) {
    const token = sessionStorage.getItem('chatroom_token') || '';
    const init = Object.assign({}, opts || {});
    init.headers = Object.assign({}, (init.headers || {}));
    if (token) init.headers['Authorization'] = 'Bearer ' + token;
    const resp = await fetch(resolveBackendBase() + path, init);
    return resp.json();
  }
  function fmtDkTime(ts) {
    const d = new Date(ts);
    const p = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
  }
  async function loadSettings() {
    hideSettingsError();
    setUsername.textContent = sessionStorage.getItem('chatroom_username') || '-';
    setEmail.textContent = '-';
    try {
      const authData = await apiFetch('/api/auth/status');
      if (authData && authData.ok && authData.user) {
        setUsername.textContent = authData.user.username || '-';
        setEmail.textContent = authData.user.email || '-';
      }
    } catch (e) { /* 邮箱获取失败不影响主流程 */ }
    renderDkList(await apiFetch('/api/device-keys'));
  }
  function renderDkList(data) {
    dkList.innerHTML = '';
    if (!data || !data.ok) {
      const tip = document.createElement('div');
      tip.className = 'empty-tip';
      tip.textContent = (data && data.error) || '获取设备密钥列表失败';
      dkList.appendChild(tip);
      return;
    }
    if (!Array.isArray(data.keys) || data.keys.length === 0) {
      const tip = document.createElement('div');
      tip.className = 'empty-tip';
      tip.textContent = '暂无设备密钥，点击上方按钮为本机生成一个';
      dkList.appendChild(tip);
      return;
    }
    for (const dk of data.keys) {
      const item = document.createElement('div');
      item.className = 'dk-item';
      const meta = document.createElement('div');
      meta.className = 'dk-meta';
      meta.innerHTML = '设备密钥 <span class="dk-tail">…' + esc(dk.tail || '') + '</span><div class="dk-time">创建于 ' + fmtDkTime(dk.createdAt) + '</div>';
      const del = document.createElement('button');
      del.className = 'dk-del';
      del.textContent = '删除';
      del.addEventListener('click', async () => {
        if (!window.confirm('确定删除这台设备的密钥吗？删除后该设备将无法用此密钥登录。')) return;
        hideSettingsError();
        del.disabled = true;
        try {
          const r = await apiFetch('/api/device-keys/' + encodeURIComponent(dk.id), { method: 'DELETE' });
          if (r && r.ok) renderDkList(await apiFetch('/api/device-keys'));
          else showSettingsError((r && r.error) || '删除失败');
        } catch (e) {
          showSettingsError('删除失败：' + e.message);
        }
      });
      item.appendChild(meta);
      item.appendChild(del);
      dkList.appendChild(item);
    }
  }
  async function genDeviceKey() {
    hideSettingsError();
    genDeviceKeyBtn.disabled = true;
    try {
      const data = await apiFetch('/api/device-keys', { method: 'POST' });
      if (data && data.ok && data.key) {
        newDkKey.textContent = data.key;
        newDkBox.classList.add('show');
        renderDkList(await apiFetch('/api/device-keys'));
      } else {
        showSettingsError((data && data.error) || '生成失败，请重新登录');
      }
    } catch (e) {
      showSettingsError('生成失败：' + e.message);
    } finally {
      genDeviceKeyBtn.disabled = false;
    }
  }
  function openSettings() {
    hideSettingsError();
    newDkBox.classList.remove('show');
    newDkKey.textContent = '';
    joinPage.style.display = 'none';
    settingsPage.classList.add('active');
    loadSettings();
  }
  function closeSettings() {
    settingsPage.classList.remove('active');
    joinPage.style.display = 'flex';
  }
  async function doRegister() {
    const username = (regUsername.value || '').trim();
    const email = (regEmail.value || '').trim();
    const password = regPassword.value || '';
    const confirm = regPassword2.value || '';
    if (!username) return showRegisterError('请输入用户名');
    if (!email) return showRegisterError('请输入邮箱');
    if (!isValidEmail(email)) return showRegisterError('邮箱格式不正确');
    if (password.length < 4) return showRegisterError('密码最短 4 位');
    if (password !== confirm) return showRegisterError('两次输入的密码不一致');
    const backend = resolveBackendBase();
    registerBtn.disabled = true;
    hideRegisterError();
    try {
      const resp = await fetch(backend + '/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, email, password })
      });
      const data = await resp.json();
      if (data && data.ok === true && data.token) {
        sessionStorage.setItem('chatroom_token', data.token);
        sessionStorage.setItem('chatroom_username', data.username || username);
        showJoinPage();
      } else {
        showRegisterError((data && data.error) || '注册失败');
      }
    } catch (e) {
      showRegisterError('无法连接注册服务器：' + e.message);
    } finally {
      registerBtn.disabled = false;
    }
  }
  /** 登录/注册卡片互切（微软账号风格） */
  function switchToLogin() {
    loginCard.classList.add('active');
    registerCard.classList.remove('active');
    hideLoginError();
    hideRegisterError();
  }
  function switchToRegister() {
    registerCard.classList.add('active');
    loginCard.classList.remove('active');
    hideLoginError();
    hideRegisterError();
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
        const isFriend = state.friendNicks.has(u.nick);
        const tip = document.createElement('span');
        tip.className = 'priv-tip';
        if (isFriend) {
          tip.textContent = '私聊';
          item.title = '点击发起私聊';
          item.addEventListener('click', () => startPrivate(id));
        } else {
          tip.textContent = '＋加好友';
          item.title = '点击添加好友';
          item.addEventListener('click', () => sendFriendRequest(id));
        }
        item.appendChild(tip);
      }
      usersListEl.appendChild(item);
    }
  }

  /* ---------------- 好友 ---------------- */
  function sendFriendRequest(targetId) {
    const target = state.users.get(targetId);
    if (!target || targetId === state.myId) return;
    if (state.friendNicks.has(target.nick)) return; // 已是好友无需重复请求
    state.socket.emit('friend:request', { to: targetId });
    addSystem(`已向 ${target.nick} 发送好友请求，等待对方确认`);
  }

  // 页面内联确认条：替代 window.confirm（iframe/内嵌预览环境会拦截 confirm 并返回 false）
  function showFriendRequestBar(from, fromId) {
    if (!friendRequestBar || !friendRequestText) return;
    state.pendingFriend = { from, fromId };
    friendRequestText.textContent = `${from} 请求加你为好友`;
    friendRequestBar.classList.add('show'); // 同一时间只显示一个请求，新请求直接覆盖旧内容
  }
  function hideFriendRequestBar() {
    state.pendingFriend = null;
    if (friendRequestBar) friendRequestBar.classList.remove('show');
  }
  // 确认条按钮：接受/拒绝（按钮在 index.html 中，事件在此统一绑定）
  document.addEventListener('DOMContentLoaded', () => {
    const acceptBtn = $('friendAcceptBtn');
    const rejectBtn = $('friendRejectBtn');
    if (acceptBtn) {
      acceptBtn.addEventListener('click', () => {
        if (state.pendingFriend) {
          state.socket.emit('friend:accept', { to: state.pendingFriend.fromId });
        }
        hideFriendRequestBar();
      });
    }
    if (rejectBtn) {
      rejectBtn.addEventListener('click', () => {
        if (state.pendingFriend) {
          state.socket.emit('friend:reject', { to: state.pendingFriend.fromId });
        }
        hideFriendRequestBar();
      });
    }
  });

  /* ---------------- 私聊 ---------------- */
  async function startPrivate(targetId) {
    const target = state.users.get(targetId);
    if (!target || targetId === state.myId) return;
    // 好友校验：只有互为好友才能私聊
    if (!state.friendNicks.has(target.nick)) {
      addSystem(`请先添加 ${target.nick} 为好友，才能发起私聊`);
      return;
    }
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
        password: state.password,
        token: sessionStorage.getItem('chatroom_token') || ''
      },
      transports: ['websocket', 'polling']
    });
    state.socket = socket;

    socket.on('connect_error', (err) => {
      joinBtn.disabled = false;
      showError('无法加入：' + (err.message || '连接失败') + '（请检查服务器地址、登录状态与房间密码）');
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

    // 好友列表（加入房间时服务端下发）
    socket.on('friends:list', (nicks) => {
      state.friendNicks = new Set(Array.isArray(nicks) ? nicks : []);
      renderUsers();
    });

    // 收到好友请求：显示页面内联确认条（不用 window.confirm，避免 iframe 环境静默拒绝）
    socket.on('friend:request', (data) => {
      if (!data || !data.from || !data.fromId) return;
      showFriendRequestBar(data.from, data.fromId);
    });

    // 好友添加成功（双方都会收到，携带对方昵称）
    socket.on('friend:added', (data) => {
      if (data && data.nick) {
        state.friendNicks.add(data.nick);
        renderUsers();
        addSystem(`已与 ${data.nick} 成为好友，现在可以私聊了`);
      }
    });

    // 好友请求被拒绝
    socket.on('friend:rejected', (data) => {
      addSystem(data && data.nick ? `${data.nick} 拒绝了你的好友请求` : '对方拒绝了你的好友请求');
    });

    // 私聊被拒（非好友）
    socket.on('chat:private_denied', (data) => {
      addSystem(data && data.reason ? data.reason : '无法私聊：请先添加对方为好友');
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

  // 登录 / 注册 / 设备密钥：点击按钮 / 回车提交
  loginBtn.addEventListener('click', doLogin);
  loginPassword.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') doLogin();
  });
  dkLoginBtn.addEventListener('click', doDeviceKeyLogin);
  loginDeviceKey.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') doDeviceKeyLogin();
  });
  registerBtn.addEventListener('click', doRegister);
  regPassword2.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') doRegister();
  });
  // 卡片切换
  toRegisterLink.addEventListener('click', switchToRegister);
  toRegisterLink2.addEventListener('click', switchToRegister);
  toLoginLink.addEventListener('click', switchToLogin);
  toDeviceKeyLink.addEventListener('click', switchToDeviceKeyMode);
  toPasswordLink.addEventListener('click', switchToPasswordMode);

  // 账号设置
  openSettingsBtn.addEventListener('click', openSettings);
  settingsBackBtn.addEventListener('click', closeSettings);
  genDeviceKeyBtn.addEventListener('click', genDeviceKey);
  newDkCloseBtn.addEventListener('click', () => {
    newDkBox.classList.remove('show');
    newDkKey.textContent = '';
  });

  // 默认服务器地址 = 当前站点 host + 后端端口 3001（端口拆分：页面 3000 / 聊天后端 3001）
  const defaultBackend = location.protocol + '//' + location.hostname + ':3001';
  $('serverAddr').value = defaultBackend;

  // 已登录（sessionStorage 有 token）→ 直接显示加入页；否则停留在登录页
  if (sessionStorage.getItem('chatroom_token')) {
    loginPage.style.display = 'none';
    joinPage.style.display = 'flex';
    $('nick').value = sessionStorage.getItem('chatroom_username') || '';
  }
})();
