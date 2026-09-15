/**
 * crypto.js — 浏览器端加密工具（Web Crypto API，零第三方依赖）
 *
 * 加密体系：
 *  - 群聊：房间密码 → PBKDF2(100k 次, 房间号确定性盐) → AES-256-GCM 密钥
 *          （所有同房间用户用同一密码与同一盐，故能互相解密；服务端无密钥）
 *  - 私聊：ECDH(P-256) 密钥协商 → 双方共享密钥 → HKDF 派生 → AES-256-GCM
 *          （仅通信双方可解密）
 *
 * 所有密文以 { ciphertext, iv, tag } base64 结构传输，服务端仅转发。
 */
'use strict';

const CryptoChat = (() => {

  const enc = new TextEncoder();
  const dec = new TextDecoder();

  /* ---------------- 工具 ---------------- */
  function b64(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
  }
  function unb64(str) {
    const bin = atob(str);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }
  function bytesToHex(buf) {
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * PBKDF2 派生房间密钥：房间密码 + 房间 ID → 256 位 AES 密钥
   * 盐由房间号确定派生（SHA-256(roomId) 前 16 字节），保证同房间所有用户
   * 派生出一致的密钥，才能互相解密；密钥不出浏览器。
   */
  async function deriveRoomKey(roomId, password) {
    const baseKey = await crypto.subtle.importKey(
      'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    // 确定性盐：由房间号派生，同房间所有客户端一致
    const roomHash = await crypto.subtle.digest('SHA-256', enc.encode(String(roomId)));
    const saltBytes = new Uint8Array(roomHash).slice(0, 16);
    const roomKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: saltBytes,
        iterations: 100000,
        hash: 'SHA-256'
      },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    return { roomKey, saltB64: b64(saltBytes) };
  }

  /** AES-256-GCM 加密 → { ciphertext, iv, tag }（base64） */
  async function aesEncrypt(key, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = enc.encode(plaintext);
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, tagLength: 128 }, key, data
    );
    // WebCrypto GCM 输出 = ciphertext || tag(16B)，按标准切分
    const ctBytes = new Uint8Array(ct);
    const ciphertext = ctBytes.slice(0, ctBytes.length - 16);
    const tag = ctBytes.slice(ctBytes.length - 16);
    return { ciphertext: b64(ciphertext), iv: b64(iv), tag: b64(tag) };
  }

  /** AES-256-GCM 解密，失败返回 null（密文被篡改 / 密钥不匹配） */
  async function aesDecrypt(key, payload) {
    try {
      const iv = unb64(payload.iv);
      const tag = unb64(payload.tag);
      const ct = unb64(payload.ciphertext);
      const combined = new Uint8Array(ct.length + tag.length);
      combined.set(ct, 0);
      combined.set(tag, ct.length);
      const plain = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, tagLength: 128 }, key, combined
      );
      return dec.decode(plain);
    } catch (e) {
      return null;
    }
  }

  /* ---------------- 私聊：ECDH P-256 密钥协商 ---------------- */
  const ecdhParams = { name: 'ECDH', namedCurve: 'P-256' };

  /** 生成 ECDH 密钥对，公钥以 raw(base64) 形式交换 */
  async function ecdhGenerate() {
    const kp = await crypto.subtle.generateKey(ecdhParams, true, ['deriveKey']);
    const rawPub = await crypto.subtle.exportKey('raw', kp.publicKey);
    return { keyPair: kp, publicKeyB64: b64(rawPub) };
  }

  /** 本地私钥 + 对方公钥 → 共享密钥 → HKDF → AES-256-GCM 密钥 */
  async function ecdhDeriveSharedKey(myKeyPair, peerPublicKeyB64, contextStr) {
    const peerRaw = unb64(peerPublicKeyB64);
    const peerKey = await crypto.subtle.importKey('raw', peerRaw, ecdhParams, false, []);
    const shared = await crypto.subtle.deriveKey(
      { name: 'ECDH', public: peerKey }, myKeyPair.privateKey,
      { name: 'HKDF' }, false, ['deriveKey']
    );
    const aesKey = await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: enc.encode('chatroom-ecdh-salt-v1'),
        info: enc.encode(contextStr)
      },
      shared,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    return aesKey;
  }

  /** 一次性会话随机数（供 ECDH 握手防重放） */
  function randomId() {
    return bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
  }

  return {
    deriveRoomKey,
    aesEncrypt,
    aesDecrypt,
    ecdhGenerate,
    ecdhDeriveSharedKey,
    randomId,
    b64,
    unb64
  };
})();

if (typeof window !== 'undefined') window.CryptoChat = CryptoChat;
