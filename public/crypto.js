/**
 * crypto.js — 浏览器端加密工具（纯 JS 实现：@noble/ciphers + @noble/hashes + @noble/curves）
 *
 * 加密体系：
 *  - 群聊：房间密码 → PBKDF2(100k 次, 房间号确定性盐) → AES-256-GCM 密钥
 *          （所有同房间用户用同一密码与同一盐，故能互相解密；服务端无密钥）
 *  - 私聊：ECDH(P-256) 密钥协商 → 双方共享密钥 → HKDF 派生 → AES-256-GCM
 *          （仅通信双方可解密）
 *
 * 所有密文以 { ciphertext, iv, tag } base64 结构传输，服务端仅转发。
 *
 * 说明：不再依赖 Web Crypto API（crypto.subtle），因此无需 HTTPS / localhost，
 * 公网 HTTP 环境下同样可用。底层由 public/vendor/noble.js 提供（esbuild 打包的
 * @noble 系列库），请确保在 crypto.js 之前引入该文件。
 */
'use strict';

const CryptoChat = (() => {
  const N = (typeof window !== 'undefined' && window.NobleCrypto) ||
            (typeof globalThis !== 'undefined' && globalThis.NobleCrypto);
  if (!N) {
    throw new Error('NobleCrypto 未加载：请先引入 public/vendor/noble.js');
  }

  const { gcm, pbkdf2, sha256, hkdf, randomBytes, utf8ToBytes, bytesToHex, hexToBytes, bytesToUtf8, concatBytes, p256 } = N;

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

  /**
   * PBKDF2 派生房间密钥：房间密码 + 房间 ID → 256 位 AES 密钥
   * 盐由房间号确定派生（SHA-256(roomId) 前 16 字节），保证同房间所有用户
   * 派生出一致的密钥，才能互相解密；密钥不出浏览器。
   * 返回 roomKey（Uint8Array 32 字节）与 saltB64，接口与旧版一致。
   */
  async function deriveRoomKey(roomId, password) {
    const roomHash = sha256(enc.encode(String(roomId)));
    const saltBytes = roomHash.slice(0, 16);
    const roomKey = pbkdf2(sha256, enc.encode(password), saltBytes, { c: 100000, dkLen: 32 });
    return { roomKey, saltB64: b64(saltBytes) };
  }

  /** AES-256-GCM 加密 → { ciphertext, iv, tag }（base64） */
  async function aesEncrypt(key, plaintext) {
    const iv = randomBytes(12);
    const ct = gcm(key, iv).encrypt(enc.encode(plaintext));
    // noble gcm 输出 = ciphertext || tag(16B)，按标准切分
    const ciphertext = ct.slice(0, ct.length - 16);
    const tag = ct.slice(ct.length - 16);
    return { ciphertext: b64(ciphertext), iv: b64(iv), tag: b64(tag) };
  }

  /** AES-256-GCM 解密，失败返回 null（密文被篡改 / 密钥不匹配） */
  async function aesDecrypt(key, payload) {
    try {
      const iv = unb64(payload.iv);
      const tag = unb64(payload.tag);
      const ct = unb64(payload.ciphertext);
      const combined = concatBytes(ct, tag);
      const plain = gcm(key, iv).decrypt(combined);
      return dec.decode(plain);
    } catch (e) {
      return null;
    }
  }

  /* ---------------- 私聊：ECDH P-256 密钥协商 ---------------- */

  /** 生成 ECDH 密钥对，公钥以 raw(未压缩 65B, base64) 形式交换 */
  async function ecdhGenerate() {
    const privateKey = p256.utils.randomPrivateKey();
    const rawPub = p256.getPublicKey(privateKey, false); // 未压缩 65 字节，与 WebCrypto raw 导出一致
    return { keyPair: { privateKey }, publicKeyB64: b64(rawPub) };
  }

  /** 本地私钥 + 对方公钥 → 共享密钥(X 坐标) → HKDF → AES-256-GCM 密钥 */
  async function ecdhDeriveSharedKey(myKeyPair, peerPublicKeyB64, contextStr) {
    const peerRaw = unb64(peerPublicKeyB64);
    const shared = p256.getSharedSecret(myKeyPair.privateKey, peerRaw); // 33B 压缩点
    const x = shared.slice(1); // X 坐标 32 字节，与 WebCrypto ECDH 输出一致
    const aesKey = hkdf(sha256, x, enc.encode('chatroom-ecdh-salt-v1'), enc.encode(contextStr), 32);
    return aesKey;
  }

  /** 一次性会话随机数（供 ECDH 握手防重放） */
  function randomId() {
    return bytesToHex(randomBytes(16));
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
