/**
 * public/web.js — 前端显示界面服务（默认 3000 端口）
 *
 * 职责：仅 Express 静态托管 public 目录（index.html / vendor / crypto.js / app.js），
 * 不承载 Socket.IO 与存储逻辑；聊天后端在 3001 端口（server.js）。
 */
'use strict';

const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// 静态托管 public 目录（本文件位于 public/ 下，__dirname 即静态根目录）
app.use(express.static(__dirname));

// 健康检查（前端 3000 端口）
app.get('/api/health', (req, res) => {
  res.json({ ok: true, time: Date.now() });
});

app.listen(PORT, () => {
  console.log(`✔ 前端页面已启动：http://localhost:${PORT}`);
  console.log(`  聊天后端服务：http://localhost:${process.env.BACKEND_PORT || 3001}`);
});
