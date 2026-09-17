/**
 * start.js — 并行启动前端界面服务（public/web.js, 3000）与后端聊天服务（server.js, 3001）
 *
 * 用法：npm start（等价于 node start.js）
 *  - 两个子进程均继承 stdio，日志直接输出到当前终端
 *  - 任一进程退出时，另一个进程也会被终止
 */
'use strict';

const { spawn } = require('child_process');
const path = require('path');

const ROOT = __dirname;
const webProc = spawn(process.execPath, [path.join(ROOT, 'public', 'web.js')], { stdio: 'inherit' });
const serverProc = spawn(process.execPath, [path.join(ROOT, 'server.js')], { stdio: 'inherit' });

let shuttingDown = false;
function shutdown(exitCode = 0) {
  if (shuttingDown) return;
  shuttingDown = true;
  try { webProc.kill(); } catch (e) { /* noop */ }
  try { serverProc.kill(); } catch (e) { /* noop */ }
  setTimeout(() => process.exit(exitCode), 300);
}

process.on('SIGINT', () => shutdown(0));
process.on('SIGTERM', () => shutdown(0));

webProc.on('exit', (code) => {
  console.error(`[web.js] 前端服务退出，code=${code}`);
  shutdown(code || 0);
});
serverProc.on('exit', (code) => {
  console.error(`[server.js] 后端服务退出，code=${code}`);
  shutdown(code || 0);
});
