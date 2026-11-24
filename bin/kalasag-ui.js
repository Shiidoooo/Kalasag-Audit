#!/usr/bin/env node

import { exec } from 'node:child_process';
import { createAppServer } from '../src/server.js';

const PORT = Number(process.env.PORT) || 3847;
const HOST = process.env.HOST || '127.0.0.1';
const shouldOpen = process.argv.includes('--open') || process.argv.includes('-o');

const server = createAppServer();

server.listen(PORT, HOST, () => {
  const url = `http://${HOST}:${PORT}`;
  console.log(`
  \x1b[33m╔══════════════════════════════════════════════════════════╗
  ║                  \x1b[1m\x1b[37mKALASAG AUDIT — WEB UI\x1b[0m\x1b[33m                  ║
  ║       Outside-In Web Security & Posture Auditor          ║
  ╚══════════════════════════════════════════════════════════╝\x1b[0m

  \x1b[32m[✓] Local server running at:\x1b[0m  \x1b[1m\x1b[4m${url}\x1b[0m
  \x1b[90m[*] Bound to ${HOST} (local-only). Press Ctrl+C to stop.\x1b[0m
  `);

  if (shouldOpen) {
    const cmd =
      process.platform === 'win32'
        ? `start "" "${url}"`
        : process.platform === 'darwin'
          ? `open "${url}"`
          : `xdg-open "${url}"`;
    exec(cmd);
  }
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`\n  \x1b[31m[!] Port ${PORT} is already in use. Try setting PORT=3848 npm run ui\x1b[0m\n`);
  } else {
    console.error(`\n  \x1b[31m[!] Server error:\x1b[0m ${err.message}\n`);
  }
  process.exit(1);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    console.log('\n  \x1b[33m[*] Shutting down Kalasag Audit local server...\x1b[0m');
    server.close(() => process.exit(0));
  });
}
