# Analysis: Root Cause and Escalation

## Affected Code Path

```
decompress(input, output)
  -> makeExtractor (decompress-unzip / decompress-tar)
    -> extract(entry, output)
      -> line 104-109: realDestinationDir check (file + hardlink paths)
      -> line 112-113: hard link -> fsP.link(x.linkname, dest)   [checked]
      -> line 116-118: symlink -> fsP.symlink(x.linkname, dest)  [NOT checked]
```

## Vulnerability 1 - Symlink Escape

`decompress-unzip/index.js` derives the entry type from the zip external
attributes:

```js
file.mode = (entry.externalFileAttributes >> 16) & 0xFFFF;
file.type = getType(entry, file.mode);
// getType: (mode & IFMT) === IFLNK  ->  'symlink'
```

A crafted zip sets the symlink mode (`0xA000`), so `file.type === 'symlink'`.
On POSIX the extractor creates the symlink directly:

```js
if (x.type === 'symlink') {
    return fsP.symlink(x.linkname, dest);
}
```

There is no `realDestinationDir`-style check on this branch. The symlink is
created pointing anywhere the archive says, e.g. `escape.txt -> ../../marker.txt`.
Writes through that symlink escape the output directory.

## Vulnerability 2 - Hardlink Write Bypass

`preventWritingThroughSymlink` is only invoked for `x.type === 'file'`:

```js
if (x.type === 'file') {
    return preventWritingThroughSymlink(dest, realOutputPath);
}
if (x.type === 'link') {
    return fsP.link(x.linkname, dest);       // hard link, unchecked
}
```

A hard link entry is materialized with `fsP.link()`. It is not a symlink, so a
subsequent `preventWritingThroughSymlink(dest)` call does `fsP.readlink(dest)`,
which throws/returns null for a hard link, and the write proceeds through the
hard link to the external target.

## Why the fork fix works

The `@xhmikosr/decompress` fork adds `ensureLinkTargetInsideOutput()` which
resolves the link target and verifies it stays inside the output directory
before creating the link. Applying the same check to both the symlink branch
and the hardlink branch closes both bypasses.

## RCE Escalation Vectors

Arbitrary file write can become code execution depending on context:

1. **Shell profiles** - overwrite `~/.bashrc` / `~/.zshrc` to run a payload on
   the next interactive shell.
2. **Cron jobs** - write to `/etc/crontab` or `/etc/cron.d/` when running as
   root.
3. **SSH keys** - overwrite or append `~/.ssh/authorized_keys`.
4. **Application code** - overwrite a file in `node_modules` or patch a
   `package.json` `postinstall` hook when extracted inside a package build.

## Verification Notes

- Tested against `decompress@4.2.1` on Node.js 24.18.0 / Linux.
- Both PoCs create their own directories under `/tmp` and remove them on exit.
- The symlink PoC builds a zip by hand (including the required symlink mode in
  the central directory external attributes) so no extra npm dependency is
  needed beyond `decompress` itself.
