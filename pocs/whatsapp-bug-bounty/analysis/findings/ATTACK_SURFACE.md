# WhatsApp Native Media Parser Attack Surface

## Architecture
- `libs.so` is a **superpack archive** containing 30+ packed .so libraries
- `libsuperpack.so` unpacks them at runtime via `dlopen`/`mmap`/`mprotect`
- Archive is **encrypted** - no ELF headers, no standard compression signatures
- Cannot extract packed libraries statically - need runtime unpacking

## Key Native Libraries (packed inside libs.so)
| Library | Purpose |
|---------|---------|
| `libgifimage.so` | GIF parsing/decoding |
| `libstatic-webp.so` | WebP parsing/decoding |
| `libwebpencoder-native.so` | WebP encoding |
| `libopus_mlow.so` | Opus audio codec |
| `libwa_sandboxed_gifimage.so` | Sandboxed GIF parsing |
| `libnative-filters.so` | Image filters |
| `libsqlitejni.so` | SQLite JNI bridge |
| `libprofilo_*.so` | Profiling/logging |
| `libgraphicsengine-*.so` | AR/graphics engine |

## JNI Attack Surface (from smali analysis)

### Mp4Ops (highest priority)
```
mp4check(String path, boolean) -> LibMp4OperationResult
mp4checkAndRepair(String input, String output) -> LibMp4CheckAndRepairResult
mp4mux(String input1, String input2, String output, float, int) -> LibMp4OperationResult
mp4streamcheck(String path, boolean, long) -> LibMp4StreamCheckResult
mp4DescribeEditList(String path) -> LibMp4EditListInfo
mp4forensic(int, String, String) -> boolean
mp4removeDolbyEAC3Track(String input, String output) -> LibMp4OperationResult
removeAudioTracks(String input, String output) -> LibMp4OperationResult
```

### GifHelper
```
applyGifTag(String input, String output) -> LibMp4OperationResult
hasGifTag(String path) -> boolean
```

### ImgOps
```
createImageForensicEvidence(int, String, String) -> boolean
nativeStripJpegMetadata(int, int) -> int
```

### VideoFrameConverter
```
convertAndroid420toARGB(ByteBuffer, int, ...) -> void
convertAndroid420toI420(ByteBuffer, int, ...) -> void
scalePlane(ByteBuffer, int, int, int, ByteBuffer, int, int, int) -> void
```

### OpusPlayer/OpusRecorder
```
allocateNative(String, int, OpusPlayerConfig) -> void
freeNative() -> void
```

## Exploitation Strategy

### Most Promising Targets
1. **mp4check / mp4checkAndRepair** - takes file path, parses MP4 container. Crafted MP4 could trigger buffer overflow in box parsing
2. **mp4mux** - takes two inputs, merges them. Complex parsing = more attack surface
3. **GIF tag operations** - `applyGifTag` / `hasGifTag` process GIF metadata
4. **VideoFrameConverter** - ByteBuffer operations, potential for out-of-bounds read/write

### Why Native RCE is High-Value
- WhatsApp runs with full app permissions (contacts, camera, storage, microphone)
- Native code runs in the same process as the Java app
- Buffer overflow in media parser = code execution in WhatsApp's context
- No user interaction beyond receiving a media file (passive trigger)

### Current Blocker
- Cannot extract packed .so files statically (encrypted superpack format)
- Need Android runtime to unpack libraries for Ghidra analysis
- Alternatively: analyze the superpack unpacker (`libsuperpack.so`) to understand the format

## Files Created
- `/home/kali/2stage/analysis/ghidra/WhatsAppAnalysis.gpr` - Ghidra project
- `/home/kali/2stage/analysis/extracted_libs/superpack_archive.bin` - raw archive data
- `/home/kali/2stage/analysis/findings/ATTACK_SURFACE.md` - this file
