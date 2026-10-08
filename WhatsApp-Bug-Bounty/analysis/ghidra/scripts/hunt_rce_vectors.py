# Ghidra headless script: Hunt RCE vectors - fixed for array-based refs

import json

OUTPUT = "/home/kali/2stage/analysis/ghidra/libs_rce_analysis.json"

def run():
    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()
    mem = currentProgram.getMemory()

    report = {
        "program": currentProgram.getName(),
        "language": str(currentProgram.getLanguageID()),
        "total_functions": fm.getFunctionCount(),
        "jni_entry_points": [],
        "gif_functions": [],
        "webp_functions": [],
        "mp4_functions": [],
        "dangerous_calls": [],
        "large_functions": [],
        "format_strings": [],
        "buffer_vulns": [],
    }

    # ===== 1. Find JNI entry points =====
    func_iter = fm.getFunctions(True)
    while func_iter.hasNext():
        func = func_iter.next()
        name = func.getName()
        body = func.getBody()
        size = body.getNumAddresses() if body else 0

        if name.startswith("Java_") or name == "JNI_OnLoad" or "RegisterNatives" in name:
            report["jni_entry_points"].append({
                "name": name,
                "address": str(func.getEntryPoint()),
                "size": size,
                "signature": str(func.getSignature()),
            })

    # ===== 2. Find media parser functions =====
    func_iter2 = fm.getFunctions(True)
    while func_iter2.hasNext():
        func = func_iter2.next()
        name = func.getName()
        name_lower = name.lower()
        body = func.getBody()
        size = body.getNumAddresses() if body else 0

        if any(kw in name_lower for kw in ["gif", "lzw", "gct", "lct", "graphic_control", "image_descriptor"]):
            report["gif_functions"].append({"name": name, "address": str(func.getEntryPoint()), "size": size})
        if any(kw in name_lower for kw in ["webp", "vp8", "vp9", "lossless", "lossy"]):
            report["webp_functions"].append({"name": name, "address": str(func.getEntryPoint()), "size": size})
        if any(kw in name_lower for kw in ["mp4", "atom", "moov", "mdat", "ftyp", "avc", "hevc", "sample"]):
            report["mp4_functions"].append({"name": name, "address": str(func.getEntryPoint()), "size": size})

    # ===== 3. Find dangerous function calls =====
    dangerous_names = [
        "malloc", "calloc", "realloc", "free",
        "memcpy", "memmove", "memset", "memcmp",
        "strcpy", "strncpy", "strcat", "strncat", "sprintf", "snprintf",
        "fread", "fwrite", "fopen", "fseek", "ftell",
        "mmap", "munmap", "mprotect",
        "dlopen", "dlsym", "dlclose",
        "read", "write", "open", "close", "lseek",
    ]

    func_iter3 = fm.getFunctions(True)
    while func_iter3.hasNext():
        func = func_iter3.next()
        name = func.getName()

        if name in dangerous_names:
            body = func.getBody()
            size = body.getNumAddresses() if body else 0

            try:
                refs = getReferencesTo(func.getEntryPoint())
                ref_list = []
                if hasattr(refs, '__iter__'):
                    for ref in refs:
                        ref_list.append(str(ref.getFromAddress()))
                        if len(ref_list) >= 20:
                            break
                report["dangerous_calls"].append({
                    "name": name,
                    "address": str(func.getEntryPoint()),
                    "size": size,
                    "caller_count": len(ref_list),
                    "sample_callers": ref_list[:10],
                })
            except:
                report["dangerous_calls"].append({
                    "name": name,
                    "address": str(func.getEntryPoint()),
                    "size": size,
                })

    # ===== 4. Find large functions (likely main parsers) =====
    func_iter4 = fm.getFunctions(True)
    while func_iter4.hasNext():
        func = func_iter4.next()
        name = func.getName()
        body = func.getBody()
        size = body.getNumAddresses() if body else 0

        if size > 200:
            report["large_functions"].append({
                "name": name,
                "address": str(func.getEntryPoint()),
                "size": size,
            })

    report["large_functions"].sort(key=lambda x: x["size"], reverse=True)

    # ===== 5. Find format strings with untrusted input =====
    string_iter = listing.getDefinedData(True)
    count = 0
    while string_iter.hasNext() and count < 100000:
        data = string_iter.next()
        if data.hasStringValue():
            val = data.getDefaultValueRepresentation()
            val_clean = val.strip('"').strip("'")
            val_lower = val_clean.lower()

            if any(kw in val_lower for kw in [
                "gif", "webp", "mp4", "frame", "image", "buffer",
                "overflow", "size", "length", "offset", "chunk",
                "error", "fail", "invalid", "corrupt", "malformed",
                "lzw", "decompress", "decode", "parse",
                "malloc", "alloc", "free",
                "memcpy", "strcpy", "integer overflow",
                "checksum", "stream", "archive", "superpack",
            ]):
                report["format_strings"].append({
                    "address": str(data.getAddress()),
                    "value": val_clean[:300],
                })
        count += 1

    # ===== 6. Find buffer-related patterns =====
    func_iter5 = fm.getFunctions(True)
    while func_iter5.hasNext():
        func = func_iter5.next()
        name = func.getName()
        body = func.getBody()
        size = body.getNumAddresses() if body else 0

        # Look for functions that take size parameters and call malloc/calloc
        if size > 100 and ("alloc" in name.lower() or "buffer" in name.lower() or
                           "read" in name.lower() or "parse" in name.lower() or
                           "decompress" in name.lower()):
            report["buffer_vulns"].append({
                "name": name,
                "address": str(func.getEntryPoint()),
                "size": size,
                "signature": str(func.getSignature()),
            })

    with open(OUTPUT, 'w') as f:
        json.dump(report, f, indent=2)

    print("\n" + "="*60)
    print("RCE ANALYSIS REPORT: %s" % currentProgram.getName())
    print("="*60)
    print("Total functions: %d" % fm.getFunctionCount())
    print("JNI entry points: %d" % len(report["jni_entry_points"]))
    print("GIF functions: %d" % len(report["gif_functions"]))
    print("WebP functions: %d" % len(report["webp_functions"]))
    print("MP4 functions: %d" % len(report["mp4_functions"]))
    print("Dangerous call sites: %d" % len(report["dangerous_calls"]))
    print("Large functions (>200 bytes): %d" % len(report["large_functions"]))
    print("Format strings: %d" % len(report["format_strings"]))
    print("Buffer-related functions: %d" % len(report["buffer_vulns"]))

    print("\n=== JNI ENTRY POINTS ===")
    for j in report["jni_entry_points"]:
        print("  [%s] %s (size=%s)" % (j.get("address", "?"), j["name"], j.get("size", "?")))

    print("\n=== GIF FUNCTIONS ===")
    for g in report["gif_functions"]:
        print("  [%s] %s (size=%d)" % (g["address"], g["name"], g["size"]))

    print("\n=== WebP FUNCTIONS ===")
    for w in report["webp_functions"]:
        print("  [%s] %s (size=%d)" % (w["address"], w["name"], w["size"]))

    print("\n=== MP4 FUNCTIONS ===")
    for m in report["mp4_functions"]:
        print("  [%s] %s (size=%d)" % (m["address"], m["name"], m["size"]))

    print("\n=== TOP 20 DANGEROUS CALLS ===")
    sorted_danger = sorted(report["dangerous_calls"], key=lambda x: x.get("caller_count", 0), reverse=True)
    for d in sorted_danger[:20]:
        print("  [%s] %s - called by %d functions" % (d["address"], d["name"], d.get("caller_count", 0)))

    print("\n=== TOP 30 LARGEST FUNCTIONS ===")
    for l in report["large_functions"][:30]:
        print("  [%s] %s (size=%d)" % (l["address"], l["name"], l["size"]))

    print("\n=== BUFFER-RELATED FUNCTIONS ===")
    for b in report["buffer_vulns"][:20]:
        print("  [%s] %s (size=%d) %s" % (b["address"], b["name"], b["size"], b.get("signature", "")))

    print("\n=== SUSPICIOUS FORMAT STRINGS (first 30) ===")
    for s in report["format_strings"][:30]:
        print("  [%s] %s" % (s["address"], s["value"]))

    print("\n[+] Report written to: %s" % OUTPUT)

run()
