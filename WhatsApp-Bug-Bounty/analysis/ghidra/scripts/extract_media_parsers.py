# Ghidra headless script: Extract media parser functions from libs.so

import json

OUTPUT = "/home/kali/2stage/analysis/ghidra/media_parser_report.json"

def run():
    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()
    
    report = {
        "program": currentProgram.getName(),
        "language": str(currentProgram.getLanguageID()),
        "image_base": str(currentProgram.getImageBase()),
        "total_functions": fm.getFunctionCount(),
        "media_related": [],
        "all_exports": [],
        "string_references": []
    }
    
    media_keywords = [
        "gif", "webp", "mp4", "video", "image", "media", "decode", "encode",
        "parse", "read", "buffer", "frame", "pixel", "color", "compress",
        "decompress", "stream", "demux", "mux", "codec", "av1", "hevc",
        "h264", "h265", "opus", "aac", "flac", "ogg", "wav", "pcm",
        "superpack", "unpack", "dlopen", "mmap", "mprotect", "dlsym",
        "asset", "loader", "native", "jni"
    ]
    
    func_iter = fm.getFunctions(True)
    while func_iter.hasNext():
        func = func_iter.next()
        name = func.getName()
        name_lower = name.lower()
        is_media = any(kw in name_lower for kw in media_keywords)
        
        entry = {
            "name": name,
            "address": str(func.getEntryPoint()),
            "signature": str(func.getSignature()),
            "param_count": func.getParameterCount(),
            "body_size": func.getBody().getNumAddresses() if func.getBody() else 0,
        }
        
        if is_media:
            report["media_related"].append(entry)
        
        # Check for exports via symbol table
        st = currentProgram.getSymbolTable()
        syms = st.getSymbols(func.getEntryPoint())
        for sym in syms:
            if sym.isExternalEntryPoint():
                report["all_exports"].append(entry)
                break
    
    # Scan strings
    string_iter = listing.getDefinedData(True)
    count = 0
    while string_iter.hasNext() and count < 50000:
        data = string_iter.next()
        if data.hasStringValue():
            val = data.getDefaultValueRepresentation()
            val_clean = val.strip('"').strip("'")
            val_lower = val_clean.lower()
            if any(kw in val_lower for kw in media_keywords):
                report["string_references"].append({
                    "address": str(data.getAddress()),
                    "value": val_clean[:200]
                })
        count += 1
    
    with open(OUTPUT, 'w') as f:
        json.dump(report, f, indent=2)
    
    print("[+] Report: %s" % OUTPUT)
    print("[+] Functions: %d total, %d media-related, %d exports" % (
        fm.getFunctionCount(), len(report["media_related"]), len(report["all_exports"])))
    print("[+] Media strings: %d" % len(report["string_references"]))

run()
