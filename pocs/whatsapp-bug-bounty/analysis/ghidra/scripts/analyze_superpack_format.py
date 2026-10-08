# Ghidra script: Deep analysis of libsuperpack.so decompression logic
import json

OUTPUT = "/home/kali/2stage/analysis/ghidra/superpack_analysis.json"

def run():
    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()
    mem = currentProgram.getMemory()
    
    report = {
        "program": currentProgram.getName(),
        "total_functions": fm.getFunctionCount(),
        "key_functions": [],
        "all_functions": [],
        "data_sections": [],
        "interesting_strings": []
    }
    
    # Get the main decompress and archive functions
    key_names = [
        "decompress", "archive", "stream", "unpack", "load",
        "init", "create", "open", "read", "write", "decode",
        "inflate", "deflate", "zstd", "lz4", "zlib"
    ]
    
    func_iter = fm.getFunctions(True)
    while func_iter.hasNext():
        func = func_iter.next()
        name = func.getName()
        name_lower = name.lower()
        
        entry = {
            "name": name,
            "address": str(func.getEntryPoint()),
            "signature": str(func.getSignature()),
            "param_count": func.getParameterCount(),
            "body_size": func.getBody().getNumAddresses() if func.getBody() else 0,
            "is_key": any(kw in name_lower for kw in key_names)
        }
        
        report["all_functions"].append(entry)
        if entry["is_key"]:
            report["key_functions"].append(entry)
    
    # Get all defined strings
    string_iter = listing.getDefinedData(True)
    count = 0
    while string_iter.hasNext() and count < 10000:
        data = string_iter.next()
        if data.hasStringValue():
            val = data.getDefaultValueRepresentation()
            val_clean = val.strip('"').strip("'")
            report["interesting_strings"].append({
                "address": str(data.getAddress()),
                "value": val_clean[:300]
            })
        count += 1
    
    # Get memory blocks
    for block in mem.getBlocks():
        report["data_sections"].append({
            "name": block.getName(),
            "start": str(block.getStart()),
            "size": block.getSize(),
            "type": str(block.getType()),
            "readable": block.isRead(),
            "executable": block.isExecute()
        })
    
    with open(OUTPUT, 'w') as f:
        json.dump(report, f, indent=2)
    
    print("[+] Report: %s" % OUTPUT)
    print("[+] Total functions: %d" % fm.getFunctionCount())
    print("[+] Key functions: %d" % len(report["key_functions"]))
    print("[+] Strings: %d" % len(report["interesting_strings"]))
    print("[+] Sections: %d" % len(report["data_sections"]))
    
    print("\n=== KEY FUNCTIONS ===")
    for f in report["key_functions"]:
        print("  %s @ %s (params=%d, size=%d)" % (f['name'], f['address'], f['param_count'], f['body_size']))
    
    print("\n=== ARCHIVE/DECOMPRESS STRINGS ===")
    for s in report["interesting_strings"]:
        v = s['value'].lower()
        if any(kw in v for kw in ['archive', 'decompress', 'stream', 'unpack', 'corrupt', 'error', 'superpack']):
            print("  [%s] %s" % (s['address'], s['value']))

run()
