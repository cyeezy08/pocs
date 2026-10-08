# Ghidra script: Analyze decompress_from_so and related functions
import json

OUTPUT = "/home/kali/2stage/analysis/ghidra/decompress_analysis.json"

def run():
    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()
    mem = currentProgram.getMemory()

    report = {
        "program": currentProgram.getName(),
        "decompress_functions": [],
        "all_strings": []
    }

    # Find decompress-related functions
    decompress_names = [
        "decompress_from_so", "decompress_range_from_so",
        "decompress", "decompress_legacy", "decompress_with_format",
        "decompress_with_ref", "decompress_range",
        "openObArchiveBytesNative", "openInputStreamNative",
        "openObArchive", "init_archive", "read_header",
        "read_checkpoint", "read_stream_header"
    ]

    func_iter = fm.getFunctions(True)
    while func_iter.hasNext():
        func = func_iter.next()
        name = func.getName()
        name_lower = name.lower()

        if any(kw in name_lower for kw in decompress_names):
            # Get function body as bytes
            body = func.getBody()
            start = body.getMinAddress().getOffset()
            end = body.getMaxAddress().getOffset()
            size = end - start

            # Read the function bytes
            func_bytes = bytearray()
            addr = body.getMinAddress()
            while addr.getOffset() <= end:
                b = mem.getByte(addr)
                func_bytes.append(b & 0xFF)
                addr = addr.add(1)

            # Look for string references
            refs = []
            for ref in getReferencesTo(func.getEntryPoint()):
                refs.append(str(ref.getFromAddress()))

            entry = {
                "name": name,
                "address": str(func.getEntryPoint()),
                "size": size,
                "signature": str(func.getSignature()),
                "param_count": func.getParameterCount(),
                "first_bytes": ' '.join('%02x' % b for b in func_bytes[:64]),
                "callers": refs
            }
            report["decompress_functions"].append(entry)

            print("\n=== %s @ %s (size=%d) ===" % (name, func.getEntryPoint(), size))
            print("  Signature: %s" % func.getSignature())
            print("  First 32 bytes: %s" % ' '.join('%02x' % b for b in func_bytes[:32]))
            print("  Callers: %s" % refs)

    # Get all strings related to archive format
    string_iter = listing.getDefinedData(True)
    count = 0
    while string_iter.hasNext() and count < 10000:
        data = string_iter.next()
        if data.hasStringValue():
            val = data.getDefaultValueRepresentation()
            val_clean = val.strip('"').strip("'")
            val_lower = val_clean.lower()
            if any(kw in val_lower for kw in ['archive', 'header', 'stream', 'checkpoint',
                                                 'format', 'version', 'magic', 'compress',
                                                 'decompress', 'superpack', 'ob ', 'obh']):
                report["all_strings"].append({
                    "address": str(data.getAddress()),
                    "value": val_clean[:300]
                })
        count += 1

    with open(OUTPUT, 'w') as f:
        json.dump(report, f, indent=2)

    print("\n[+] Report: %s" % OUTPUT)
    print("[+] Decompress functions: %d" % len(report["decompress_functions"]))
    print("[+] Format strings: %d" % len(report["all_strings"]))

    print("\n=== ALL FORMAT STRINGS ===")
    for s in report["all_strings"]:
        print("  [%s] %s" % (s['address'], s['value']))

run()
