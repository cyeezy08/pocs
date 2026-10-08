# Deep disassembly of libgifimage.so key functions

import json

OUTPUT = "/home/kali/2stage/analysis/ghidra/gif_deep_analysis.json"

def run():
    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()
    mem = currentProgram.getMemory()

    report = {
        "program": currentProgram.getName(),
        "functions": [],
        "all_strings": [],
        "xrefs_to_malloc": [],
        "xrefs_to_memcpy": [],
        "xrefs_to_free": [],
    }

    # Get all functions with their body bytes
    func_iter = fm.getFunctions(True)
    while func_iter.hasNext():
        func = func_iter.next()
        name = func.getName()
        body = func.getBody()
        start = body.getMinAddress()
        end = body.getMaxAddress()
        size = body.getNumAddresses() if body else 0

        if size < 20:
            continue

        # Read function bytes
        func_bytes = bytearray()
        addr = start
        while addr.getOffset() <= end.getOffset():
            b = mem.getByte(addr)
            func_bytes.append(b & 0xFF)
            addr = addr.add(1)

        # Get references to this function
        callers = []
        try:
            refs = getReferencesTo(func.getEntryPoint())
            if hasattr(refs, '__iter__'):
                for ref in refs:
                    callers.append(str(ref.getFromAddress()))
        except:
            pass

        # Check for string references within the function
        str_refs = []
        try:
            ref_iter = listing.getReferenceIterator(start)
            while ref_iter.hasNext():
                ref = ref_iter.next()
                if ref.getToAddress().getOffset() <= end.getOffset():
                    continue
                # Check if reference points to a string
                data = listing.getDataAt(ref.getToAddress())
                if data and data.hasStringValue():
                    str_refs.append({
                        "addr": str(ref.getToAddress()),
                        "value": data.getDefaultValueRepresentation()[:200],
                        "ref_type": str(ref.getReferenceType()),
                    })
        except:
            pass

        # Check for dangerous patterns in the assembly
        func_hex = ''.join('%02x' % b for b in func_bytes)
        patterns = []
        if "94000000" in func_hex:  # bl (function call)
            call_count = func_hex.count("94000000")
            patterns.append("calls: %d" % call_count)
        if "a9" in func_hex[0:4]:  # stp (stack push)
            patterns.append("stack_frame_setup")
        if "f94000" in func_hex:  # ldr from memory
            patterns.append("memory_load")

        entry = {
            "name": name,
            "address": str(start),
            "size": size,
            "callers": callers,
            "string_refs": str_refs,
            "patterns": patterns,
            "first_bytes": ' '.join('%02x' % b for b in func_bytes[:32]),
        }
        report["functions"].append(entry)

    # Get ALL strings
    string_iter = listing.getDefinedData(True)
    count = 0
    while string_iter.hasNext() and count < 50000:
        data = string_iter.next()
        if data.hasStringValue():
            val = data.getDefaultValueRepresentation()
            report["all_strings"].append({
                "address": str(data.getAddress()),
                "value": val.strip('"').strip("'")[:300],
            })
        count += 1

    # Sort functions by size
    report["functions"].sort(key=lambda x: x["size"], reverse=True)

    with open(OUTPUT, 'w') as f:
        json.dump(report, f, indent=2)

    print("=" * 60)
    print("DEEP ANALYSIS: %s" % currentProgram.getName())
    print("=" * 60)
    print("Total functions analyzed: %d" % len(report["functions"]))
    print("Total strings: %d" % len(report["all_strings"]))

    print("\n=== TOP 15 LARGEST FUNCTIONS (potential main parsers) ===")
    for func in report["functions"][:15]:
        print("\n  [%s] %s (size=%d)" % (func["address"], func["name"], func["size"]))
        print("    First bytes: %s" % func["first_bytes"])
        if func["callers"]:
            print("    Called from: %s" % ', '.join(func["callers"][:3]))
        if func["string_refs"]:
            print("    String refs:")
            for s in func["string_refs"][:5]:
                print("      [%s] %s (%s)" % (s["addr"], s["value"], s["ref_type"]))

    print("\n=== ALL STRINGS ===")
    for s in report["all_strings"]:
        print("  [%s] %s" % (s["address"], s["value"]))

    print("\n[+] Report: %s" % OUTPUT)

run()
