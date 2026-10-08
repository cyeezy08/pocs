# Leviathan LVX - Toolchain

Private. Authorized research only.

The working toolkit behind the Leviathan research: passive exposure measurement,
firmware reverse-engineering, and a threat-intel bot.

```
shodan/     passive exposure measurement (Shodan)
fw/         firmware extraction + ARM/Thumb/aarch64 reverse engineering
intel-bot/  Leviathan Telegram bot (keyless sources)
```

---

## shodan/ - passive exposure measurement

Reads Shodan's index. Does not resolve, connect to, or scan any host. The scan
API is deliberately not implemented anywhere in this tree.

| File | Purpose |
|---|---|
| `shodan_engine.py` | Corrected crawl engine. Throttles **per page**, not per result |
| `fleet_census.py` | Facet-first version census: what firmware builds are actually deployed |
| `shodan_tui.py` | Original TUI (curses). See the pacing note below |
| `hunt_unpatched.py` | NVD triage: CVEs with a public PoC but no vendor advisory |
| `cstecgi_map.py` | Vendor map for the Realtek cstecgi dispatcher |
| `cstecgi_targets.py` | Candidate rebadges with no cstecgi CVE naming them |

### The pacing bug, and why it matters

`shodan_tui.py` sleeps **1.0s per result**:

```python
for b in api.search_cursor(query):
    if non_blocking_sleep(std, 1.0):   # per result
```

Shodan's limit is **1 request/second**, and one request returns a whole page of
100 results. Sleeping per result waits ~100x longer than needed:

| Pacing | 10,000 results |
|---|---|
| per result (TUI) | ~2.8 hours |
| per page (`shodan_engine.py`) | ~110 seconds |

`shodan_engine.py` pages manually so the throttle sits on the page boundary -
`search_cursor` hides that boundary, which is exactly how the sleep ended up in
the wrong loop.

### The credit model (not a bypass)

From Shodan's developer book:

> 1 query credit is deducted per **100 pages** of search results.

One page = 100 results, so **1 credit ≈ 10,000 results**. `search_cursor` is
Shodan's own documented method. Nothing in this tree evades a limit; the method
is simply to page rather than to fetch one at a time.

---

## fw/ - firmware extraction and reverse engineering

The chain that turns a vendor `.bin` into a readable binary, then finds the
sinks inside it. Built against Dahua and Tenda images.

### Extraction

| File | Purpose |
|---|---|
| `findsqfs.py` | Locate a squashfs inside a container, validate the superblock |
| `carve.py` | Carve an embedded filesystem out of a larger image |
| `diff_builds.py` | Separate real content changes from opkg metadata noise |

The general chain, which differs per vendor:

```
.bin
  -> gzip -dc            (magic is often at offset 0)
  -> tar xf              (the payload is frequently a tar)
  -> root.squashfs       (which may be a UBI image, not squashfs!)
  -> ubireader_extract_images
  -> unsquashfs
```

Two traps that each produced a wrong answer first: a scanner that only looks for
`hsqs` reports "no filesystem" when the payload is a tar, and `root.squashfs`
being a UBI image makes `unsquashfs` fail with a superblock error.

### Call-site analysis

| File | Purpose |
|---|---|
| `callsite_truth.sh` | Call-site census via `arm-linux-gnueabi-objdump` (ground truth) |
| `exec_census.sh` | Census of process-exec primitives |
| `classify_system.py` | Classify `system()` sites by how the argument is built |
| `sonia_system.py` / `sonia_formats.py` | Resolve `system()` sites and their format strings |
| `sonia_other.py` | `popen` / `execl` / `execvp` / `PDI_systemCmd` sites |
| `sonia_callerwalk.py` | Two-level caller walk (working) |
| `sonia_vtables.py` | RTTI/vtable recovery |
| `sonia_indirect.py` | Vtable / init_array / pointer-table reachability |
| `pdi_family.py` | Sweep a symbol family for the same sink pattern |
| `dahua_reach.py` | Reachability across every ELF in a rootfs |

### Hard-won facts, so they don't have to be rediscovered

**objdump needs the right architecture.** The host `objdump` has no ARM
support. Install `binutils-arm-linux-gnueabi` and
`binutils-aarch64-linux-gnu`, and disassemble with those.

**Match `blx`, not just `bl`.** Thumb interworking uses `blx`. A search for
`bl` alone returns zero and looks like a clean negative.

**Thumb symbol values carry bit 0.** `0x83331` is a function at `0x83330`. Mask
with `~1` before using an address as a range start.

**objdump prints variable-width addresses.** `   83330:` is 5 hex digits while
later sections print 8, so a `{6,8}` regex silently skips every low-address
function.

**`readelf` column indices:** `Num: Value Size Type Bind Vis Ndx Name` -
visibility is index 5, not 6 (6 is Ndx). Testing the wrong one matches nothing.

**The `.rel.plt` row carries an `AI` flags field** that shifts the
address/offset/size columns, breaking any fixed-column parser.

**Branch targets are function ENTRIES, not call sites.** Matching branches
against the address of a `system()` call can never succeed; the caller branches
to the function's entry.

**Prologue detection is unreliable on ARM.** ARM data regions sit adjacent to
code and produce false prologues. Derive an entry as the nearest preceding
address that some branch in the file targets - that yields entries with real
incoming branches where prologue-derived ones had none.

**Vtable offset is not the Itanium `-8`.** Measured on a Dahua build:
`typeinfo_object + 60` recovers 826 vtables / 9,411 virtual functions, where
`-8` recovers 88. Sweep the offset, don't assume it.

**Mangled-name regexes need `(C|I)\w+`, not `(C|I)\d+\w+`.** Dahua nests
scopes, so `N5Dahua7Manager8IConsoleE` has letters after `I` before any digit.
The strict form matched 53 of 4,318 names.

**`-fPIC` with GOT-relative addressing means no static string xref exists.**
A binary with 176k relocations references rodata strings by computed offset, so
`ldr`-from-literal-pool scans find nothing. Verify with a control before
concluding a string is unreferenced.

### The rule this tree was built on

**A scanner reporting zero has the same failure shape as a test that cannot
fail.** Every script here requires a known-positive control (`malloc`,
`sprintf`, a PLT stub with a known call count) to return non-zero before any
negative result is believed. Six separate tools in this tree returned confident
zeroes that were entirely artifacts of a broken scanner. Without controls, all
six would have been written up as findings.

---

## intel-bot/ - Leviathan

Threat-intel Telegram bot. Buttons for IP enrich, CVE intel, vendor KEV sweep,
hash lookup, exploit stream, and an AI analyst.

**Keyless by design.** InternetDB, NVD, EPSS, CISA KEV and Exploit-DB need no
API key, so the bot scales without riding one academic Shodan key that could be
revoked. Shodan search is optional.

The headline button is **CVE Intel**: NVD severity + EPSS probability + CISA KEV
in one call, with an exploitation verdict. A CVSS score says how bad something
*would* be; these three together say how bad it *is*.

```
export TELEGRAM_BOT_TOKEN='...'
export BOT_ALLOWED_USERS='123'     # optional; omit = open
python3 bot.py
```

Stdlib only. No pip installs.

---

## Scope

Everything here is passive or offline:

- `shodan/` reads an index. No host is contacted.
- `fw/` analyzes firmware files. No device is contacted.
- `intel-bot/` reads public feeds.

No credential, token or key is stored in this repository.

Leviathan Offsec - private.
