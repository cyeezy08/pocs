#!/usr/bin/env bash
# Call-site count for the two PDI imports, using the correct Thumb branch mnemonic.
#
# Three wrong turns recorded here so they are not repeated:
#   1. hand-rolled Thumb BL decoder  -> 0 sites for malloc (impossible; scanner was wrong)
#   2. searched for "bl"           -> 0 sites, because sonia uses Thumb interworking "blx"
#   3. sonia is a mixed ARM/Thumb PIE, and readelf's .rel.plt row carries an AI
#      flags field that shifts the address/offset/size columns
# The correct mnemonic set is bl / blx / b / bx, and the target may be printed as
# <sym@plt> or <sym@plt+0x4> depending on Thumb bit 0.
set -uo pipefail

ASM=/tmp/sonia.asm
PLT=/tmp/sonia.plt

count() {
    local sym="$1"
    grep -cE "[[:space:]](bl|blx|b|bx)[[:space:]]+[0-9a-f]+ <${sym}@plt" "$ASM"
}

echo "=== control ==="
for s in malloc free memcpy; do
    printf "  %-10s %s call sites\n" "$s" "$(count "$s")"
done

echo
echo "=== PDI targets ==="
for s in run_sys PDI_systemCmd; do
    n=$(count "$s")
    printf "  %-20s %s call sites\n" "$s" "$n"
    if [ "$n" -gt 0 ]; then
        grep -E "[[:space:]](bl|blx|b|bx)[[:space:]]+[0-9a-f]+ <${s}@plt" "$ASM" |
            head -10 | sed 's/^/      /'
    fi
done