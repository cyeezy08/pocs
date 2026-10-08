#!/usr/bin/env bash
# Call-site census for every process-spawning import in sonia.
#
# The PDI wrapper (PDI_systemCmd) has 2 call sites, but sonia also imports
# system/popen/execl/execvp straight from libc. Those are more likely to sit
# in HTTP request handling, so they are the better reachability candidates.
set -uo pipefail

ASM=/tmp/sonia.asm

count() { grep -cE "[[:space:]](bl|blx|b|bx)[[:space:]]+[0-9a-f]+ <$1@plt" "$ASM"; }

echo "=== control ==="
for s in malloc free memcpy memset; do
    printf "  %-16s %5s\n" "$s" "$(count "$s")"
done

echo
echo "=== process execution primitives ==="
for s in system popen execl execvp execlp execvpe fork posix_spawn; do
    printf "  %-16s %5s\n" "$s" "$(count "$s")"
done

echo
echo "=== PDI wrappers ==="
for s in PDI_systemCmd run_sys NetSetDNSHostName; do
    printf "  %-20s %5s\n" "$s" "$(count "$s")"
done