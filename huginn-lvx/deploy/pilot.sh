#!/bin/sh
# Huginn pilot - one fetch -> draft -> post cycle, run by the systemd timer.
# The post step is a DRY RUN unless HUG_AUTOPILOT=1 in /opt/huginn/.env.
# Dry-run previews land in the journal: journalctl -u huginn-pilot
set -u
BIN=/opt/huginn/venv/bin/huginn

"$BIN" fetch || true   # 1 = nothing new (fine), 2 = API down (next run retries)
"$BIN" draft || true   # 1 = nothing new to draft (fine)

if [ "${HUG_AUTOPILOT:-0}" = "1" ]; then
    "$BIN" post --yes  # real send - the only place this box touches X writes
else
    "$BIN" post        # dry run: prints the exact tweet + weighted length
fi
rc=$?
# 1 = nothing to post - healthy, keep the unit green; 0 = posted; 2 = real error
[ "$rc" -eq 1 ] && exit 0
exit "$rc"
