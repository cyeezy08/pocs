"""Telegram mirror: send each posted tweet to a TG channel/chat as backup feed."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request

from . import config


def send_message(text: str, post=None) -> dict:
    token = os.environ.get(config.ENV_TG_TOKEN, "")
    chat = os.environ.get(config.ENV_TG_CHAT, "")
    if not token or not chat:
        raise MirrorError("set HUG_TG_TOKEN and HUG_TG_CHAT to mirror posts")
    url = config.TG_SEND_URL.format(token=token)
    data = urllib.parse.urlencode(
        {"chat_id": chat, "text": text, "disable_web_page_preview": "false"}
    ).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    do_post = post or urllib.request.urlopen
    try:
        with do_post(req, timeout=30) as resp:  # type: ignore[operator]
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise MirrorError(f"telegram HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:200]}") from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise MirrorError(f"network error: {e}") from e
    if not payload.get("ok"):
        raise MirrorError(f"telegram rejected: {str(payload)[:200]}")
    return payload


class MirrorError(RuntimeError):
    pass
