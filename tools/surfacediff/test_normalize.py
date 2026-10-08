from surfacediff.normalize import parse_line, parse_stream

HTTPX_LINE = ('{"timestamp":"2026-09-16T01:00:00Z","url":"https://vpn.example.com",'
              '"status_code":200,"title":"SSL VPN","webserver":"nginx","tech":["nginx"],'
              '"cdn":"Cloudflare","asn":"AS12345"}')
NAABU_LINE = '{"host":"vpn.example.com","ip":"1.2.3.4","port":8443,"protocol":"tcp"}'


def test_subfinder_line_becomes_host():
    a, warn = parse_line("vpn.example.com")
    assert warn is None and a.kind == "host" and a.key == "host|vpn.example.com"


def test_url_line_becomes_url():
    a, _ = parse_line("https://Example.com/app/")
    assert a.key == "url|https://example.com/app"


def test_ip_line_becomes_host():
    a, _ = parse_line("192.0.2.10")
    assert a.kind == "host" and a.key == "host|192.0.2.10"


def test_httpx_json_keeps_attrs():
    a, warn = parse_line(HTTPX_LINE)
    assert warn is None
    assert a.kind == "url" and a.key == "url|https://vpn.example.com"
    assert a.attrs["status_code"] == 200 and a.attrs["webserver"] == "nginx"


def test_naabu_json_becomes_port():
    a, warn = parse_line(NAABU_LINE)
    assert warn is None
    assert a.kind == "port" and a.key == "port|vpn.example.com:tcp/8443"
    assert a.attrs["ip"] == "1.2.3.4"


def test_comments_and_blanks_skipped():
    assert parse_line("") == (None, None)
    assert parse_line("# comment") == (None, None)


def test_malformed_json_warns():
    a, warn = parse_line('{"broken":')
    assert a is None and warn and "malformed" in warn


def test_stream_dedupes_and_merges():
    text = "a.example.com\nb.example.com\na.example.com\n" + HTTPX_LINE
    assets, warnings = parse_stream(text)
    keys = {x.key for x in assets}
    assert len(keys) == 3
    assert warnings == []


def test_default_port_dropped_from_url_key():
    a, _ = parse_line("https://example.com:443/x")
    b, _ = parse_line("https://example.com/x")
    assert a.key == b.key
