"""Static, responsive HTML dashboard. No backend required."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _kv_table(data: dict[str, Any]) -> str:
    rows = "".join(
        f"<tr><th>{_esc(k)}</th><td><code>{_esc(v)}</code></td></tr>"
        for k, v in (data or {}).items() if v is not None
    )
    return f"<table>{rows}</table>" if rows else "<p class='muted'>No data collected.</p>"


def _list_table(headers: list[str], rows: list[list[Any]]) -> str:
    head = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td><code>{_esc(c)}</code></td>" for c in row) + "</tr>"
        for row in rows[:400]
    )
    if not body:
        return "<p class='muted'>No data collected.</p>"
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _section(section_id: str, title: str, body: str) -> str:
    return (
        f'<section id="{section_id}" class="card">'
        f'<h2><button class="collapse" aria-expanded="true">{_esc(title)}</button></h2>'
        f'<div class="content">{body}</div></section>'
    )


def write(scan_data: dict[str, Any], target: str, scope: dict, path: str) -> str:
    bd = scan_data.get("bangladesh") or {}
    dns = scan_data.get("dns") or {}
    rdap = scan_data.get("rdap") or {}
    certs = scan_data.get("certificates") or {}
    subs = (scan_data.get("subdomains") or {}).get("subdomains", [])
    http_data = scan_data.get("http") or {}
    tls = scan_data.get("tls") or {}
    techs = scan_data.get("technologies") or []
    sechdrs = scan_data.get("security_headers") or {}
    wayback = scan_data.get("wayback") or {}
    rels = scan_data.get("relationships") or []
    findings = scan_data.get("findings", [])

    findings_rows = []
    for f in findings:
        d = f.to_dict() if hasattr(f, "to_dict") else f
        findings_rows.append([d.get("severity"), d.get("title"), d.get("category"),
                              d.get("confidence"), d.get("status"), d.get("evidence")])
    sev_badge = lambda s: f"<span class='badge sev-{_esc(s).lower()}'>{_esc(s)}</span>"
    dns_rows = [[rt, v] for rt in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")
                for v in dns.get(rt, [])]

    sections = [
        _section("overview", "Overview", _kv_table({
            "Target": target, "Profile": scan_data.get("profile"),
            "Timestamp": scan_data.get("timestamp"),
            "Jurisdiction": "Bangladesh" if bd.get("is_bd") else "Other",
            "TLD": bd.get("tld") or "n/a", "Category": bd.get("category") or "n/a",
            "Subdomains discovered": len(subs),
            "Certificates found": len(certs.get("certificates", [])),
            "Findings": len(findings),
        })),
        _section("scope", "Scope", _kv_table(scope)),
        _section("dns", "DNS", _list_table(["Type", "Value"], dns_rows) +
                 f"<p class='muted'>DNSSEC: {_esc(dns.get('dnssec', 'unknown'))}</p>"),
        _section("rdap", "RDAP", _kv_table(rdap)),
        _section("subdomains", "Subdomains",
                 _list_table(["Subdomain", "Classification"],
                             [[s["subdomain"], s["classification"]] for s in subs])
                 + "<p class='muted'>Classifications are descriptive only — never vulnerability indicators.</p>"),
        _section("certificates", "Certificates",
                 _list_table(["ID", "Issuer", "Names", "First seen"],
                             [[c.get("id"), c.get("issuer"), " ".join(c.get("names", [])[:5]),
                               c.get("first_seen")] for c in certs.get("certificates", [])[:100]])),
        _section("tls", "TLS", _kv_table({k: v for k, v in tls.items() if k != "san"})
                 + f"<p><b>SAN:</b> {_esc(', '.join(tls.get('san', [])[:20]))}</p>"),
        _section("http", "HTTP Metadata", _kv_table(http_data)),
        _section("tech", "Technologies",
                 _list_table(["Technology", "Confidence", "Version", "Evidence"],
                             [[t.get("technology"), t.get("confidence"),
                               t.get("version") or "not observed",
                               "; ".join(t.get("evidence", []))] for t in techs])),
        _section("headers", "Security Headers",
                 _list_table(["Header", "Present", "Value"],
                             [[h, "yes" if v.get("present") else "no", v.get("value") or "—"]
                              for h, v in sechdrs.items()])
                 + "<p class='muted'>Missing headers are informational observations, not automatic vulnerabilities.</p>"),
        _section("wayback", "Historical URLs",
                 _list_table(["URL", "Timestamp", "Status", "Category"],
                             [[e.get("url"), e.get("timestamp"), e.get("status"), e.get("category")]
                              for e in (wayback.get("interesting") or wayback.get("urls", []))[:150]])),
        _section("relationships", "Relationships",
                 _list_table(["Source", "Relationship", "Target"],
                             [[r["source"], r["relationship"], r["target"]] for r in rels[:200]])),
        _section("findings", "Findings",
                 "<table><thead><tr><th>Severity</th><th>Title</th><th>Category</th>"
                 "<th>Confidence</th><th>Status</th><th>Evidence</th></tr></thead><tbody>"
                 + "".join(
                     f"<tr><td>{sev_badge(r[0])}</td><td>{_esc(r[1])}</td><td>{_esc(r[2])}</td>"
                     f"<td>{_esc(r[3])}</td><td>{_esc(r[4])}</td><td><code>{_esc(r[5])}</code></td></tr>"
                     for r in findings_rows)
                 + "</tbody></table>"),
        _section("evidence", "Raw Evidence",
                 f"<pre>{_esc(json.dumps(scan_data, indent=2, ensure_ascii=False, default=str)[:80000])}</pre>"),
    ]

    page = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BD-OSINT Report — {_esc(target)}</title>
<style>
:root{{--bg:#0f1420;--card:#171e2e;--fg:#e6eaf2;--muted:#8b94a8;--accent:#3b82f6}}
*{{box-sizing:border-box}}body{{margin:0;font:15px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg)}}
header{{padding:24px 16px;background:linear-gradient(135deg,#101828,#1d2a44)}}
header h1{{margin:0;font-size:1.4em}}header p{{color:var(--muted);margin:4px 0 0}}
#controls{{position:sticky;top:0;background:var(--bg);padding:10px 16px;display:flex;gap:8px;flex-wrap:wrap;z-index:5}}
#search{{flex:1;min-width:200px;padding:8px 12px;border-radius:8px;border:1px solid #2a3550;background:#0c1018;color:var(--fg)}}
main{{padding:16px;max-width:1100px;margin:auto}}
.card{{background:var(--card);border-radius:12px;margin:12px 0;overflow:hidden}}
.card h2{{margin:0}}.collapse{{width:100%;background:none;border:0;color:var(--fg);padding:14px 18px;font-size:1.05em;text-align:left;cursor:pointer}}
.collapse::before{{content:"▾ ";color:var(--accent)}}.collapse[aria-expanded="false"]::before{{content:"▸ "}}
.content{{padding:0 18px 16px}}table{{width:100%;border-collapse:collapse;font-size:.9em}}
th,td{{padding:6px 10px;border-bottom:1px solid #25304a;text-align:left;word-break:break-all}}
th{{color:var(--muted)}}code{{background:#0c1018;padding:1px 5px;border-radius:4px;font-size:.9em}}
.muted{{color:var(--muted);font-size:.9em}}pre{{overflow:auto;background:#0c1018;padding:12px;border-radius:8px;font-size:.8em}}
.badge{{padding:2px 8px;border-radius:10px;font-size:.8em}}
.sev-info{{background:#1e3a5f}}.sev-low{{background:#3a4d1e}}.sev-medium{{background:#5f4a1e}}.sev-high{{background:#5f1e1e}}
@media(max-width:600px){{.content{{padding:0 10px 12px}}table{{font-size:.8em}}}}
</style></head><body>
<header><h1>BD-OSINT v3 Report</h1><p>Target: {_esc(target)} — passive reconnaissance, authorized use only</p></header>
<div id="controls"><input id="search" placeholder="Search report… (filters rows and sections)"></div>
<main>{''.join(sections)}</main>
<script>
document.querySelectorAll('.collapse').forEach(b=>b.addEventListener('click',()=>{{
 const c=b.closest('.card').querySelector('.content');
 const open=b.getAttribute('aria-expanded')==='true';
 b.setAttribute('aria-expanded',String(!open));c.style.display=open?'none':'block';}}));
document.getElementById('search').addEventListener('input',e=>{{
 const q=e.target.value.toLowerCase();
 document.querySelectorAll('.card').forEach(card=>{{
  let visible=0;
  card.querySelectorAll('tbody tr').forEach(tr=>{{
   const hit=tr.textContent.toLowerCase().includes(q);
   tr.style.display=hit?'':'none'; if(hit)visible++;}});
  if(!card.querySelector('tbody')) visible=card.textContent.toLowerCase().includes(q)?1:0;
  card.style.display=(q===''||visible>0)?'':'none';}});
}});
</script></body></html>"""

    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(page, encoding="utf-8")
    return str(out)
