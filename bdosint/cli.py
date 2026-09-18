"""BD-OSINT v3 command-line interface."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Any

import bdosint
from bdosint.analysis import findings as findings_engine
from bdosint.analysis import relationships
from bdosint.analysis import subdomains as sub_analysis
from bdosint.analysis.headers import analyze as analyze_headers
from bdosint.analysis.technologies import detect as detect_technologies
from bdosint.authorized import active_checks
from bdosint.bangladesh import domain_rules
from bdosint.bangladesh import tld as bd_tld
from bdosint.config import load_config
from bdosint.core.cache import FileCache
from bdosint.core.http import HttpClient
from bdosint.logging_utils import banner, setup_logging
from bdosint.models import ModuleResult, ScanContext
from bdosint.passive import certificates, crtsh, http_metadata, rdap, securitytxt, wayback
from bdosint.passive import dns as dns_mod
from bdosint.reports import csv_report, graph as graph_mod, html_report, json_report
from bdosint.scope import Scope, validate_target_in_scope

log = setup_logging()

PASSIVE_MODULES = ("dns", "rdap", "crtsh", "wayback", "tls", "headers", "tech",
                   "securitytxt", "http", "subdomains")
AUTHORIZED_MODULES = ("ports", "axfr")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bdosint",
        description="BD-OSINT v3 — Bangladesh-focused passive OSINT and defensive recon.",
        epilog="Active scanning requires --profile authorized and documented permission.",
    )
    p.add_argument("target", help="target domain (e.g. example.com.bd)")
    p.add_argument("--profile", choices=("passive", "authorized"), default="passive")
    p.add_argument("--modules", default=None,
                   help="comma list: " + ",".join(PASSIVE_MODULES + AUTHORIZED_MODULES))
    p.add_argument("--scope-file", default=None, help="optional scope file")
    p.add_argument("--format", choices=("json", "csv", "html", "all"), default="json")
    p.add_argument("--output", default=None, help="output path (default: reports/<target>/report.<ext>)")
    p.add_argument("--delay", type=float, default=None, help="per-provider delay override (seconds)")
    p.add_argument("--timeout", type=float, default=None, help="per-request timeout (seconds)")
    p.add_argument("--no-cache", action="store_true", help="disable filesystem cache")
    p.add_argument("--shodan-key", default=None, help="OPTIONAL Shodan API key (paid, not required)")
    p.add_argument("--ports", default=None, help="ports for authorized port scan")
    p.add_argument("--graph", action="store_true", help="also write graph.json (+ graph.svg if Graphviz installed)")
    p.add_argument("--config", default=None, help="path to config.yaml")
    p.add_argument("--verbose", action="store_true")
    return p


def _run_module(name: str, fn) -> ModuleResult:
    """Run one module; a provider failure never crashes the scan."""
    log.info(f"Module: {name}")
    start = time.monotonic()
    try:
        data = fn()
        return ModuleResult(name, True, data, duration_ms=int((time.monotonic() - start) * 1000))
    except Exception as exc:  # isolation by design
        log.warning(f"Module {name} failed: {exc}")
        return ModuleResult(name, False, None, error=str(exc),
                            duration_ms=int((time.monotonic() - start) * 1000))


def run_scan(args: argparse.Namespace) -> dict[str, Any]:
    cfg = load_config(args.config)

    timeout = args.timeout if args.timeout is not None else float(cfg["general"]["timeout"])
    delay = args.delay if args.delay is not None else float(cfg["rate_limits"]["default_delay"])
    concurrency = int(cfg["general"]["concurrency"])
    cache = FileCache(root=cfg["cache"]["directory"], ttl=int(cfg["general"]["cache_ttl"]),
                      enabled=not args.no_cache)
    http = HttpClient(timeout=timeout, delay=delay, cache=cache, max_concurrency=concurrency)

    scope = Scope.from_file(args.scope_file) if args.scope_file else None
    scope = validate_target_in_scope(args.target, scope)

    bd_info = bd_tld.classify(args.target)
    policy = domain_rules.policy_for(bd_info)
    if policy["sensitive"]:
        http.rate.get("default", policy["min_delay"])
        log.warning("Sensitive BD domain (%s): conservative rates enforced.", bd_info.tld)

    if args.profile == "authorized":
        log.warning("AUTHORIZED PROFILE: you assert documented permission to actively test this target.")
    else:
        log.info("Passive profile: no active scanning will be performed.")

    ctx = ScanContext(target=args.target, profile=args.profile, timeout=timeout,
                      concurrency=concurrency, delay=delay, use_cache=not args.no_cache,
                      shodan_key=args.shodan_key)

    requested = set(args.modules.split(",")) if args.modules else None
    if requested:
        bad = requested - set(PASSIVE_MODULES) - set(AUTHORIZED_MODULES)
        if bad:
            raise SystemExit(f"Unknown modules: {', '.join(sorted(bad))}")
    active_requested = (requested or set()) & set(AUTHORIZED_MODULES)
    if active_requested and args.profile != "authorized":
        raise SystemExit("Active modules (ports/axfr) require --profile authorized.")

    modules = requested or (set(PASSIVE_MODULES) if args.profile == "passive"
                            else set(PASSIVE_MODULES) | set(AUTHORIZED_MODULES))

    results: dict[str, ModuleResult] = {}
    want = lambda m: m in modules

    if want("dns"):
        results["dns"] = _run_module("dns", lambda: dns_mod.collect(args.target, timeout))
    if want("rdap") and cfg["providers"]["rdap"]:
        results["rdap"] = _run_module("rdap", lambda: rdap.collect(args.target, http))
    if want("crtsh") and cfg["providers"]["crtsh"]:
        results["crtsh"] = _run_module("crtsh", lambda: crtsh.collect(args.target, http))
    if want("wayback") and cfg["providers"]["wayback"]:
        results["wayback"] = _run_module("wayback", lambda: wayback.collect(args.target, http))
    if want("securitytxt"):
        results["securitytxt"] = _run_module("securitytxt", lambda: securitytxt.collect(args.target, http))
    if want("tls"):
        results["tls"] = _run_module("tls", lambda: certificates.collect(args.target, timeout=timeout))

    http_data: dict[str, Any] = {}
    if want("http"):
        results["http"] = _run_module(
            "http", lambda: http_metadata.collect_http_metadata(http, f"https://{args.target}"))
        http_data = results["http"].data if results["http"].ok else {}

    # ---- analysis over collected data ----
    dns_data = results["dns"].data if results.get("dns") and results["dns"].ok else {}
    crt_data = results["crtsh"].data if results.get("crtsh") and results["crtsh"].ok else {}

    sub_result = None
    if want("subdomains"):
        shodan_subs: list[str] = []
        if ctx.shodan_key:
            from bdosint.passive import shodan_optional
            shodan_subs = shodan_optional.subdomains(args.target, ctx.shodan_key, http)
        sub_result = sub_analysis.aggregate(args.target, dns_data or {}, crt_data or {}, shodan_subs)

    techs = []
    sec_headers = {}
    if want("tech") or want("headers"):
        try:
            resp = http.session.get(f"https://{args.target}", timeout=timeout)
            if want("tech"):
                techs = detect_technologies(dict(resp.headers), resp.text)
            if want("headers"):
                sec_headers = analyze_headers(dict(resp.headers))
        except Exception as exc:
            log.warning(f"header/tech analysis failed: {exc}")

    rels = relationships.build(args.target, dns_data or {}, sub_result or {}, crt_data or {})

    authorized_results = None
    if args.profile == "authorized":
        authorized_results = active_checks.run(
            args.profile, args.target, set(AUTHORIZED_MODULES) & modules,
            args.ports or "80,443,22,21,25,53,110,143,3306,3389,8080,8443", timeout)

    scan_data: dict[str, Any] = {
        "target": args.target,
        "profile": args.profile,
        "timestamp": ctx.started_at(),
        "bangladesh": {"is_bd": bd_info.is_bd, "tld": bd_info.tld,
                       "category": bd_info.category, "sensitive": bd_info.sensitive},
        "dns": dns_data,
        "rdap": results["rdap"].data if results.get("rdap") else None,
        "certificates": crt_data,
        "subdomains": sub_result,
        "http": http_data,
        "tls": results["tls"].data if results.get("tls") else None,
        "securitytxt": results["securitytxt"].data if results.get("securitytxt") else None,
        "technologies": techs,
        "security_headers": sec_headers,
        "wayback": results["wayback"].data if results.get("wayback") else None,
        "relationships": rels,
        "authorized": authorized_results,
        "module_results": [r.to_dict() for r in results.values()],
        "findings": [],
    }

    scan_data["findings"] = findings_engine.generate(scan_data)
    return scan_data


def write_outputs(args: argparse.Namespace, scan_data: dict[str, Any], scope_dict: dict) -> list[str]:
    target = scan_data["target"].replace("*", "_")
    out_dir = Path(args.output).parent if args.output else Path("reports") / target
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[str] = []

    fmt = args.format
    base = Path(args.output) if args.output else out_dir / "report"
    if fmt in ("json", "all"):
        written.append(json_report.write(scan_data, target, scope_dict, str(base) + ".json"))
    if fmt in ("csv", "all"):
        written.append(csv_report.write(scan_data, str(out_dir / "report.csv")))
    if fmt in ("html", "all"):
        written.append(html_report.write(scan_data, target, scope_dict, str(base) + ".html"))
    if args.graph:
        written.append(graph_mod.write_json(scan_data.get("relationships", []),
                                            str(out_dir / "graph.json")))
        svg = graph_mod.write_svg(scan_data.get("relationships", []), str(out_dir / "graph.svg"))
        if svg:
            written.append(svg)
        else:
            log.info("Graphviz not installed — skipped graph.svg.")
    return written


def main(argv: list[str] | None = None) -> int:
    global log
    args = build_parser().parse_args(argv)
    log = setup_logging(verbose=args.verbose)

    print(banner())
    try:
        scan_data = run_scan(args)
    except ValueError as exc:
        log.error(str(exc))
        return 2
    except PermissionError as exc:
        log.error(str(exc))
        return 3

    scope_dict = {"target": scan_data["target"], "profile": scan_data["profile"]}
    written = write_outputs(args, scan_data, scope_dict)

    findings = scan_data.get("findings", [])
    subs = (scan_data.get("subdomains") or {}).get("count", 0)
    certs = len((scan_data.get("certificates") or {}).get("certificates", []))
    completed = sum(1 for m in scan_data.get("module_results", []) if m.get("ok"))

    print("\n" + "=" * 55)
    print("Scan completed")
    print(f"Modules completed: {completed}")
    print(f"Subdomains discovered: {subs}")
    print(f"Certificates found: {certs}")
    print(f"Findings: {len(findings)}")
    for w in written:
        print(f"Report: {w}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
