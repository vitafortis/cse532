import json
import re
from datetime import datetime, timedelta, timezone
from typing import List, Tuple, Optional, Dict, Any

import requests
from flask import Blueprint, request, jsonify

from .models import ApiRequest, PackageStat, VulnCache  # <-- includes VulnCache
from . import db

vuln_api = Blueprint("vuln_api", __name__)

OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_GET   = "https://api.osv.dev/v1/vulns/{id}"

# Accept both MEDIUM and MODERATE synonyms
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW", "N/A"]
VALID_SEVERITIES = {"LOW", "MODERATE", "MEDIUM", "HIGH", "CRITICAL"}

_pkg_re = re.compile(r"^\s*([A-Za-z0-9._\-]+)(?:@([A-Za-z0-9.*+!\-_/]+))?\s*$")


def _parse_sbom_text(sbom_text: str) -> List[Tuple[str, Optional[str]]]:
    items = []
    for raw in re.split(r"[,\n]", sbom_text):
        raw = raw.strip()
        if not raw:
            continue
        m = _pkg_re.match(raw)
        if not m:
            continue
        name, version = m.group(1), m.group(2)
        items.append((name, version))
    return items


def _iso_to_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def _cvss_to_bucket(score: float) -> str:
    # CVSS v3.x style thresholds
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "N/A"


def _extract_severity(v: Dict[str, Any]) -> str:
    """
    Try database_specific.severity → severity array (CVSS or labels) → plain string → N/A
    """
    flat = (v.get("database_specific") or {}).get("severity")
    if isinstance(flat, str) and flat.strip():
        s = flat.strip().upper()
        return "MEDIUM" if s == "MODERATE" else s

    sev_arr = v.get("severity")
    if isinstance(sev_arr, list) and sev_arr:
        best = "N/A"
        best_rank = SEVERITY_ORDER.index("N/A")
        for entry in sev_arr:
            if not isinstance(entry, dict):
                continue
            score = entry.get("score")
            if score is not None:
                try:
                    bucket = _cvss_to_bucket(float(str(score)))
                    rank = SEVERITY_ORDER.index(bucket)
                    if rank < best_rank:
                        best, best_rank = bucket, rank
                except Exception:
                    pass
            label = entry.get("type")
            if isinstance(label, str) and label.upper() in VALID_SEVERITIES:
                bucket = "MEDIUM" if label.upper() == "MODERATE" else label.upper()
                rank = SEVERITY_ORDER.index(bucket)
                if rank < best_rank:
                    best, best_rank = bucket, rank
        return best

    top = v.get("severity")
    if isinstance(top, str) and top.strip():
        s = top.strip().upper()
        return "MEDIUM" if s == "MODERATE" else s

    return "N/A"


def _extract_published(v: Dict[str, Any]) -> Optional[str]:
    pub = v.get("published")
    if pub:
        return pub
    mod = v.get("modified")
    if mod:
        return mod
    return None


def _filter_by_days(vulns: List[Dict[str, Any]], days: int) -> List[Dict[str, Any]]:
    if days <= 0:
        return vulns
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    out = []
    for v in vulns:
        when = _iso_to_dt(v.get("published")) or _iso_to_dt(v.get("modified"))
        if when and when > cutoff:
            out.append(v)
    return out


def _filter_by_severity(vulns: List[Dict[str, Any]], severity: Optional[List[str]]) -> List[Dict[str, Any]]:
    if not severity:
        return vulns
    wanted = {("MEDIUM" if s.upper() == "MODERATE" else s.upper()) for s in severity}
    out = []
    for v in vulns:
        bucket = _extract_severity(v)
        if bucket in wanted:
            out.append(v)
    return out


def _simplify(v: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": v.get("id"),
        "summary": v.get("summary"),
        "severity": _extract_severity(v) or "N/A",
        "published": _extract_published(v),
        "aliases": v.get("aliases", []),
        "references": v.get("references", []),
    }


def _need_enrichment(simple_v: Dict[str, Any]) -> bool:
    return (not simple_v.get("published")) or (simple_v.get("severity") in (None, "", "N/A"))


def _enrich_from_osv(vuln_id: str) -> Optional[Dict[str, Any]]:
    """
    Fetch full OSV record for an ID. Uses cache if available and younger than 7 days.
    """
    fresh_cutoff = datetime.utcnow() - timedelta(days=7)
    cached = VulnCache.query.get(vuln_id)
    if cached:
        if cached.fetched_at and cached.fetched_at > fresh_cutoff:
            try:
                return json.loads(cached.json)
            except Exception:
                pass  # fall through to refetch

    try:
        r = requests.get(OSV_GET.format(id=vuln_id), timeout=15)
        r.raise_for_status()
        payload = r.json()
        blob = json.dumps(payload)
        if cached:
            cached.json = blob
            cached.fetched_at = datetime.utcnow()
        else:
            cached = VulnCache(id=vuln_id, json=blob, fetched_at=datetime.utcnow())
            db.session.add(cached)
        db.session.commit()
        return payload
    except requests.RequestException:
        return None
    except Exception:
        db.session.rollback()
        return None


def _sort_key(simple_v: Dict[str, Any]) -> tuple:
    sev = (simple_v.get("severity") or "N/A").upper()
    sev = "MEDIUM" if sev == "MODERATE" else sev
    try:
        sev_rank = SEVERITY_ORDER.index(sev)
    except ValueError:
        sev_rank = SEVERITY_ORDER.index("N/A")
    dt = _iso_to_dt(simple_v.get("published")) or datetime.min.replace(tzinfo=timezone.utc)
    return (sev_rank, -dt.timestamp())


@vuln_api.route("/api/v1/vulns/by-package", methods=["POST"])
def by_package():
    body = request.get_json(silent=True) or {}
    package = body.get("package")
    ecosystem = body.get("ecosystem", "PyPI")
    days = int(body.get("days", 0))
    severity = body.get("severity")
    if isinstance(severity, str):
        severity = [severity]

    if not package:
        return jsonify({"error": "Missing required field: 'package'"}), 400

    query = {"package": {"name": package, "ecosystem": ecosystem}}
    try:
        resp = requests.post(OSV_QUERY, json=query, timeout=15)
        resp.raise_for_status()
    except requests.RequestException as e:
        return jsonify({"error": f"OSV error: {e}"}), 502

    raw = resp.json()
    vulns = raw.get("vulns", []) or []

    if days:
        vulns = _filter_by_days(vulns, days)
    if severity:
        vulns = _filter_by_severity(vulns, severity)

    seen = set()
    clean = []
    for v in vulns:
        vid = v.get("id")
        if vid and vid not in seen:
            seen.add(vid)
            clean.append(_simplify(v))

    enriched = []
    for sv in clean:
        if _need_enrichment(sv) and sv.get("id"):
            full = _enrich_from_osv(sv["id"])
            if full:
                sv = _simplify(full)
        enriched.append(sv)

    enriched.sort(key=_sort_key)

    result = {
        "package": package,
        "ecosystem": ecosystem,
        "count": len(enriched),
        "vulnerabilities": enriched,
    }

    try:
        ApiRequest.record(
            endpoint="/api/v1/vulns/by-package",
            payload=json.dumps(body),
            response=json.dumps(result),
            package_count=1,
            vuln_count=len(enriched),
        )
        PackageStat.bump(package, ecosystem)
    except Exception:
        db.session.rollback()

    return jsonify(result)


@vuln_api.route("/api/v1/vulns/by-sbom", methods=["POST"])
def by_sbom():
    """
    Accepts either:
      {
        "sbom": "flask@2.2.5, requests\\nnumpy@1.26.4",
        "ecosystem": "PyPI",
        "days": 365,
        "severity": ["HIGH","CRITICAL"]
      }
    or:
      {
        "packages": ["flask@2.2.5","requests","numpy@1.26.4"],
        "ecosystem": "PyPI"
      }
    """
    body = request.get_json(silent=True) or {}
    sbom_text = (body.get("sbom") or "").strip()
    packages_list = body.get("packages") or []
    ecosystem = body.get("ecosystem", "PyPI")
    days = int(body.get("days", 0))
    severity = body.get("severity")
    if isinstance(severity, str):
        severity = [severity]

    # Build (name, version) pairs from sbom_text and/or packages[]
    pairs = []
    if sbom_text:
        pairs.extend(_parse_sbom_text(sbom_text))
    for item in packages_list:
        if not isinstance(item, str):
            continue
        m = _pkg_re.match(item)
        if m:
            pairs.append((m.group(1), m.group(2)))

    # Unique by (name, version)
    uniq = []
    seen = set()
    for name, ver in pairs:
        key = (name.lower(), (ver or ""))
        if key not in seen:
            seen.add(key)
            uniq.append((name, ver))

    if not uniq:
        return jsonify({"error": "No valid packages found. Provide 'sbom' or 'packages'."}), 400

    # Build OSV batch queries
    queries = []
    for name, ver in uniq:
        q = {"package": {"name": name, "ecosystem": ecosystem}}
        if ver:
            q["version"] = ver
        queries.append(q)

    try:
        r = requests.post(OSV_BATCH, json={"queries": queries}, timeout=25)
        r.raise_for_status()
    except requests.RequestException as e:
        return jsonify({"error": f"OSV batch error: {e}"}), 502

    batch = r.json().get("results", []) or []

    combined = []
    for entry in batch:
        vulns = entry.get("vulns", []) or []
        if days:
            vulns = _filter_by_days(vulns, days)
        if severity:
            vulns = _filter_by_severity(vulns, severity)
        for v in vulns:
            combined.append(_simplify(v))

    # Dedupe across all packages by vuln id
    seen_ids = set()
    dedup = []
    for v in combined:
        vid = v.get("id")
        if vid and vid not in seen_ids:
            seen_ids.add(vid)
            dedup.append(v)

    # Enrichment pass (only when needed)
    enriched = []
    for sv in dedup:
        if _need_enrichment(sv) and sv.get("id"):
            full = _enrich_from_osv(sv["id"])
            if full:
                sv = _simplify(full)
        enriched.append(sv)

    # Sort by severity then date (desc)
    enriched.sort(key=_sort_key)

    per_package_counts = {}
    for (name, _) in uniq:
        lower_name = name.lower()
        per_package_counts[lower_name] = 0

    for v in enriched:
        # Try to map each vuln to its originating package (by name or in references)
        matched_pkg = None
        if v.get("id"):
            # Basic heuristic — check for name hints
            for pkg in per_package_counts:
                if any(pkg in (ref.get("url", "").lower() or "") for ref in v.get("references", [])):
                    matched_pkg = pkg
                    break
        if not matched_pkg and "aliases" in v:
            # fallback: match alias text
            for pkg in per_package_counts:
                if any(pkg in a.lower() for a in v["aliases"]):
                    matched_pkg = pkg
                    break
        if matched_pkg:
            per_package_counts[matched_pkg] += 1
            
    result = {
        "ecosystem": ecosystem,
        "packages_scanned": len(uniq),
        "total_vulnerabilities": len(enriched),
        "vulnerabilities_by_package": per_package_counts,
        "vulnerabilities": enriched,
    }

    # Analytics (best-effort)
    try:
        ApiRequest.record(
            endpoint="/api/v1/vulns/by-sbom",
            payload=json.dumps(body),
            response=json.dumps(result),
            package_count=len(uniq),
            vuln_count=len(enriched),
        )

        for pkg_name, _ in uniq:
            pkg_lower = pkg_name.lower()
            stat = PackageStat.query.filter_by(package=pkg_lower, ecosystem=ecosystem).first()
            if not stat:
                stat = PackageStat(package=pkg_lower, ecosystem=ecosystem)
                db.session.add(stat)
            stat.times_requested = (stat.times_requested or 0) + 1
            stat.last_requested_at = datetime.utcnow()

            # NEW: log vulnerability totals per package if known
            if pkg_lower in per_package_counts:
                stat.total_vulns_recorded = (stat.total_vulns_recorded or 0) + per_package_counts[pkg_lower]

        db.session.commit()
    except Exception:
        db.session.rollback()

    return jsonify(result)

@vuln_api.route("/api/v1/stats/packages", methods=["GET"])
def stats_packages():
    rows = (
        PackageStat.query.order_by(PackageStat.times_requested.desc())
        .limit(10)
        .all()
    )
    result = [
        {
            "package": r.package,
            "ecosystem": r.ecosystem,
            "times_requested": r.times_requested,
	    "total_vulns_recorded": r.total_vulns_recorded,
            "last_requested_at": r.last_requested_at.isoformat() if r.last_requested_at else None,
        }
        for r in rows
    ]
    return jsonify({"top_packages": result})


from sqlalchemy import func

@vuln_api.route("/api/v1/stats/endpoints", methods=["GET"])
def stats_endpoints():
    rows = (
        db.session.query(
            ApiRequest.endpoint,
            func.count(ApiRequest.id),
            func.avg(ApiRequest.package_count),
            func.avg(ApiRequest.vuln_count),
        )
        .group_by(ApiRequest.endpoint)
        .all()
    )
    result = [
        {
            "endpoint": r[0],
            "requests": int(r[1]),
            "avg_packages": round(float(r[2] or 0), 2),
            "avg_vulns": round(float(r[3] or 0), 2),
        }
        for r in rows
    ]
    return jsonify({"endpoint_stats": result})

@vuln_api.route("/api/v1/stats/recent", methods=["GET"])
def stats_recent():
    rows = ApiRequest.query.order_by(ApiRequest.created_at.desc()).limit(10).all()
    result = [
        {
            "timestamp": r.created_at.isoformat(),
            "endpoint": r.endpoint,
            "client_ip": r.client_ip,
            "packages": r.package_count,
            "vulns": r.vuln_count,
        }
        for r in rows
    ]
    return jsonify({"recent_requests": result})

@vuln_api.route("/api/v1/stats/summary", methods=["GET"])
def stats_summary():
    """
    Returns a high-level summary of usage metrics for dashboards and reporting.
    """
    try:
        # Count total requests
        total_requests = db.session.query(ApiRequest).count()

        # Sum total vulnerabilities and packages
        totals = db.session.query(
            db.func.sum(ApiRequest.vuln_count),
            db.func.sum(ApiRequest.package_count)
        ).first()
        total_vulns = totals[0] or 0
        total_packages = totals[1] or 0

        # Find top 3 packages
        top_packages = (
            db.session.query(PackageStat.package, PackageStat.times_requested)
            .order_by(PackageStat.times_requested.desc())
            .limit(3)
            .all()
        )
        top_list = [{"package": pkg, "times_requested": count} for pkg, count in top_packages]

        # Find most recent request
        latest = db.session.query(ApiRequest).order_by(ApiRequest.created_at.desc()).first()
        latest_time = latest.created_at.isoformat() if latest else None

        summary = {
            "total_requests": total_requests,
            "total_vulnerabilities_recorded": total_vulns,
            "total_packages_processed": total_packages,
            "top_packages": top_list,
            "latest_request": latest_time,
        }

        return jsonify(summary), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500
      
@vuln_api.route("/api/v1/stats/all", methods=["GET"])
def all_stats():
    from sqlalchemy import func

    total_requests = db.session.query(func.count(ApiRequest.id)).scalar() or 0
    total_vulns = db.session.query(func.sum(ApiRequest.vuln_count)).scalar() or 0
    total_packages = db.session.query(func.count(PackageStat.id)).scalar() or 0
    latest_request = (
        db.session.query(func.max(ApiRequest.created_at)).scalar()
    )

    top_packages = [
        {
            "package": p.package,
            "ecosystem": p.ecosystem,
            "times_requested": p.times_requested,
            "last_requested_at": p.last_requested_at.isoformat()
            if p.last_requested_at else None,
        }
        for p in PackageStat.query.order_by(PackageStat.times_requested.desc()).limit(10).all()
    ]

    endpoint_stats = [
        {
            "endpoint": e,
            "requests": int(reqs),
            "avg_packages": float(avg_pkgs or 0),
            "avg_vulns": float(avg_vulns or 0),
        }
        for e, reqs, avg_pkgs, avg_vulns in db.session.query(
            ApiRequest.endpoint,
            func.count(ApiRequest.id),
            func.avg(ApiRequest.package_count),
            func.avg(ApiRequest.vuln_count),
        ).group_by(ApiRequest.endpoint).all()
    ]

    recent = [
        {
            "timestamp": r.created_at.isoformat(),
            "endpoint": r.endpoint,
            "vulns": r.vuln_count,
            "packages": r.package_count,
            "ip": r.client_ip,
        }
        for r in ApiRequest.query.order_by(ApiRequest.created_at.desc()).limit(10).all()
    ]

    return jsonify({
        "summary": {
            "total_requests": total_requests,
            "total_vulnerabilities": total_vulns,
            "total_packages": total_packages,
            "latest_request": latest_request.isoformat() if latest_request else None,
        },
        "top_packages": top_packages,
        "endpoint_stats": endpoint_stats,
        "recent_activity": recent,
    })

@vuln_api.route("/api/v1/debug/packages", methods=["GET"])
def debug_packages():
    """
    Debug endpoint — returns full package_stat table for quick inspection.
    Safe to keep locally; remove or protect if deploying externally.
    """
    rows = PackageStat.query.order_by(PackageStat.times_requested.desc()).all()
    result = [
        {
            "package": r.package,
            "ecosystem": r.ecosystem,
            "times_requested": r.times_requested,
            "total_vulns_recorded": r.total_vulns_recorded,
            "last_requested_at": r.last_requested_at.isoformat() if r.last_requested_at else None,
        }
        for r in rows
    ]
    return jsonify({"packages": result})

      
from flask import render_template

@vuln_api.route("/dashboard", methods=["GET"])
def dashboard():
    return render_template("dashboard.html")
