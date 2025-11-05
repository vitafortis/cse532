from datetime import datetime
from flask import request
from . import db

class ApiRequest(db.Model):
    __tablename__ = "api_request"
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    endpoint = db.Column(db.String(128), index=True, nullable=False)
    client_ip = db.Column(db.String(64))
    payload = db.Column(db.Text)            # raw request JSON/text
    response = db.Column(db.Text)           # normalized JSON response
    package_count = db.Column(db.Integer, default=0)
    vuln_count = db.Column(db.Integer, default=0)

    @staticmethod
    def record(endpoint: str, payload: str, response: str, package_count: int, vuln_count: int):
        rec = ApiRequest(
            endpoint=endpoint,
            client_ip=(request.headers.get("X-Forwarded-For") or request.remote_addr or ""),
            payload=payload,
            response=response,
            package_count=package_count,
            vuln_count=vuln_count,
        )
        db.session.add(rec)
        db.session.commit()

class PackageStat(db.Model):
    __tablename__ = "package_stat"
    id = db.Column(db.Integer, primary_key=True)
    package = db.Column(db.String(256), index=True, nullable=False)
    ecosystem = db.Column(db.String(64), index=True, nullable=False, default="PyPI")
    times_requested = db.Column(db.Integer, default=0)
    total_vulns_recorded = db.Column(db.Integer, default=0)
    last_requested_at = db.Column(db.DateTime, default=datetime.utcnow)

    @staticmethod
    def bump(package: str, ecosystem: str = "PyPI"):
        row = PackageStat.query.filter_by(package=package, ecosystem=ecosystem).first()
        if not row:
            row = PackageStat(package=package, ecosystem=ecosystem, times_requested=0)
            db.session.add(row)
        row.times_requested += 1
        row.last_requested_at = datetime.utcnow()
        db.session.commit()


class VulnCache(db.Model):
    __tablename__ = "vuln_cache"
    id = db.Column(db.String(64), primary_key=True)   # OSV ID (e.g., GHSA-..., PYSEC-...)
    json = db.Column(db.Text, nullable=False)         # raw OSV vuln JSON
    fetched_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
