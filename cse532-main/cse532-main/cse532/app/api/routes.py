import logging

from flask import Flask
from flask_appbuilder import AppBuilder, SQLA

"""
 Logging configuration
"""

logging.basicConfig(format="%(asctime)s:%(levelname)s:%(name)s:%(message)s")
logging.getLogger().setLevel(logging.DEBUG)

app = Flask(__name__)
app.config.from_object("config")
db = SQLA(app)
appbuilder = AppBuilder(app, db.session)


"""
from sqlalchemy.engine import Engine
from sqlalchemy import event

#Only include this for SQLLite constraints
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    # Will force sqllite contraint foreign keys
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()
"""

from . import views

from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
from dateutil.parser import parse as dateparse
import requests, cachetools

api_bp = Blueprint("api", __name__)
cache = cachetools.TTLCache(maxsize=500, ttl=3600)

OSV_API = "https://api.osv.dev/v1/query"

def osv_query(ecosystem, name, version=None):
    key = f"{ecosystem}:{name}:{version}"
    if key in cache:
        return cache[key]
    payload = {"package": {"ecosystem": ecosystem, "name": name}}
    if version:
        payload["version"] = version
    r = requests.post(OSV_API, json=payload, timeout=10)
    data = r.json().get("vulns", [])
    cache[key] = data
    return data

@api_bp.route("/vulns/by-package", methods=["POST"])
def by_package():
    req = request.get_json(force=True)
    eco, name = req.get("ecosystem"), req.get("name")
    version = req.get("version")
    filters = req.get("filters", {})

    vulns = osv_query(eco, name, version)

    # --- basic filters ---
    days = filters.get("newer_than_days")
    if days:
        cutoff = datetime.utcnow() - timedelta(days=int(days))
        def recent(v):
            date = v.get("published") or v.get("modified")
            try:
                return dateparse(date) >= cutoff
            except Exception:
                return True
        vulns = [v for v in vulns if recent(v)]

    severity = [s.upper() for s in filters.get("severity", [])]
    if severity:
        vulns = [v for v in vulns if v.get("severity") and any(s["type"].upper() in severity for s in v["severity"])]

    return jsonify({"count": len(vulns), "items": vulns})
