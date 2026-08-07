"""
Site management
===============
GET    /api/sites              — list all sites
POST   /api/sites              — add a new site
DELETE /api/sites/<site_id>    — deactivate a site
"""
from flask import Blueprint, request, jsonify
import services.device_service as device_svc
import config

sites_bp = Blueprint("sites", __name__)


def _require_api_key():
    key = request.headers.get("X-API-Key", "")
    if key != config.MPWT_API_KEY:
        return jsonify(status="error", message="Unauthorized"), 401
    return None


@sites_bp.route("/api/sites", methods=["GET"])
def list_sites():
    err = _require_api_key()
    if err:
        return err
    return jsonify(status="ok", sites=device_svc.list_sites())


@sites_bp.route("/api/sites", methods=["POST"])
def add_site():
    err = _require_api_key()
    if err:
        return err

    data        = request.get_json(silent=True) or {}
    hostname    = (data.get("hostname")    or "").strip()
    description = (data.get("description") or "").strip() or None

    if not hostname:
        return jsonify(status="error", message="hostname required"), 400

    from database import execute_returning
    site = execute_returning(
        """
        INSERT INTO sites (hostname, description)
        VALUES (%s, %s)
        ON CONFLICT (hostname) DO UPDATE SET active = TRUE
        RETURNING *
        """,
        (hostname, description),
    )
    return jsonify(status="ok", site=site), 201


@sites_bp.route("/api/sites/<int:site_id>", methods=["DELETE"])
def deactivate_site(site_id):
    err = _require_api_key()
    if err:
        return err
    from database import execute_db
    execute_db("UPDATE sites SET active = FALSE WHERE id = %s", (site_id,))
    return jsonify(status="ok", message=f"Site {site_id} deactivated")
