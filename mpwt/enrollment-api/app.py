"""
MPWT Enrollment API — Flask application factory
"""
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import database
import config

#limiter = Limiter(key_func=get_remote_address, default_limits=["200 per hour"])
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="redis://127.0.0.1:6379"
)

def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = config.SECRET_KEY

    # ── Logging ──────────────────────────────────────────────────────────────
    logging.basicConfig(
        filename=config.LOG_PATH,
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    # ── Database pool ─────────────────────────────────────────────────────────
    database.init_pool(min_conn=1, max_conn=10)

    # ── Rate limiter ──────────────────────────────────────────────────────────
    limiter.init_app(app)

    # ── Blueprints ────────────────────────────────────────────────────────────
    from routes.enroll  import enroll_bp
    from routes.devices import devices_bp
    from routes.revoke  import revoke_bp
    from routes.sites   import sites_bp

    app.register_blueprint(enroll_bp)
    app.register_blueprint(devices_bp)
    app.register_blueprint(revoke_bp)
    app.register_blueprint(sites_bp)

    # ── Health ────────────────────────────────────────────────────────────────
    @app.route("/health")
    def health():
        return {"status": "ok"}

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
