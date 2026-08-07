"""
Invite-token logic for the Telegram-bot enrollment flow.
Tokens are single-use and expire after TOKEN_EXPIRY_HOURS.
"""
import secrets
import string
from datetime import datetime, timezone, timedelta
import database
import config


def _now() -> datetime:
    return datetime.now(timezone.utc)


def generate_token(length: int = 32) -> str:
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def create_invite_token(device_id: int, created_by: str) -> dict:
    """
    Generate a new invite token for a device row (must be in PENDING state).
    Returns the token string and expiry.
    """
    token   = generate_token()
    expires = _now() + timedelta(hours=config.TOKEN_EXPIRY_HOURS)

    database.execute_db(
        """
        UPDATE devices
        SET    enroll_token  = %s,
               token_status  = 'UNUSED',
               token_expires = %s
        WHERE  id = %s
        """,
        (token, expires, device_id),
    )

    database.execute_db(
        """
        INSERT INTO audit_log (event, device_id, detail)
        VALUES ('TOKEN_CREATED', %s, %s)
        """,
        (device_id, f"Created by {created_by}"),
    )

    return {"token": token, "expires": expires.isoformat()}


def TokenService(token: str) -> dict | None:
    """
    Return the device row if token is UNUSED and not expired,
    otherwise return None.
    """
    row = database.query_one(
        """
        SELECT d.*, e.full_name, e.department
        FROM   devices d
        JOIN   employees e ON e.employee_id = d.employee_id
        WHERE  d.enroll_token   = %s
          AND  d.token_status   = 'UNUSED'
          AND  d.token_expires  > NOW()
        """,
        (token,),
    )
    return row


def consume_token(device_id: int) -> None:
    """Mark token as USED (one-time enforcement)."""
    database.execute_db(
        "UPDATE devices SET token_status = 'USED' WHERE id = %s",
        (device_id,),
    )


def get_device_sites(device_id: int) -> list[dict]:
    """Return sites assigned to this device."""
    return database.query_all(
        """
        SELECT s.hostname, s.description
        FROM   device_access da
        JOIN   sites s ON s.id = da.site_id
        WHERE  da.device_id = %s
        ORDER  BY s.hostname
        """,
        (device_id,),
    )

