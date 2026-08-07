"""
Device CRUD and device-level access checks.
"""
import database


# ── Employee helpers ───────────────────────────────────────────────────────────

def create_employee(employee_id: str, full_name: str,
                    department: str, email: str = None) -> dict:
    return database.execute_returning(
        """
        INSERT INTO employees (employee_id, full_name, department, email)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (employee_id) DO UPDATE
            SET full_name  = EXCLUDED.full_name,
                department = EXCLUDED.department,
                email      = EXCLUDED.email
        RETURNING *
        """,
        (employee_id, full_name, department, email),
    )


def get_employee(employee_id: str) -> dict | None:
    return database.query_one(
        "SELECT * FROM employees WHERE employee_id = %s",
        (employee_id,),
    )


# ── Device helpers ─────────────────────────────────────────────────────────────

def create_device(employee_id: str) -> dict:
    """Create a bare PENDING device for an employee."""
    return database.execute_returning(
        """
        INSERT INTO devices (employee_id, cert_status, token_status)
        VALUES (%s, 'PENDING', 'UNUSED')
        RETURNING *
        """,
        (employee_id,),
    )


def get_device_by_id(device_id: int) -> dict | None:
    return database.query_one(
        "SELECT * FROM devices WHERE id = %s",
        (device_id,),
    )


def get_device_by_serial(serial: str) -> dict | None:
    return database.query_one(
        "SELECT * FROM devices WHERE cert_serial = %s",
        (serial,),
    )


#def list_devices(employee_id: str = None) -> list[dict]:
#    if employee_id:
#        return database.query_all(
#            "SELECT * FROM devices WHERE employee_id = %s ORDER BY created_at DESC",
#            (employee_id,),
#        )
#    return database.query_all(
#        "SELECT * FROM devices ORDER BY created_at DESC"
#    )

#def list_devices(employee_id: str = None) -> list[dict]:
#    if employee_id:
#        return database.query_all(
#            "SELECT * FROM devices WHERE employee_id = %s ORDER BY created_at ASC",  # ← ASC
#            (employee_id,),
#        )
#    return database.query_all(
#        "SELECT * FROM devices ORDER BY created_at ASC"  # ← ASC
#    )

def list_devices(employee_id: str = None) -> list[dict]:
    if employee_id:
        return database.query_all(
            """
            SELECT d.*, e.full_name, e.department
            FROM   devices d
            JOIN   employees e ON e.employee_id = d.employee_id
            WHERE  d.employee_id = %s
            ORDER  BY d.created_at ASC
            """,
            (employee_id,),
        )
    return database.query_all(
        """
        SELECT d.*, e.full_name, e.department
        FROM   devices d
        JOIN   employees e ON e.employee_id = d.employee_id
        ORDER  BY d.created_at ASC
        """
    )

def activate_device(device_id: int, device_name: str,
                    cert_serial: str, os_type: str) -> None:
    database.execute_db(
        """
        UPDATE devices
        SET    cert_serial  = %s,
               device_name  = %s,
               os_type      = %s,
               cert_status  = 'ACTIVE',
               enrolled_at  = NOW()
        WHERE  id = %s
        """,
        (cert_serial, device_name, os_type, device_id),
    )


def revoke_device(device_id: int) -> None:
    database.execute_db(
        """
        UPDATE devices
        SET    cert_status = 'REVOKED',
               revoked_at  = NOW()
        WHERE  id = %s
        """,
        (device_id,),
    )


# ── Site / access helpers ──────────────────────────────────────────────────────

def list_sites() -> list[dict]:
    return database.query_all(
        "SELECT * FROM sites WHERE active = TRUE ORDER BY hostname"
    )


def assign_site(device_id: int, site_id: int, granted_by: str) -> None:
    database.execute_db(
        """
        INSERT INTO device_access (device_id, site_id, granted_by)
        VALUES (%s, %s, %s)
        ON CONFLICT (device_id, site_id) DO NOTHING
        """,
        (device_id, site_id, granted_by),
    )


def unassign_site(device_id: int, site_id: int) -> None:
    database.execute_db(
        "DELETE FROM device_access WHERE device_id = %s AND site_id = %s",
        (device_id, site_id),
    )


def get_device_sites(device_id: int) -> list[dict]:
    return database.query_all(
        """
        SELECT s.id, s.hostname, s.description
        FROM   device_access da
        JOIN   sites s ON s.id = da.site_id
        WHERE  da.device_id = %s
        ORDER  BY s.hostname
        """,
        (device_id,),
    )


# ── Auth-check (called by Nginx sub-request) ───────────────────────────────────

def check_device_access(cert_serial: str, hostname: str) -> bool:
    """
    Returns True if:
      - A device with cert_serial exists and is ACTIVE
      - That device has device_access for the requested hostname
    """
    row = database.query_one(
        """
        SELECT 1
        FROM   devices d
        JOIN   device_access da ON da.device_id = d.id
        JOIN   sites s          ON s.id = da.site_id
        WHERE  d.cert_serial = %s
          AND  d.cert_status = 'ACTIVE'
          AND  s.hostname    = %s
          AND  s.active      = TRUE
        LIMIT  1
        """,
        (cert_serial, hostname),
    )
    return row is not None


# ── Audit ──────────────────────────────────────────────────────────────────────

def audit(event: str, employee_id: str = None, device_id: int = None,
          device_name: str = None, detail: str = None,
          ip_address: str = None) -> None:
    database.execute_db(
        """
        INSERT INTO audit_log
            (event, employee_id, device_id, device_name, detail, ip_address)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (event, employee_id, device_id, device_name, detail, ip_address),
    )

