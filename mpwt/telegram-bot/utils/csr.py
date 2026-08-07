"""
CSR validation and normalisation helpers.
"""


def normalize_csr(text: str) -> str:
    """Normalise legacy 'NEW CERTIFICATE REQUEST' headers to the RFC standard."""
    return (
        text.strip()
        .replace(
            "-----BEGIN NEW CERTIFICATE REQUEST-----",
            "-----BEGIN CERTIFICATE REQUEST-----",
        )
        .replace(
            "-----END NEW CERTIFICATE REQUEST-----",
            "-----END CERTIFICATE REQUEST-----",
        )
    )


def is_valid_pem_csr(text: str) -> bool:
    """Return True if *text* looks like a PEM-encoded CSR."""
    s = text.strip()
    has_begin = (
        s.startswith("-----BEGIN CERTIFICATE REQUEST-----")
        or s.startswith("-----BEGIN NEW CERTIFICATE REQUEST-----")
    )
    has_end = (
        s.endswith("-----END CERTIFICATE REQUEST-----")
        or s.endswith("-----END NEW CERTIFICATE REQUEST-----")
    )
    return has_begin and has_end
