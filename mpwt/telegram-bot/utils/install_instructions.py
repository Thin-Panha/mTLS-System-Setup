"""
OS-specific certificate install instructions (MarkdownV2-safe strings).
"""


def get_install_instructions(os_type: str) -> str:
    if os_type == "windows":
        return (
            "\U0001f4e5 *Installing your certificate on Windows*\n\n"
            "*1\\. Download the signed certificate*\n"
            "*2\\. Install the CA chain*\n"
            "*Double\\-click Certificate* \u2192 *Open* \u2192"
            "*Install Certificate* \u2192 *Current User* \u2192 "
            "*Place all certificates* \u2192 *Browse* \u2192 *Personal* \u2192 Next \u2192 Finish\\.\n\n"
            "*3\\. Test*\n"
            "Open Chrome or Edge and navigate to your assigned internal site\\. "
            "Select your certificate when prompted\\."
        )
    if os_type == "macos":
        return (
            "\U0001f4e5 *Installing your certificate on macOS*\n\n"
            "*1\\. Download the signed certificate*\n"
            "*2\\. Install the CA chain*\n"
            "Double\\-click Certificate \u2192 "
            "Choose the *login* keychain \\(not *Local Items*\\)"
            "*3\\. Test*\n"
            "Open Safari or Chrome and navigate to internal website \\. "
            "Select your certificate when prompted\\."
        )

    # linux (default)
    return (
        "\U0001f4e5 *Installing your certificate on Linux*\n\n"
        "*Chrome \\/  Chromium:*\n"
        "```\n"
        "# Debian/Ubuntu: sudo apt install libnss3-tools\n"
        "# Fedora/RHEL:   sudo dnf install nss-tools\n\n"
        "# Trust the CA\n"
        "certutil -d sql:$HOME/.pki/nssdb \\\n"
        "  -A -t 'CT,C,C' -n 'MPWT-CA' \\\n"
        "  -i ~/Downloads/ca-chain.crt\n\n"
        "# Bundle key + cert\n"
        "openssl pkcs12 -export \\\n"
        "  -inkey ~/mpwt-cert/client.key \\\n"
        "  -in ~/Downloads/client.crt \\\n"
        "  -out ~/mpwt-cert/client.p12\n\n"
        "# Import the bundle\n"
        "pk12util -d sql:$HOME/.pki/nssdb \\\n"
        "  -i ~/mpwt-cert/client.p12\n"
        "```\n\n"
        "*Firefox:*\n"
        "Settings \u2192 Privacy \\& Security \u2192 View Certificates \u2192 "
        "Import \u2192 select `client\\.p12`\\.\n"
        "Also import `ca\\-chain\\.crt` under the *Authorities* tab\\.\n\n"
        "*Test:* Navigate to your assigned site and select your certificate\\."
    )

