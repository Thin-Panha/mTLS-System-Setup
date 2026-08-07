"""
MPWT Enrollment Bot — entry point.

Drop this file (and the bot/, config/, utils/ packages) into /opt/mpwt/bot/
alongside the existing venv/ and requirements.txt. The systemd unit needs no
changes at all.
"""

from config.logging_config import setup_logging
from bot.app import create_app

if __name__ == "__main__":
    setup_logging()
    app = create_app()
    app.run_polling()
