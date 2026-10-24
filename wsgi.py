import os

from plaguardsv2.PlagWeb import create_app

app = create_app()

if __name__ == "__main__":
    # Developer shortcut only; gunicorn and waitress import wsgi:app directly.
    # Loopback by default: 0.0.0.0 with debug=True exposes Werkzeug's shell.
    debug = os.environ.get("PLAGUARDSV2_DEBUG", "") == "1"
    app.run(host=os.environ.get("PLAGUARDSV2_HOST", "127.0.0.1"), port=8000, debug=debug)
