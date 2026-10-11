"""Run the lab portal with Waitress on 127.0.0.1 only (never 0.0.0.0).

    set PORTAL_SECRET_KEY=<random 64 hex chars>
    python run.py
"""
import os

from waitress import serve

from portal import create_app

HOST = "127.0.0.1"   # loopback only: the lab app is never exposed to the network


def main():
    port = int(os.environ.get("PORTAL_PORT", "8080"))
    serve(create_app(), host=HOST, port=port)


if __name__ == "__main__":
    main()
