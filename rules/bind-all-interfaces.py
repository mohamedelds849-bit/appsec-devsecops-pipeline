# Semgrep test fixture (lint patterns only, not a runnable app).
from flask import Flask
from waitress import serve

app = Flask(__name__)
# ruleid: bind-all-interfaces
HOST = "0.0.0.0"
# ruleid: bind-all-interfaces
app.run(host="0.0.0.0", port=8080)
# ruleid: bind-all-interfaces
serve(app, host="0.0.0.0", port=8080)
# ok: bind-all-interfaces
serve(app, host="127.0.0.1", port=8080)
# ok: bind-all-interfaces
app.run(host="127.0.0.1")
