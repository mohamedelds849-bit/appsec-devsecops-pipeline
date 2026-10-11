# Semgrep test fixture (lint patterns only, not a runnable app).
from flask import Flask

app = Flask(__name__)
# ruleid: flask-debug-enabled
app.debug = True
# ruleid: flask-debug-enabled
app.config["DEBUG"] = True
# ok: flask-debug-enabled
app.config["DEBUG"] = False

if __name__ == "__main__":
    # ruleid: flask-debug-enabled
    app.run(host="127.0.0.1", debug=True)
    # ok: flask-debug-enabled
    app.run(host="127.0.0.1")
