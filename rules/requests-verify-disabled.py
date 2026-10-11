# Semgrep test fixture (lint patterns only, not a runnable app).
import requests


def call_payment_api(url, payload):
    # ruleid: requests-verify-disabled
    requests.post(url, json=payload, verify=False, timeout=10)
    # ruleid: requests-verify-disabled
    requests.get(url, verify=False, timeout=10)
    s = requests.Session()
    # ruleid: requests-verify-disabled
    s.verify = False
    # ruleid: requests-verify-disabled
    s.get(url, verify=False, timeout=10)
    # ok: requests-verify-disabled
    requests.post(url, json=payload, timeout=10)
    # ok: requests-verify-disabled
    requests.get(url, verify="/etc/ssl/certs/agrisouss-ca.pem", timeout=10)
