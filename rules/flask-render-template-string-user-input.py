# Semgrep test fixture (lint patterns only, not a runnable app).
from flask import render_template, render_template_string, request


def greet():
    name = request.args.get("name", "")
    # ruleid: flask-render-template-string-user-input
    return render_template_string("<p>Hello " + name + "</p>")


def note_preview():
    # ruleid: flask-render-template-string-user-input
    return render_template_string(request.form["note"])


def greet_ok():
    name = request.args.get("name", "")
    # ok: flask-render-template-string-user-input
    return render_template_string("<p>Hello {{ name }}</p>", name=name)


def greet_file_ok():
    # ok: flask-render-template-string-user-input
    return render_template("hello.html", name=request.args.get("name", ""))
