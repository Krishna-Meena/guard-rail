# GR-BFSI-008 fixture — Dangerous subprocess / eval Usage (Python)
"""
Intentionally vulnerable: eval, exec, and shell=True subprocess calls.
DO NOT deploy — sample-app fixture for GuardRail unit tests only.
"""

import os
import subprocess


def execute_expression(user_input: str):
    # Direct eval of user input — arbitrary code execution
    return eval(user_input)  # noqa: S307


def run_script(script_code: str) -> None:
    # exec with user-controlled input
    exec(script_code)  # noqa: S102


def convert_file(filename: str) -> None:
    # subprocess with shell=True — command injection possible
    subprocess.run(f"convert {filename} output.pdf", shell=True)  # noqa: S602, S607


def list_dir(path: str) -> str:
    # os.system with user input
    return os.system(f"ls {path}")  # noqa: S605


def read_proc(cmd: str) -> str:
    # os.popen with user-controlled command
    return os.popen(cmd).read()  # noqa: S605
