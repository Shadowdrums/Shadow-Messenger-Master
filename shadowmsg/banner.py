import os
import re

from shadowmsg import BANNER as banner


def supports_ansi() -> bool:
    """
    Check if the environment supports ANSI escape codes.
    """
    return os.getenv('TERM') in ('xterm', 'xterm-color', 'xterm-256color', 'vt100', 'linux', 'screen')


def strip_ansi_codes(text):
    """
    Remove ANSI color codes from the text.
    """
    return re.sub(r'\x1b\[[0-9;]*m', '', text)


def run_banner(txt: str = banner):
    if not supports_ansi():
        print(strip_ansi_codes(txt))
    else:
        print(txt)

