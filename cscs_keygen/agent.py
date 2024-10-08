"""
SSH agent utilities
"""
import logging
import sys

from cscs_keygen.models import Key
from cscs_keygen.utils import run_command


def is_agent_running() -> bool:
    """Check if the SSH agent is running"""
    if sys.platform == "win32":
        # TODO: add support for Windows
        return False

    return run_command("ssh-add -l", check=False) == 0


def add_key_to_agent(key: Key) -> None:
    """Add a private key to SSH agent"""
    # TODO: add support for Windows
    add_cmd = "ssh-add -t 1d"

    if sys.platform == "darwin":
        add_cmd = "/usr/bin/ssh-add -t 1d --apple-use-keychain"

    run_command(f"{add_cmd} {key.path.expanduser().resolve()}")


def is_key_in_agent(key: Key) -> bool:
    """Check if a key is in the SSH agent"""
    return key.fingerprint in str(run_command("ssh-add -l", capture=True))
