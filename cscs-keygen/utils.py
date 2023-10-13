"""
Utils module
"""
import logging
import os
import pathlib as pl
import shlex
import subprocess as sp
import sys

import requests


def setup_logging(verbosity: int) -> None:
    """Setup logging"""
    # default: logging.WARNING
    default_log_level = getattr(logging, (os.getenv("LOG_LEVEL", "WARNING").upper()))
    verbosity = min(2, verbosity)

    log_level = default_log_level - verbosity * 10

    logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=log_level)


def run_command(cmd: str | list[str], *, capture: bool = True, check: bool = True, **kwargs) -> str | int:
    """Run a `cmd` and return the output or raise an exception"""
    if isinstance(cmd, str) and sys.platform != "win32":
        cmd = shlex.split(cmd)

    try:
        output = sp.run(cmd, capture_output=capture, check=check, **kwargs)  # noqa: S603
    except sp.CalledProcessError as err:
        logging.error("Error while running the command '%s': %s", " ".join(cmd), err.stderr)
        raise SystemExit(err.returncode) from err

    if capture:
        if kwargs.get("text"):
            return str(output.stdout)

        return output.stdout.decode()

    return output.returncode


def get_keys_from_api(username: str, password: str, totp: str) -> tuple[str | None, str | None]:
    """Perform the API request to CSCS"""
    logging.info("Fetching signed key from CSCS API...")

    priv_key = pub_key = None

    try:
        response = requests.post(
            "https://sshservice.cscs.ch/api/v1/auth/ssh-keys/signed-key",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            json={
                "username": username,
                "password": password,
                "otp": totp,
            },
            verify=True,
            timeout=30.0,
        )
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        try:
            message = err.response.json()
        except Exception:
            raise SystemExit(1) from err

        if "payload" in message and "message" in message["payload"]:
            logging.error(f"Error: {message['payload']}")
            sys.exit(1)
    else:
        pub_key = response.json()["public"]
        priv_key = response.json()["private"]

    return priv_key, pub_key


def save_key(key_content: str | None, key_path: pl.Path, key_type: str) -> None:
    """Save a key file to disk and set the right permissions"""
    if not key_content:
        logging.error(f"Error: could not save {key_type} key to {key_path}: key content is invalid.")
        raise TypeError

    try:
        key_path.write_text(key_content)
    except OSError:
        logging.error(f"Error: could not write {key_type} key to {key_path}")
        sys.exit(1)

    try:
        if key_type == "private":
            key_path.chmod(0o600)
        elif key_type == "public":
            key_path.chmod(0o644)
    except PermissionError:
        logging.error(f"Error: could not set permissions on key {key_path}")
        sys.exit(1)


def add_key(key_path: pl.Path) -> None:
    """Add a private key to SSH agent"""
    # TODO: add support for Windows
    add_cmd = "ssh-add -t 1d"

    if sys.platform == "darwin":
        add_cmd = "/usr/bin/ssh-add -t 1d --apple-use-keychain"

    run_command(f"{add_cmd} {key_path.resolve()}")
