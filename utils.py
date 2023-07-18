"""
Utils module
"""
import pathlib as pl
import shlex
import subprocess as sp
import sys
import logging

import requests


def run_command(cmd: str, capture: bool = True, check: bool = True, **kwargs) -> str | int:
    """Run a `cmd` and return the output or raise an exception"""
    if sys.platform != "win32":
        cmd = shlex.split(cmd)

    try:
        output = sp.run(cmd, capture_output=capture, check=check, **kwargs)
    except sp.CalledProcessError as err:
        logging.error(err.stderr, exc_info=err)
        raise err

    if capture:
        if kwargs.get("text"):
            return str(output.stdout)

        return output.stdout.decode()

    return output.returncode


def get_keys_from_api(username: str, password: str, totp: str) -> tuple[str, str] | None:
    """Perform the API request to CSCS"""
    logging.info("Fetching signed key from CSCS API...")

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

        if not (pub_key and priv_key):
            logging.error("Error: no public/private key returned")
            sys.exit(1)

        return priv_key, pub_key


def save_key(key_content: str, key_path: pl.Path, key_type: str) -> None:
    """Save a key file to disk and set the right permissions"""
    try:
        key_path.write_text(key_content)
    except IOError:
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
