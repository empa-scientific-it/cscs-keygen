"""
Utils module
"""
import pathlib as pl
import shlex
import shutil
import subprocess as sp
import sys

import requests


def run_command(cmd: str, **kwargs) -> str:
    """Run a `cmd` and return the output or raise an exception"""
    cmd = shlex.split(cmd, posix=False)

    if not shutil.which(cmd[0]):
        raise FileNotFoundError(f"Command {cmd[0]} not found.")

    try:
        output = sp.run(cmd, capture_output=True, check=True, **kwargs)
    except sp.CalledProcessError as err:
        print(err.stderr, file=sys.stderr)
        raise err

    if kwargs.get("text"):
        return output.stdout

    return output.stdout.decode()


def get_keypair_from_api(user: str, pwd: str, otp: str) -> tuple[str]:
    """Peform the API request to CSCS"""
    print("Fetching signed key from CSCS API...")

    try:
        response = requests.post(
            "https://sshservice.cscs.ch/api/v1/auth/ssh-keys/signed-key",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            json={
                "username": user,
                "password": pwd,
                "otp": otp,
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
            print(f"Error: {message['payload']}", file=sys.stderr)
            sys.exit(1)
    else:
        pub_key = response.json()["public"]
        priv_key = response.json()["private"]
        if not (pub_key and priv_key):
            print("Error: no public/private key returned", file=sys.stderr)
            sys.exit(1)

    return priv_key, pub_key


def save_key(key_content: str, key_path: pl.Path, key_type: str) -> None:
    """Save a key file to disk and set the right permissions"""
    try:
        key_path.write_text(key_content)
    except IOError:
        print(f"Error: could not write {key_type} key to {key_path}", file=sys.stderr)
        sys.exit(1)

    try:
        if key_type == "private":
            key_path.chmod(0o600)
        elif key_type == "public":
            key_path.chmod(0o644)
    except:
        print(f"Error: could not set permissions on key {key_path}", file=sys.stderr)
        sys.exit(1)


def add_key(key_path: pl.Path) -> None:
    """Add a private key to SSH agent"""
    # TODO: add support for Windows
    add_cmd = "ssh-add -t 1d"

    if sys.platform == "darwin":
        add_cmd = "/usr/bin/ssh-add -t 1d --apple-use-keychain"

    run_command(f"{add_cmd} {key_path.resolve()}")
