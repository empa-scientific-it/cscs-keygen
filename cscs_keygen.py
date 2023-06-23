#!/usr/bin/env python3
"""
Python script to fetch SSH key pair from CSCS service using credentials stored in Bitwarden

Pre-requisites:
    - Python 3 installation with the 'requests' package installed
    - Bitwarden CLI: https://bitwarden.com/help/cli/

TODO:
    - Support 1Password and (maybe) KeePassXC
    - Add a dry-run mode
    - Restructure the CLI in multiple subcommands: fetch, add, ...
"""

import argparse
import json
import os
import pathlib as pl
import re
import shlex
import shutil
import subprocess as sp
import sys
from datetime import datetime, timedelta
from dataclasses import dataclass

try:
    import requests
except ImportError:
    print("Please, install 'requests' with 'pip install requests' first.")
    sys.exit(1)


@dataclass
class Field:
    """Utility class for a string field"""

    content: str

    def __str__(self) -> str:
        return self.content

    def __format__(self, __format_spec: str) -> str:
        if __format_spec == "hidden":
            return self.content[0] + "*" * len(self.content[1:-4]) + self.content[-4:]
        return self.content


def run_command(cmd: str, **kwargs) -> str:
    """Run a `cmd` and return the output or raise an exception"""
    cmd = shlex.split(cmd)

    if not shutil.which(cmd[0]):
        raise FileNotFoundError(f"Command {cmd[0]} not found.")

    try:
        output = sp.run(cmd, capture_output=True, check=True, **kwargs)
    except sp.CalledProcessError as err:
        print(err.stderr, file=sys.stderr)
        raise err

    if "text" in kwargs and kwargs["text"]:
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


def save_keyfile(key_content: str, key_path: pl.Path, key_type: str) -> None:
    """Save the key to disk"""
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


def is_cli_logged_in() -> bool:
    """Check if Bitwarden CLI is logged in"""
    if os.getenv("BW_SESSION"):
        return True
    return False


def search_id(bitwarden_search: str = None) -> str | None:
    """Search Bitwarden for an item ID with a given search string"""
    # Empty search string returns None
    if not bitwarden_search:
        return None

    # Check if Bitwarden CLI is logged in
    if not is_cli_logged_in():
        print("Bitwarden CLI not logged in. Exiting.")
        sys.exit(1)

    # Search Bitwarden for a valid item ID
    if not (
        result := json.loads(
            run_command(f"bw list items --search '{bitwarden_search}'")
        )
    ):
        return None

    if isinstance(result, list) and len(result) > 1:
        print(
            "More than one result found: please, be more specific with your search. Exiting."
        )
        sys.exit(1)

    return result[0].get("id")


def get_keys(bitwarden_item_id: str = None) -> tuple[str]:
    """Get Bitwarden credentials and fetch the keys from CSCS API"""
    # Set the Bitwarden item ID
    if not bitwarden_item_id:
        print("Bitwarden item ID not set as env variable or passed as argument.")
        sys.exit(1)

    # Check if Bitwarden CLI is logged in
    if not is_cli_logged_in():
        print("Bitwarden CLI not logged in. Exiting.")
        sys.exit(1)

    # Get the credentials from Bitwarden
    print("Fetching credentials from Bitwarden...")
    creds = json.loads(run_command(f"bw get item {bitwarden_item_id} --raw"))
    username = Field(creds["login"]["username"])
    password = Field(creds["login"]["password"])
    totp = Field(
        run_command(f"bw get totp {bitwarden_item_id} --raw", text=True).strip()
    )

    # Validate the credentials
    if not re.match(r"^[a-z0-9_-]{2,15}$", username):
        print("Invalid username. Exiting.")
        sys.exit(1)

    if not password:
        print("Empty password. Exiting.")
        sys.exit(1)

    if not re.match(r"^[0-9]{6}$", totp):
        print("Invalid TOTP. Exiting.")
        sys.exit(1)

    # Fetch and return the keys from the API
    return get_keypair_from_api(username, password, totp)


def add_keys(key_path: pl.Path) -> None:
    """Add the keys to ssh-agent"""
    # TODO: add support for Windows
    add_cmd = "ssh-add -t 1d"

    if sys.platform == "darwin":
        add_cmd = "/usr/bin/ssh-add -t 1d --apple-use-keychain"

    run_command(f"{add_cmd} {key_path.resolve()}")


if __name__ == "__main__":
    # Parse the command-line arguments
    parser = argparse.ArgumentParser(
        description="Fetch private/public key pair from CSCS service using Bitwarden credentials"
    )
    # parser.add_argument(
    #     "--dry_run",
    #     "-n",
    #     action="store_true",
    #     default=False,
    #     help="do nothing, only print the commands that would be run",
    # )
    parser.add_argument(
        "--quiet", "-q", action="store_true", default=False, help="silence all output"
    )
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        default=False,
        help="delete existing keys and fetch new ones",
    )
    parser.add_argument(
        "--add", "-a", action="store_true", default=False, help="add keys to ssh-agent"
    )
    parser.add_argument(
        "--item_id",
        "-i",
        type=str,
        default=None,
        help="Bitwarden item ID. If not passed, the BW_ITEM_ID env variable is used (if set)",
    )
    parser.add_argument(
        "--search_id",
        "-s",
        type=str,
        default=None,
        help="search Bitwarden for an item ID with this search string. The script exits if more than one result is found",
    )
    args = parser.parse_args()

    # Output
    if args.quiet:
        sys.stdout = open(os.devnull, "w")
        sys.stderr = open(os.devnull, "w")

    # Set private/public key paths
    (dot_ssh_path := pl.Path.home() / ".ssh").mkdir(exist_ok=True)
    private_key_path = dot_ssh_path / "cscs-key"
    public_key_path = dot_ssh_path / "cscs-key-cert.pub"

    # If key pair exists, try adding it to the agent then exit
    if not args.force and args.add and private_key_path.exists():
        delta = timedelta(
            milliseconds=datetime.now().timestamp() - private_key_path.stat().st_ctime
        )
        if delta < timedelta(hours=24.0):
            print("Valid private key found, adding it to ssh-agent...")
            add_keys(private_key_path)
            print("Done.")
            sys.exit(0)

    # Test if keypair already exists
    if private_key_path.exists() or public_key_path.exists():
        if args.force:
            print("Deleting existing keys...")
            private_key_path.unlink(missing_ok=True)
            public_key_path.unlink(missing_ok=True)
        else:
            print("Key pair already exists. Use --force if you want to delete them.")
            sys.exit(1)

    # Get the keys
    item_id = args.item_id or os.getenv("BW_ITEM_ID") or search_id(args.search_id)

    if not item_id:
        print("Invalid item ID or search string: either one is required. Exiting.")
        sys.exit(1)

    private_key, public_key = get_keys(item_id)

    # Write the keys to disk
    print(f"Saving the keys to {private_key_path.parent}...")
    save_keyfile(private_key, private_key_path, "private")
    save_keyfile(public_key, public_key_path, "public")

    # Set the passphrase
    item_json = json.loads(run_command(f"bw get item {item_id} --raw"))
    try:
        passphrase = Field(item_json["fields"][0]["value"])
    except (KeyError, IndexError):
        print(f"Passphrase field not found in Bitwarden item with ID {item_id}.")
        sys.exit(1)

    if passphrase:
        print("Setting the passphrase...")
        run_command(f"ssh-keygen -p -f {private_key_path} -N {passphrase}")

    # Add the keys to ssh-agent
    if args.add:
        print("Adding keys to ssh-agent...")
        add_keys(private_key_path)

    print("Done.")
