#!/usr/bin/env python3
"""
Python script to fetch SSH key pair from CSCS service using credentials stored in Bitwarden or 1Password vaults.

Pre-requisites:
    - Python 3 installation and `requirements.txt` dependencies
    - Bitwarden CLI: https://bitwarden.com/help/cli/
    - 1Password CLI: https://developer.1password.com/docs/cli/get-started/
"""

import enum
import logging
import pathlib as pl
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import typer
from credentials_helper import BWHelper, OPHelper
from typing_extensions import Annotated
from utils import add_key, get_keys_from_api, save_key, setup_logging


class Backend(str, enum.Enum):
    """Enum to store the supported backends"""

    BW = "bw"
    OP = "op"


@dataclass
class Keys:
    """Class to store private and public keys"""

    dot_ssh_path: pl.Path = pl.Path.home() / ".ssh"
    private_key: pl.Path = field(init=False)
    public_key: pl.Path = field(init=False)

    def __post_init__(self) -> None:
        """Set private/public key paths"""
        self.private_key = self.dot_ssh_path / "cscs-key"
        self.public_key = self.dot_ssh_path / "cscs-key-cert.pub"

    def exist(self) -> bool:
        """Check if the key pair exists"""
        return self.private_key.exists() or self.public_key.exists()

    def delete(self) -> None:
        """Delete the key pair"""
        self.private_key.unlink(missing_ok=True)
        self.public_key.unlink(missing_ok=True)

    def save(self, _type: str, content: str) -> None:
        """Save the key to the filesystem"""
        key_path = self.private_key if _type == "private" else self.public_key
        save_key(content, key_path, _type)


@dataclass
class State:
    keys: Keys = field(default_factory=Keys)
    verbose: int = 0
    dry_run: bool = False


app = typer.Typer()
state = State()


@app.command()
def fetch(
    backend: Annotated[Backend, typer.Argument(..., help="Backend for your vault: Bitwarden or 1Password")],
    item_id: Annotated[
        str,
        typer.Argument(
            ..., help="Item name or ID in your vault that contains the credentials (username, password, totp)"
        ),
    ],
    *,
    force: Annotated[bool, typer.Option(help="Delete existing keys and fetch new ones.")] = False,
):
    """
    Fetch a new key pair from CSCS service.
    """
    if state.keys.exist():
        if not force:
            logging.warning("Key pair already exists, use --force to overwrite.")
            logging.info(str(state.keys))
            sys.exit(1)
        else:
            logging.warning("Deleting existing keys...")
            if not state.dry_run:
                state.keys.delete()

    # Create a new credentials helper
    creds_helper = BWHelper if backend.value == "bw" else OPHelper
    vault = creds_helper(item_name=item_id)

    # Get the credentials
    logging.info("Unlocking the vault and fetching credentials...")
    vault.unlock()
    credentials = vault.fetch_credentials()

    # Validate the credentials
    if not vault.are_credentials_valid():
        # TODO: catch which credential is not valid
        sys.exit("Credentials are not valid.")

    logging.info(
        "Fetching signed key from CSCS API and saving it to '%s'...",
        state.keys.dot_ssh_path,
    )

    if not state.dry_run:
        private_key, public_key = get_keys_from_api(**credentials)

        if private_key and public_key:
            state.keys.save("private", private_key)
            state.keys.save("public", public_key)
        else:
            sys.exit("Could not fetch signed key from CSCS API.")

    logging.info("Done.")


@app.command()
def add():
    """
    Add an existing key pair to ssh-agent.
    """
    if state.keys.exist():
        delta = datetime.now(timezone.utc) - datetime.fromtimestamp(
            state.keys.private_key.stat().st_ctime, timezone.utc
        )
        if delta < timedelta(hours=24.0):
            logging.info("Valid private key found, adding it to ssh-agent...")
            if not state.dry_run:
                add_key(state.keys.private_key)
            sys.exit(0)
        else:
            logging.warning("Private key is older than 24 hours, please fetch a new one.")
            sys.exit(1)
    else:
        logging.error("No valid keys found.")
        sys.exit(1)


@app.callback()
def main(
    *,
    verbose: Annotated[int, typer.Option(count=True, help="Enable verbose mode.")] = 0,
    dry_run: Annotated[bool, typer.Option(help="Log the actions without executing them.")] = False,
):
    """
    Manage SSH keypair for CSCS infrastructure using credentials stored in a password manager.
    """
    if verbose:
        logging.info("Verbose mode enabled.")
        state.verbose = verbose

    if dry_run:
        logging.info("Dry run mode enabled, no action will be executed.")
        state.dry_run = True

    setup_logging(state.verbose)


def entry_point() -> None:
    app()


if __name__ == "__main__":
    app()
