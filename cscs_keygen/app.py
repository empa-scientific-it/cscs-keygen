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
import sys
from datetime import datetime, timedelta, timezone

import typer
from typing_extensions import Annotated

from cscs_keygen.agent import add_key_to_agent, is_agent_running, is_key_in_agent
from cscs_keygen.credentials_helper import BWHelper, OPHelper
from cscs_keygen.models import State
from cscs_keygen.utils import get_keys_from_api, setup_logging


class Backend(str, enum.Enum):
    """Enum to store the supported backends"""

    BW = "bw"
    OP = "op"


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
    private_key = None
    public_key = None
    keys = state.keys

    if keys.exist():
        if not force:
            logging.warning("Key pair already exists, use --force to overwrite.")
            logging.info(str(keys))
            sys.exit(1)
        else:
            logging.warning("Deleting existing keys...")
            if not state.dry_run:
                keys.delete()

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
        keys.dot_ssh_path,
    )

    if not state.dry_run:
        private_key, public_key = get_keys_from_api(**credentials)

        if not (private_key and public_key):
            sys.exit("Could not fetch signed key from CSCS API.")

        keys.private_key.content = private_key
        keys.public_key.content = public_key
        keys.save()

    logging.info("Done.")


@app.command()
def add():
    """
    Add an existing key pair to SSH agent.
    """
    keys = state.keys

    if keys.exist():
        delta = datetime.now(timezone.utc) - datetime.fromtimestamp(keys.private_key.c_time, timezone.utc)
        if delta < timedelta(hours=24.0):
            logging.info("Valid private key found, adding it to the agent...")
            if not state.dry_run:
                if not (is_agent_running() and is_key_in_agent(keys.private_key)):
                    add_key_to_agent(keys.private_key)
                else:
                    logging.warning("Private key is already in the agent.")
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
