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


logger = logging.getLogger(__name__)

app = typer.Typer()
state = State()


@app.command()
def fetch(
    backend: Annotated[
        Backend,
        typer.Argument(..., help="Backend for your vault: Bitwarden or 1Password"),
    ],
    item_id: Annotated[
        str,
        typer.Argument(
            ...,
            help="Item name or ID in your vault that contains the credentials (username, password, totp)",
        ),
    ],
    *,
    force: Annotated[
        bool, typer.Option(help="Delete existing keys and fetch new ones.")
    ] = False,
):
    """
    Fetch a new key pair from CSCS service.
    """

    private_key = None
    public_key = None
    keys = state.keys

    if keys.exist():
        if not force:
            logger.warning("Key pair already exists, use --force to overwrite.")
            logger.debug(str(keys))
            sys.exit(1)

        if state.dry_run:
            logger.warning("Dry run: Would delete existing keys.")
        else:
            logger.warning("Deleting existing keys...")
            keys.delete()

    # Create a new credentials helper
    creds_helper = BWHelper if backend.value == "bw" else OPHelper
    vault = creds_helper(item_name=item_id)

    # Get the credentials
    logger.info("Unlocking the vault and fetching credentials...")
    vault.unlock()
    credentials = vault.fetch_credentials()

    # Validate the credentials
    if not vault.are_credentials_valid():
        # TODO: catch which credential is not valid
        sys.exit("Credentials are not valid.")

    if not state.dry_run:
        logger.info(
            "Fetching signed key from CSCS API and saving it to '%s'...",
            keys.dot_ssh_path,
        )

        private_key, public_key = get_keys_from_api(**credentials)

        if not (private_key and public_key):
            sys.exit("Could not fetch signed key from CSCS API.")

        keys.private_key.content = private_key
        keys.public_key.content = public_key
        keys.save()

        logger.info("Done.")
    else:
        logger.info("Dry run: Would fetch signed key from CSCS API.")


@app.command()
def add():
    """
    Add an existing key pair to SSH agent.
    """

    keys = state.keys

    if not keys.exist():
        logger.error("No valid keys found.")
        sys.exit(1)

    delta = datetime.now(timezone.utc) - datetime.fromtimestamp(
        keys.private_key.c_time, timezone.utc
    )
    if delta >= timedelta(hours=24.0):
        logger.warning("Private key is older than 24 hours, please fetch a new one.")
        sys.exit(1)

    if state.dry_run:
        logger.info("Dry run: Would add private key to the agent.")
        sys.exit(0)

    if not is_agent_running():
        logger.error("SSH agent is not running.")
        sys.exit(1)

    if is_key_in_agent(keys.private_key):
        logger.warning("Private key is already in the agent.")
        sys.exit(0)

    logger.info("Adding private key to the agent...")
    add_key_to_agent(keys.private_key)
    logger.info("Key successfully added to the agent.")


@app.callback()
def main(
    *,
    verbose: Annotated[
        int,
        typer.Option(
            "--verbose",
            "-v",
            count=True,
            help="Increase verbosity (can be repeated: -v, -vv)",
        ),
    ] = 0,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", "-n", help="Log the actions without executing them."),
    ] = False,
):
    """
    Manage SSH keypair for CSCS infrastructure using credentials stored in a password manager.
    """
    setup_logging(verbose)

    state.verbose = verbose
    state.dry_run = dry_run

    if verbose:
        logger.info("Verbose mode enabled.")

    if dry_run:
        logger.info("Dry run mode enabled, no action will be executed.")


def entry_point() -> None:
    app()


if __name__ == "__main__":
    app()
