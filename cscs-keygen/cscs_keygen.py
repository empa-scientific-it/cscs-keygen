#!/usr/bin/env python3
"""
Python script to fetch SSH key pair from CSCS service using credentials stored in Bitwarden or 1Password vaults.

Pre-requisites:
    - Python 3 installation and `requirements.txt` dependencies
    - Bitwarden CLI: https://bitwarden.com/help/cli/
    - 1Password CLI: https://developer.1password.com/docs/cli/get-started/
"""

import argparse
import logging
import os
import pathlib as pl
import sys
from datetime import datetime, timedelta

from credentials_helper import BWHelper, OPHelper
from utils import add_key, get_keys_from_api, save_key


def setup_logging(verbosity: int) -> None:
    """Setup logging"""
    # default: logging.WARNING
    default_log_level = getattr(logging, (os.getenv("LOG_LEVEL", "WARNING").upper()))
    verbosity = min(2, verbosity)

    log_level = default_log_level - verbosity * 10

    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=log_level
    )


if __name__ == "__main__":
    # Parse the command-line arguments
    parser = argparse.ArgumentParser(
        description="Fetch private/public key pair from CSCS service "
        "using credentials stored in a password manager."
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=0,
        dest="verbosity",
        help="verbose output",
    )

    parser.add_argument(
        "--quiet",
        "-q",
        action="store_const",
        const=-1,
        default=0,
        dest="verbosity",
        help="silence all output except errors",
    )

    parser.add_argument(
        "--dry-run",
        "-n",
        action="store_true",
        help="log the actions without executing them",
    )

    subparser = parser.add_subparsers(
        title="subcommands",
        help="available subcommands",
        dest="command",
    )

    parser_fetch = subparser.add_parser(
        "fetch", help="fetch a new key pair from CSCS service"
    )

    parser_add = subparser.add_parser(
        "add", help="add an existing key pair to ssh-agent"
    )

    # 'fetch' subcommand arguments

    parser_fetch.add_argument(
        "backend",
        choices=["bw", "op", "bitwarden", "1password"],
        help="backend for your vault: Bitwarden or 1Password",
    )

    parser_fetch.add_argument(
        "item_id",
        help="item name or ID in your vault that contains the credentials (username, password, totp)",
    )

    parser_fetch.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="delete existing keys and fetch new ones",
    )

    args = parser.parse_args()

    # Logging
    setup_logging(args.verbosity)

    if args.dry_run:
        logging.info("Dry run mode enabled, no action will be executed.")

    # Set private/public key paths
    (dot_ssh_path := pl.Path.home() / ".ssh").mkdir(exist_ok=True)
    private_key_path = dot_ssh_path / "cscs-key"
    public_key_path = dot_ssh_path / "cscs-key-cert.pub"

    # If a key pair exists, try adding it to the agent then exit
    if args.command == "add":
        if private_key_path.exists() and public_key_path.exists():
            delta = timedelta(
                milliseconds=datetime.now().timestamp()
                - private_key_path.stat().st_ctime
            )
            if delta < timedelta(hours=24.0):
                logging.info("Valid private key found, adding it to ssh-agent...")
                if not args.dry_run:
                    add_key(private_key_path)
                print("Done.")
                sys.exit(0)
            else:
                logging.warning(
                    "Private key is older than 24 hours, please fetch a new one."
                )
                sys.exit(1)
        else:
            logging.error("No valid private key found.")
            sys.exit(1)

    elif args.command == "fetch":
        # Test if a keypair already exists
        if private_key_path.exists() or public_key_path.exists():
            if args.force:
                logging.warning("Deleting existing keys...")
                if not args.dry_run:
                    private_key_path.unlink(missing_ok=True)
                    public_key_path.unlink(missing_ok=True)
            else:
                logging.error(
                    "Key pair already exists. Use --force if you want to delete them."
                )
                sys.exit(1)

        # Create a new credentials helper
        CredsHelper = BWHelper if args.backend in ("bw", "bitwarden") else OPHelper
        vault = CredsHelper(item_name=args.item_id)

        # Get the credentials
        logging.info("Unlocking the vault and fetching credentials...")
        vault.unlock()
        credentials = vault.fetch_credentials()

        # Validate the credentials
        if not vault.are_credentials_valid():
            # TODO: catch which credential is not valid
            raise SystemExit("Credentials are not valid.")

        logging.info(
            "Fetching signed key from CSCS API and saving it to '%s'...",
            private_key_path.parent,
        )
        if not args.dry_run:
            private_key, public_key = get_keys_from_api(**credentials)

            if not (private_key or public_key):
                raise SystemExit("Could not fetch signed key from CSCS API.")

            save_key(private_key, private_key_path, "private")
            save_key(public_key, public_key_path, "public")

        logging.info("Done.")

        # TODO: set the passphrase on the private key

        if args.add:
            logging.info("Adding private key to ssh-agent...")
            if not args.dry_run:
                add_key(private_key_path)

    else:
        parser.print_help()

    sys.exit(0)
