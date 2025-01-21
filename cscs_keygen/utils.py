"""
Utils module
"""

import logging
import os
import shlex
import subprocess as sp
import sys
from typing import Optional

import requests
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class SSHKeyResponse(BaseModel):
    """Base model for SSH key response"""

    public: str = Field(..., description="Public key")
    private: str = Field(..., description="Private key")

    class Config:
        """Pydantic configuration"""

        frozen = True
        extra = "ignore"


def setup_logging(verbosity: int) -> None:
    """Setup logging"""
    # default: logging.WARNING
    default_log_level = getattr(logging, (os.getenv("LOG_LEVEL", "WARNING").upper()))
    verbosity = min(2, verbosity)

    log_level = default_log_level - verbosity * 10

    logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=log_level)


def run_command(cmd: str | list[str], *, capture: bool = True, check: bool = True, **kwargs) -> str | int:
    """Run a `cmd` and return the output or raise an exception"""
    text = bool(kwargs.get("text"))

    if isinstance(cmd, str) and sys.platform != "win32":
        cmd = shlex.split(cmd)

    try:
        output = sp.run(cmd, check=check, capture_output=capture, stdout=sp.DEVNULL if not capture else None, **kwargs)
    except sp.CalledProcessError as err:
        logger.error(
            "Error while running the command '%s': %s",
            " ".join(cmd),
            err.stderr if text else err.stderr.decode().strip(),
        )
        raise SystemExit(err.returncode) from err

    if capture:
        if text:
            return str(output.stdout)
        return output.stdout.decode()

    return output.returncode


def get_keys_from_api(username: str, password: str, totp: str) -> tuple[Optional[str], Optional[str]]:
    """Perform the API request to CSCS"""
    logger.info("Fetching signed key from CSCS API...")

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

        key_response = SSHKeyResponse.model_validate(response.json())
    except requests.exceptions.HTTPError as err:
        try:
            message = err.response.json()
        except Exception:
            raise SystemExit(1) from err

        if "payload" in message and "message" in message["payload"]:
            logger.error(f"Error: {message['payload']}")
            sys.exit(1)
    else:
        return key_response.private, key_response.public

    return None, None
