"""
A credentials helper class for Bitwarden and 1Password
"""
import json
import os
import re
from abc import ABC, abstractmethod
from typing import Dict, NoReturn

from attr import define, field, validators
from utils import run_command


class CredentialsHelperError(Exception):
    """Base exception for credentials helper"""


@define
class CredsHelper(ABC):
    """A base class for password managers"""

    backend: str = field(validator=validators.in_(["bw", "op"]))
    backend_token: str = field(init=False)
    backend_name: str = field(init=False)
    item_name: str = ""
    _is_unlocked: bool = False
    __credentials: dict = field(factory=dict, init=False)

    def __attrs_post_init__(self) -> None:
        if self.backend == "bw":
            self.backend_token = "BW_SESSION"
            self.backend_name = "Bitwarden"
        elif self.backend == "op":
            self.backend_token = "OP_SERVICE_ACCOUNT_TOKEN"
            self.backend_name = "1Password"

    @property
    def credentials(self) -> Dict[str, str]:
        """Fetch and return credentials dictionary"""
        return self.__credentials

    @credentials.setter
    def credentials(self, _) -> NoReturn:
        msg = "Credentials cannot be set manually."
        raise CredentialsHelperError(msg)

    @property
    def is_unlocked(self) -> bool:
        """Check if the vault is unlocked"""
        return self._is_unlocked

    @is_unlocked.setter
    def is_unlocked(self, _) -> NoReturn:
        msg = f"You must login or unlock {self.backend_name} first."
        raise CredentialsHelperError(msg)

    def are_credentials_valid(self) -> bool:
        """Validate credentials"""
        if not self.credentials:
            return False

        return all(
            (
                re.match(r"^[a-z0-9_-]{2,15}$", self.credentials.get("username", "")),
                self.credentials.get("password"),
                re.match(r"^[0-9]{6}$", self.credentials.get("totp", "")),
            )
        )

    @abstractmethod
    def unlock(self) -> None:
        """Unlock the vault"""

    @abstractmethod
    def fetch_credentials(self) -> Dict[str, str]:
        """Fetch the credentials from the vault"""


class BWHelper(CredsHelper):
    """Bitwarden credentials helper"""

    def __init__(self, **kwargs):
        super().__init__(backend="bw", **kwargs)

    def unlock(self) -> None:
        if not self.is_unlocked:
            self._is_unlocked = bool(os.getenv(self.backend_token))

    def fetch_credentials(self) -> Dict[str, str]:
        """Fetch the credentials from Bitwarden vault"""
        if not self.is_unlocked:
            msg = f"{self.backend_name} vault is locked or you never logged in."
            raise CredentialsHelperError(msg)

        if not self.item_name:
            msg = "Bitwarden item's ID or name must be provided."
            raise ValueError(msg)

        for __field in ("username", "password", "totp"):
            self.credentials[__field] = str(
                run_command(f'bw get {__field} "{self.item_name}" --raw', text=True)
            ).strip()

        return self.credentials


class OPHelper(CredsHelper):
    """1Password credentials helper"""

    def __init__(self, **kwargs):
        super().__init__(backend="op", **kwargs)

    def unlock(self) -> None:
        if not self.is_unlocked:
            if os.getenv(self.backend_token) or run_command("op signin", capture=False) == 0:
                self._is_unlocked = True

    def fetch_credentials(self) -> Dict[str, str]:
        """Fetch the credentials from 1Password vault"""
        if not self.is_unlocked:
            msg = f"{self.backend_name} vault is locked or you never logged in."
            raise CredentialsHelperError(msg)

        if not self.item_name:
            msg = "1Password item's name must be provided."
            raise TypeError(msg)

        creds = json.loads(
            str(
                run_command(
                    f'op item get "{self.item_name}" --format json --fields label=username,password,totp',
                    text=True,
                )
            )
        )

        try:
            self.credentials["username"] = creds[0]["value"]
            self.credentials["password"] = creds[1]["value"]
            self.credentials["totp"] = creds[2]["totp"]
        except (IndexError, KeyError) as err:
            msg = f"Failed to fetch {self.backend_name} credentials."
            raise CredentialsHelperError(msg) from err

        return self.credentials
