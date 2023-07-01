"""
A credentials helper class for Bitwarden and 1Password
"""
import json
import os
import re

from attr import define, field, validators

from utils import run_command


@define
class CredsHelper:
    """A base abstract class for password managers"""

    backend: str = field(validator=validators.in_(["bw", "op"]))
    backend_token: str = field(init=False)
    backend_name: str = field(init=False)
    creds: dict = field(factory=dict)
    item_name: str = None
    item_id: str = None
    logged_in: bool = False

    def __attrs_post_init__(self) -> None:
        if self.backend == "bw":
            self.backend_token = "BW_SESSION"
            self.backend_name = "Bitwarden"
        elif self.backend == "op":
            self.backend_token = "OP_SERVICE_ACCOUNT_TOKEN"
            self.backend_name = "1Password"

    def is_logged_in(self) -> bool:
        """Check if the backend is logged in"""
        if self.logged_in:
            return True

        self.logged_in = bool(os.getenv(self.backend_token))

        return self.logged_in

    def are_creds_valid(self) -> bool:
        """Validate credentials"""
        if not self.creds:
            return False

        return (
            re.match(r"^[a-z0-9_-]{2,15}$", self.creds["username"])
            and self.creds["password"]
            and re.match(r"^[0-9]{6}$", self.creds["totp"])
        )

    def fetch_credentials(self) -> None:
        """Fetch the credentials from backend's vault"""
        if not self.is_logged_in():
            raise RuntimeError(
                f"{self.backend_name} vault is locked or you never logged in."
            )

    def get_credentials(self) -> tuple[str]:
        """Fetch and return credentials as strings"""
        self.fetch_credentials()

        if self.are_creds_valid():
            return self.creds["username"], self.creds["password"], self.creds["totp"]

        raise RuntimeError("Credentials are invalid.")


class BWHelper(CredsHelper):
    """Bitwarden credentials helper"""

    def fetch_credentials(self) -> None:
        """Fetch the credentials from Bitwarden vault"""
        super().fetch_credentials()

        __item = self.item_id or self.item_name

        if not __item:
            raise ValueError("Either item's ID or name must be provided.")

        for __field in ("username", "password", "totp"):
            self.creds[__field] = run_command(
                f'bw get {__field} "{__item}" --raw', text=True
            ).strip()


class OPHelper(CredsHelper):
    """1Password credentials helper"""

    def fetch_credentials(self) -> None:
        """Fetch the credentials from 1Password vault"""
        super().fetch_credentials()

        if not self.item_name:
            raise TypeError("1Password item's name must be provided.")

        creds = json.loads(
            run_command(
                f'op item get "{self.item_name}" --format json --fields label=username,password,totp',
                text=True,
            )
        )

        self.creds["username"] = creds[0]["value"]
        self.creds["password"] = creds[1]["value"]
        self.creds["totp"] = creds[2]["totp"]
