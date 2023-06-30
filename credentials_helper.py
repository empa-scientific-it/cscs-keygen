"""
A credentials helper class for Bitwarden and 1Password
"""
import os
from attr import define, field, validators


@define
class CredsHelper:
    """An helper class for credentials stored in Bitwarden or 1Password"""

    backend: str = field(validator=validators.in_(["bw", "op"]))
    item_name: str = None
    item_id: str = field(
        default=None,
        validator=validators.matches_re(r"[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}"),
    )
    logged_in: bool = False

    def is_logged_in(self) -> bool:
        """Check if the backend is logged in"""
        if self.logged_in:
            return True

        if self.backend == "bw":
            env_var = "BW_SESSION"

        if self.backend == "op":
            env_var = "OP_SERVICE_ACCOUNT_TOKEN"

        self.logged_in = bool(os.getenv(env_var))

        return self.logged_in

    def get_credentials(self) -> tuple[str]:
        """Fetch the credentials"""
