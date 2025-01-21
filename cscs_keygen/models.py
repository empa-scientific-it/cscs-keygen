"""Models for the cscs-keygen package"""

import logging
import pathlib as pl

from attr import define, field

from cscs_keygen.utils import run_command

logger = logging.getLogger(__name__)


@define
class Key:
    """Class to store a single key"""

    path: pl.Path = field(converter=pl.Path)
    _type: str
    _content: str = field(default="")
    _fingerprint: str = field(default="")
    _c_time: float = field(default=0.0)

    def __attrs_post_init__(self) -> None:
        """Post init hook"""
        if self._type not in ("private", "public"):
            msg = "Key type must be 'private' or 'public'"
            raise ValueError(msg)

    @property
    def content(self) -> str:
        """Return the key content"""
        return self._content

    @content.setter
    def content(self, value: str) -> None:
        """Set the key content"""
        self._content = value

    @property
    def fingerprint(self) -> str:
        """Return the key fingerprint"""
        if not self._fingerprint:
            _key_abs_path = self.path.expanduser().resolve()
            self._fingerprint = str(run_command(f"ssh-keygen -lf {_key_abs_path}", capture=True)).strip().split()[1]

        return self._fingerprint

    @fingerprint.setter
    def fingerprint(self, _: str) -> None:
        msg = "Cannot set the fingerprint"
        raise AttributeError(msg)

    @property
    def c_time(self) -> float:
        """Return the key creation time"""
        if self.path.exists() and not self._c_time:
            self._c_time = self.path.stat().st_ctime

        return self._c_time

    @c_time.setter
    def c_time(self, _: float) -> None:
        msg = "Cannot set the creation time"
        raise AttributeError(msg)

    def exists(self) -> bool:
        """Check if the key exists"""
        if self.path.exists():
            self.content = self.path.read_text()
            return True
        return False

    def delete(self) -> None:
        """Delete the key"""
        self.path.unlink(missing_ok=True)

    def save(self) -> None:
        """Save a key file to disk and set the right permissions"""
        if not self.content:
            msg = f"Error: could not save {self._type} key to {self.path}: key content is invalid."
            logger.error(msg)
            raise TypeError(msg)

        try:
            self.path.write_text(self.content)
        except OSError as err:
            logger.error(f"Error: could not write {self._type} key to {self.path}")
            raise SystemExit(1) from err

        try:
            if self._type == "private":
                self.path.chmod(0o600)
            elif self._type == "public":
                self.path.chmod(0o644)
        except PermissionError as err:
            logger.error(f"Error: could not set permissions on key {self.path}")
            raise SystemExit(1) from err


@define
class Keys:
    """Class to store private and public keys"""

    dot_ssh_path: pl.Path = pl.Path.home() / ".ssh"
    private_key: Key = field(init=False)
    public_key: Key = field(init=False)

    def __attrs_post_init__(self) -> None:
        """Set private/public key paths"""
        self.dot_ssh_path.mkdir(exist_ok=True)
        self.private_key = Key(self.dot_ssh_path / "cscs-key", "private")
        self.public_key = Key(self.dot_ssh_path / "cscs-key-cert.pub", "public")

    def exist(self) -> bool:
        """Check if the key pair exists"""
        return self.private_key.exists() or self.public_key.exists()

    def delete(self) -> None:
        """Delete the key pair"""
        self.private_key.delete()
        self.public_key.delete()

    def save(self) -> None:
        """Save the keys to the filesystem"""
        self.private_key.save()
        self.public_key.save()


@define
class State:
    """Helper class to store the state of the application"""

    keys: Keys = field(factory=Keys)
    verbose: int = 0
    dry_run: bool = False
