from datetime import datetime
from enum import IntEnum
from functools import wraps
from typing import Any, Callable, Optional, TypeVar

from rich.console import Console
from rich.status import Status
from rich.text import Text
from rich.theme import Theme

F = TypeVar("F", bound=Callable[..., Any])


class LogLevel(IntEnum):
    ERROR = 0
    WARNING = 1
    INFO = 2
    DEBUG = 3


class BaseLogger:
    """Base logger class."""

    def __init__(self) -> None:
        self.verbosity = 0

    def set_verbosity(self, level: int) -> None:
        level = min(3, level)
        self.verbosity = level

    def _should_log(self, level: LogLevel) -> bool:
        return self.verbosity >= level

    @staticmethod
    def should_log(level: LogLevel) -> Callable[[F], F]:
        def decorator(func: F) -> F:
            @wraps(func)
            def wrapper(self: "BaseLogger", *args: Any, **kwargs: Any) -> Any:
                if self._should_log(level):
                    return func(self, *args, **kwargs)
                return None

            return wrapper  # type: ignore

        return decorator


class Logger(BaseLogger):
    """A pretty logger for CSCS Keygen using Rich."""

    _instance: Optional["Logger"] = None

    def __new__(cls) -> "Logger":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not hasattr(self, "console"):
            self.theme = Theme(
                {
                    "info": "cyan",
                    "success": "green",
                    "warning": "yellow",
                    "error": "red",
                    "debug": "dim purple",
                    "timestamp": "dim cyan",
                }
            )

            self.console = Console(theme=self.theme)
            self._status: Optional[Status] = None

    def _get_timestamp(self) -> Text:
        """Return formatted timestamp."""
        return Text(f"[{datetime.now().strftime('%H:%M:%S')}]", style="timestamp")

    def success(self, message: str) -> None:
        """Log a success message."""
        self.console.print(
            self._get_timestamp(),
            Text("✅ ", style="success"),
            Text(message, style="success"),
        )

    @BaseLogger.should_log(LogLevel.INFO)
    def info(self, message: str) -> None:
        """Log an info message."""
        self.console.print(
            self._get_timestamp(), Text("ℹ️ ", style="info"), Text(message)
        )

    @BaseLogger.should_log(LogLevel.WARNING)
    def warning(self, message: str) -> None:
        """Log a warning message."""
        self.console.print(
            self._get_timestamp(),
            Text("⚠️ ", style="warning"),
            Text(message, style="warning"),
        )

    @BaseLogger.should_log(LogLevel.ERROR)
    def error(self, message: str, exc: Optional[Exception] = None) -> None:
        """Log an error message."""
        self.console.print(
            self._get_timestamp(),
            Text("❌ ", style="error"),
            Text(message, style="error"),
        )

        if exc:
            self.console.print(
                Text("   ↳ ", style="error"),
                Text(f"{exc.__class__.__name__}: {exc!s}", style="error"),
            )

    @BaseLogger.should_log(LogLevel.DEBUG)
    def debug(self, message: str) -> None:
        """Log a debug message."""
        self.console.print(
            self._get_timestamp(),
            Text("🐞 ", style="debug"),
            Text(message, style="debug"),
        )

    def start_status(self, message: str) -> None:
        """Start a status spinner."""
        if self._status is None:
            self._status = self.console.status(message, spinner="dots")
            self._status.start()

    def stop_status(self) -> None:
        """Stop the status spinner."""
        if self._status:
            self._status.stop()
            self._status = None


# Singleton instance
logger = Logger()
