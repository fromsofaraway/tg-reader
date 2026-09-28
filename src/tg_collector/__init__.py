"""tg-collector: export Telegram support chats and anonymize them for LLM use."""

__version__ = "0.1.0"

from .cli import main

__all__ = ["main", "__version__"]
