"""Settings read from the environment (or a .env file). Safe defaults for development."""
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[2]  # the repository root


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ROOT / ".env", extra="ignore")

    env: str = "development"
    secret_key: str = "dev-only-change-me"
    # SQLite while developing; docker-compose sets this to PostgreSQL.
    database_url: str = f"sqlite:///{(ROOT / 'data' / 'ainidr.db').as_posix()}"
    model_dir: Path = ROOT / "models"

    # The only addresses the system may ever block (FR-31).
    monitored_network: str = "192.168.56.0/24"

    access_token_minutes: int = 15
    session_minutes: int = 30  # FR-06

    # "dry_run" records what would be done; "ssh" drives nftables on the protected hosts.
    firewall_mode: str = "dry_run"
    firewall_hosts: str = ""      # comma-separated, e.g. "responder@192.168.56.20"
    firewall_ssh_key: str = ""    # path to the private key of the restricted account


@lru_cache
def get_settings() -> Settings:
    return Settings()
