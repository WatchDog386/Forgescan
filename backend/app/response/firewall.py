"""Firewalls behind one interface, so the response engine does not care which one it drives (SDS 6.6)."""
import ipaddress
import logging
import subprocess
from abc import ABC, abstractmethod

log = logging.getLogger(__name__)


class FirewallError(Exception):
    pass


class Firewall(ABC):
    @abstractmethod
    def block(self, ip: str, minutes: int) -> None: ...

    @abstractmethod
    def unblock(self, ip: str) -> None: ...


class DryRunFirewall(Firewall):
    """Changes nothing. Used in development and while automatic response is being tested."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, int]] = []

    def block(self, ip: str, minutes: int) -> None:
        self.calls.append(("block", ip, minutes))
        log.info("dry run: would block %s for %s minutes", ip, minutes)

    def unblock(self, ip: str) -> None:
        self.calls.append(("unblock", ip, 0))
        log.info("dry run: would release %s", ip)


class NftablesSshFirewall(Firewall):
    """Drives nftables on each protected host over SSH.

    The account on the host may run only lab/response-agent.sh (NFR-11). The address is
    checked here and again by the agent, and is passed as an argument, never through a shell.
    """

    def __init__(self, hosts: list[str], key_path: str, timeout: int = 5) -> None:
        self.hosts, self.key_path, self.timeout = hosts, key_path, timeout

    def _run(self, *args: str) -> None:
        for host in self.hosts:
            command = ["ssh", "-i", self.key_path, "-o", "BatchMode=yes", "-o", f"ConnectTimeout={self.timeout}", host, *args]
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=self.timeout + 3)
            except (subprocess.TimeoutExpired, OSError) as error:
                raise FirewallError(f"{host} could not be reached: {error}") from None
            if result.returncode != 0:
                raise FirewallError(f"{host} refused the command: {result.stderr.strip()[:120]}")

    def block(self, ip: str, minutes: int) -> None:
        self._run("block", str(ipaddress.ip_address(ip)), str(int(minutes)))

    def unblock(self, ip: str) -> None:
        self._run("unblock", str(ipaddress.ip_address(ip)))
