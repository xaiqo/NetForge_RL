"""
Abstract base for all hypervisor drivers.

Defines the HypervisorResult dataclass and the BaseHypervisor interface
that both MockHypervisor and DockerHypervisor must implement.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class HypervisorResult:
    """
    Encapsulates the raw outcome of a payload dispatched against a target.

    Both mock and real Docker drivers return this object so that the
    Sim2RealBridge can translate the outcome into environment reward deltas
    and SIEM telemetry strings in a uniform way.
    """

    success: bool
    stdout: str
    return_code: int
    latency_ms: float
    action_name: str
    target_ip: str
    target_os: str
    container_id: str = field(default='mock')  # Real DockerHypervisor populates this

    def __repr__(self) -> str:
        status = 'SUCCESS' if self.success else 'FAILED'
        return (
            f'<HypervisorResult [{status}] {self.action_name} → {self.target_ip} '
            f'({self.target_os}) | RC={self.return_code} | {self.latency_ms:.1f}ms>'
        )


class BaseHypervisor(ABC):
    """
    Abstract hypervisor driver interface.

    Implementations must provide:
    - dispatch(): Execute a payload against a target, return HypervisorResult.
    - teardown_all(): Clean up any active containers / resources on episode reset.
    """

    @abstractmethod
    def dispatch(
        self,
        action_name: str,
        target_ip: str,
        target_os: str,
    ) -> HypervisorResult:
        """
        Dispatch a named payload action against a target host.

        Args:
            action_name: Name of the action class (e.g. 'ExploitEternalBlue').
            target_ip:   Target host IP address.
            target_os:   OS profile of the target (e.g. 'Windows_Server_2016').

        Returns:
            HypervisorResult with success/stdout/return_code populated.
        """
        ...

    @abstractmethod
    def teardown_all(self) -> None:
        """
        Destroy all active execution contexts (containers, sessions).
        Called at episode end to prevent resource leaks.
        """
        ...

    def is_available(self) -> bool:
        """
        Indicate whether this hypervisor driver is operational.
        Override in concrete drivers to perform live connectivity checks.
        """
        return True
