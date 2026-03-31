"""
Sim2RealBridge — single integration point between the action system and hypervisors.

Responsibilities:
  1. Instantiate the correct driver based on mode ('sim' / 'real').
  2. Expose dispatch() to action execute() methods.
  3. Translate HypervisorResult into a reward delta for the ConflictResolutionEngine.
  4. Expose teardown_all() for episode resets.
"""
from __future__ import annotations

import logging
from typing import Literal

from netforge_rl.sim2real.hypervisor_base import BaseHypervisor, HypervisorResult

logger = logging.getLogger(__name__)

_REWARD_DELTA: dict[str, float] = {
    # Successful shell — standard scenario reward handles the bulk;
    # small bonus here to separate true exploitation from lucky rolls.
    'success': +5.0,
    # Clean failure — exploit attempted but target not vulnerable / patched.
    'failure_clean': -10.0,
    # Noisy failure with high latency — burn time and increase SIEM visibility.
    'failure_noisy': -20.0,
    # Container/infrastructure error — punishment for choosing an incompatible action.
    'failure_error': -25.0,
}

_NOISY_LATENCY_THRESHOLD_MS = 5000.0  # Longer than this = "noisy" failure


class Sim2RealBridge:
    """
    Dual-mode bridge connecting MARL actions to the hypervisor backend.

    Usage:
        bridge = Sim2RealBridge(mode='sim')   # training default
        bridge = Sim2RealBridge(mode='real')  # evaluation with Docker

        result = bridge.dispatch('ExploitEternalBlue', '10.0.1.3', 'Windows_Server_2016')
        reward_delta = bridge.reward_delta(result)
    """

    def __init__(self, mode: Literal['sim', 'real'] = 'sim') -> None:
        self.mode = mode
        self._driver: BaseHypervisor = self._init_driver(mode)

    def dispatch(
        self,
        action_name: str,
        target_ip: str,
        target_os: str,
    ) -> HypervisorResult:
        """Execute payload; auto-fallback to mock if real driver is down."""
        result = self._driver.dispatch(action_name, target_ip, target_os)
        logger.debug('Sim2RealBridge: %s', result)
        return result

    def reward_delta(self, result: HypervisorResult) -> float:
        """
        Map a HypervisorResult to an immediate scalar reward delta.

        This is *additive* on top of the scenario's standard reward — it
        represents additional friction from real-world exploit reliability.
        """
        if result.success:
            return _REWARD_DELTA['success']
        elif result.return_code == 2:
            # Container/infrastructure error
            return _REWARD_DELTA['failure_error']
        elif result.latency_ms >= _NOISY_LATENCY_THRESHOLD_MS:
            return _REWARD_DELTA['failure_noisy']
        else:
            return _REWARD_DELTA['failure_clean']

    def teardown_all(self) -> None:
        """Destroy all active containers/sessions — call at episode end."""
        self._driver.teardown_all()

    def is_available(self) -> bool:
        return self._driver.is_available()

    def _init_driver(self, mode: str) -> BaseHypervisor:
        if mode == 'real':
            from netforge_rl.sim2real.docker_hypervisor import DockerHypervisor

            driver = DockerHypervisor()
            if not driver.is_available():
                logger.warning(
                    'Sim2RealBridge: real mode requested but Docker unavailable. '
                    'Falling back to mock hypervisor.'
                )
                from netforge_rl.sim2real.mock_hypervisor import MockHypervisor

                return MockHypervisor()
            return driver

        # Default: sim / mock
        from netforge_rl.sim2real.mock_hypervisor import MockHypervisor

        return MockHypervisor()
