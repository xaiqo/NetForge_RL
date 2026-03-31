"""
NetForge_RL Sim2Real Package.

Provides a dual-mode hypervisor bridge for connecting the MARL environment
to either a lightweight MockHypervisor (for fast RL training) or a live
DockerHypervisor (for high-fidelity evaluation runs).
"""
from netforge_rl.sim2real.hypervisor_base import BaseHypervisor, HypervisorResult
from netforge_rl.sim2real.mock_hypervisor import MockHypervisor
from netforge_rl.sim2real.bridge import Sim2RealBridge

__all__ = [
    'BaseHypervisor',
    'HypervisorResult',
    'MockHypervisor',
    'Sim2RealBridge',
]
