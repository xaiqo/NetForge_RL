import pytest
from unittest.mock import MagicMock, patch
from netforge_rl.sim2real.bridge import Sim2RealBridge
from netforge_rl.sim2real.mock_hypervisor import MockHypervisor


@pytest.mark.fast
def test_bridge_fallback_on_docker_failure():
    """Verify Sim2RealBridge falls back to Mock if Docker is unavailable."""
    # Patch Docker's is_available to return False
    with patch(
        'netforge_rl.sim2real.docker_hypervisor.DockerHypervisor.is_available',
        return_value=False,
    ):
        bridge = Sim2RealBridge(mode='real')
        # Check if the internal driver is actually a MockHypervisor
        assert isinstance(bridge._driver, MockHypervisor)
        assert bridge.mode == 'real'  # Mode stays 'real' but driver is mock


@pytest.mark.fast
def test_bridge_reward_mapping_success():
    """Verify success results map to positive reward delta."""
    bridge = Sim2RealBridge(mode='sim')
    mock_result = MagicMock()
    mock_result.success = True

    assert bridge.reward_delta(mock_result) == 5.0


@pytest.mark.fast
def test_bridge_reward_mapping_noisy_failure():
    """Verify high-latency failures map to noisy punishment."""
    bridge = Sim2RealBridge(mode='sim')
    mock_result = MagicMock()
    mock_result.success = False
    mock_result.return_code = 1
    mock_result.latency_ms = 6000.0  # > 5000 threshold

    assert bridge.reward_delta(mock_result) == -20.0


@pytest.mark.fast
def test_bridge_reward_mapping_infra_error():
    """Verify infrastructure errors (RC 2) map to maximum punishment."""
    bridge = Sim2RealBridge(mode='sim')
    mock_result = MagicMock()
    mock_result.success = False
    mock_result.return_code = 2  # Error

    assert bridge.reward_delta(mock_result) == -25.0
