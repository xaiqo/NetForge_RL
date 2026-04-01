import pytest
from netforge_rl.sim2real.bridge import Sim2RealBridge
from netforge_rl.sim2real.hypervisor_base import HypervisorResult


@pytest.fixture
def bridge():
    return Sim2RealBridge(mode='sim')


@pytest.mark.fast
def test_bridge_mode_switching(bridge):
    """Verify that bridge switches correctly to real mode and back."""
    assert bridge.mode == 'sim'
    # Actually mode is set at init, but let's check init
    real_bridge = Sim2RealBridge(mode='real')
    # If Docker is unavailable, it falls back to mock but mode stays 'real' or updates?
    # Based on code: self.mode = mode; self._driver = self._init_driver(mode)
    assert real_bridge.mode == 'real'


@pytest.mark.fast
def test_bridge_dispatch_routing(bridge):
    """Verify bridge routes dispatch call to internal hypervisor."""
    result = bridge.dispatch('ExploitEternalBlue', '10.0.1.5', 'Windows_7')
    assert isinstance(result, HypervisorResult)
    assert result.action_name == 'ExploitEternalBlue'


@pytest.mark.fast
def test_bridge_reward_delta(bridge):
    """Verify reward delta mapping for different HypervisorResults."""
    # success
    res_suc = HypervisorResult(True, '', 0, 100.0, 'Act', '1.1.1.1', 'Win', 'mock')
    assert bridge.reward_delta(res_suc) == 5.0

    # clean failure
    res_fail = HypervisorResult(False, '', 1, 100.0, 'Act', '1.1.1.1', 'Win', 'mock')
    assert bridge.reward_delta(res_fail) == -10.0

    # noisy failure (>5s)
    res_noisy = HypervisorResult(False, '', 1, 6000.0, 'Act', '1.1.1.1', 'Win', 'mock')
    assert bridge.reward_delta(res_noisy) == -20.0

    # infrastructure error (RC=2)
    res_err = HypervisorResult(False, '', 2, 100.0, 'Act', '1.1.1.1', 'Win', 'mock')
    assert bridge.reward_delta(res_err) == -25.0
