import pytest
from netforge_rl.sim2real.hypervisor_base import HypervisorResult
from netforge_rl.sim2real.mock_hypervisor import MockHypervisor


@pytest.fixture
def mock_hvr():
    # Use a high seed to ensure consistency if possible, or just seed 42
    return MockHypervisor(seed=42)


@pytest.mark.fast
def test_mock_hypervisor_dispatch(mock_hvr):
    """Verify that dispatch returns a HypervisorResult with stdout."""
    result = mock_hvr.dispatch('ExploitEternalBlue', '10.0.1.5', 'Windows_Server_2016')

    assert isinstance(result, HypervisorResult)
    assert result.action_name == 'ExploitEternalBlue'
    assert result.latency_ms > 0
    # Success depends on seed 42. In mock_hypervisor with seed 42:
    # _roll_success(ExploitEternalBlue, Windows_Server_2016)
    # rate 0.72 + penalty 0.0 = 0.72.
    # random.Random(42).random() is ~0.639. 0.639 < 0.72 is True.
    assert result.success is True
    assert result.return_code == 0


@pytest.mark.fast
def test_mock_hypervisor_os_penalty(mock_hvr):
    """Verify that wrong OS lowers success chance (stochastically)."""
    # EternalBlue against Linux should fail.
    # rate 0.72 + penalty -0.60 = 0.12.
    # seed 42 random is 0.639. 0.639 < 0.12 is False.
    result = mock_hvr.dispatch('ExploitEternalBlue', '10.0.1.5', 'Linux_Ubuntu')

    assert result.success is False
    assert result.return_code == 1


@pytest.mark.fast
def test_mock_hypervisor_unknown_action(mock_hvr):
    """Verify unknown actions return failure."""
    result = mock_hvr.dispatch('UnknownAction', '10.0.0.1', 'Windows')
    # Base rate for unknown is 0.50. 0.639 < 0.50 is False.
    assert result.success is False
    assert 'UnknownAction failed' in result.stdout
    assert result.return_code == 1
