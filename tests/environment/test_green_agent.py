import pytest
from netforge_rl.agents.green_agent import GreenAgent
from netforge_rl.core.state import GlobalNetworkState, Host

@pytest.fixture
def green_agent():
    return GreenAgent()

@pytest.mark.fast
def test_green_agent_generate_noise_day(green_agent, global_state):
    """Verify that GreenAgent generates noise during the day (tick 0)."""
    # Tick 0 is day
    noise = green_agent.generate_noise(0, global_state)
    assert 'alerts' in noise
    # Since it's probabilistic, we might get 0 or more, but we check if it runs without error
    for alert in noise['alerts']:
        assert 'type' in alert
        assert 'severity' in alert

@pytest.mark.fast
def test_green_agent_generate_noise_night(green_agent, global_state):
    """Verify that GreenAgent generates noise during the night (tick 110)."""
    # Tick 110 is night
    noise = green_agent.generate_noise(110, global_state)
    assert 'alerts' in noise
    # In night, activity should be lower, but still valid structure
    for alert in noise['alerts']:
        assert 'type' in alert

@pytest.mark.fast
def test_green_agent_empty_hosts(green_agent):
    """Verify that GreenAgent handles empty host list gracefully."""
    mock_state = type('MockState', (), {'all_hosts': {}})()
    noise = green_agent.generate_noise(0, mock_state)
    assert noise == {'alerts': []}

@pytest.mark.fast
def test_green_agent_cycle_positions(green_agent, global_state):
    """Verify Day/Night logic across cycle thresholds."""
    # Day
    noise_day = green_agent.generate_noise(100, global_state)
    # Night
    noise_night = green_agent.generate_noise(101, global_state)
    # Both should be valid
    assert isinstance(noise_day['alerts'], list)
    assert isinstance(noise_night['alerts'], list)
