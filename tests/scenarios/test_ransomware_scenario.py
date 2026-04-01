import pytest
from netforge_rl.scenarios.ransomware import RansomwareScenario
from netforge_rl.core.state import GlobalNetworkState, Host
from netforge_rl.core.action import ActionEffect

@pytest.fixture
def scenario():
    return RansomwareScenario(agents=['red_operator', 'blue_operator'])

@pytest.fixture
def global_state():
    state = GlobalNetworkState()
    state.register_host(Host(ip="10.0.0.5", hostname="WebSrv", subnet_cidr="10.0.0.0/24"))
    state.register_host(Host(ip="10.0.0.10", hostname="DB", subnet_cidr="10.0.0.0/24"))
    return state

@pytest.mark.fast
def test_scenario_blue_rewards(scenario, global_state):
    """Test all bonus branches in Blue reward logic."""
    agent = "blue_operator"
    
    # 1. Successful Isolation of compromised host
    global_state.all_hosts["10.0.0.5"].compromised_by = "red_operator"
    effect = ActionEffect(
        success=True,
        state_deltas={"hosts/10.0.0.5/status": "isolated"},
        observation_data={}
    )
    r1 = scenario.calculate_reward(agent, global_state, effect)
    assert r1 > 0  # Should get bonus for correct isolation
    
    # 2. False Positive Isolation
    global_state.all_hosts["10.0.0.10"].compromised_by = "None"
    effect = ActionEffect(
        success=True,
        state_deltas={"hosts/10.0.0.10/status": "isolated"},
        observation_data={}
    )
    r2 = scenario.calculate_reward(agent, global_state, effect)
    assert r2 < 0  # Should get penalty for isolating clean host

    # 3. Restoration bonus
    effect = ActionEffect(
        success=True,
        state_deltas={"hosts/10.0.0.5/status": "online"},
        observation_data={}
    )
    r3 = scenario.calculate_reward(agent, global_state, effect)
    assert r3 > 0

@pytest.mark.fast
def test_scenario_red_rewards(scenario, global_state):
    """Test Red reward branches."""
    agent = "red_operator"
    
    # Privilege escalation bonus
    effect = ActionEffect(
        success=True,
        state_deltas={"hosts/10.0.0.5/privilege": "Root"},
        observation_data={}
    )
    r = scenario.calculate_reward(agent, global_state, effect)
    assert r >= 5.0
    
    # Integrity impact bonus
    effect = ActionEffect(
        success=True,
        state_deltas={"hosts/10.0.0.5/system_integrity": "compromised"},
        observation_data={}
    )
    r = scenario.calculate_reward(agent, global_state, effect)
    assert r >= 10.0

@pytest.mark.fast
def test_scenario_observation_rewards(scenario, global_state):
    """Test discovery and scan rewards."""
    agent = "red_operator"
    
    # Discovery bonus
    effect = ActionEffect(
        success=True,
        state_deltas={},
        observation_data={"discovered_hosts": ["10.0.0.20", "10.0.0.30"]}
    )
    r = scenario.calculate_reward(agent, global_state, effect)
    assert r > 0
    
    # Scan bonus
    effect = ActionEffect(
        success=True,
        state_deltas={},
        observation_data={"scan_results": {"port_80": "open"}}
    )
    r = scenario.calculate_reward(agent, global_state, effect)
    assert r > 0

@pytest.mark.fast
def test_scenario_failed_action_penalty(scenario, global_state):
    """Verify that failed actions receive a penalty."""
    effect = ActionEffect(success=False, state_deltas={}, observation_data={})
    r = scenario.calculate_reward("red_operator", global_state, effect)
    assert r < 0
