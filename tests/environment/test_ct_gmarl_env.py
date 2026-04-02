import pytest
import numpy as np
from netforge_rl.environment.parallel_env import NetForgeRLEnv, MAX_ACTION_DURATION

def test_asynchronous_step_delta_t():
    """Verify that step() correctly jumps over idle time and returns normalized delta_t."""
    env = NetForgeRLEnv(scenario_config={'scenario_type': 'apt_espionage'})
    obs, infos = env.reset()
    
    # 1. Start an asynchronous action (e.g. Exploit) that takes 5 ticks
    # We need an action that has duration > 1. 
    # Let's mock a Blue action like 'IsolateHost' if it has a duration.
    # Or just use the red operator's exploit if duration is defined.
    
    # Initial tick = 0.
    # We'll queue a mock action with duration 10
    from netforge_rl.core.action import BaseAction, ActionEffect
    class MockLongAction(BaseAction):
        def __init__(self, agent_id):
            super().__init__(agent_id)
            self.duration = 10
            self.cost = 0
        def validate(self, state): return True
        def execute(self, state): return ActionEffect(True, {}, {})
    
    # Manually append to event_queue since we need to test the jump
    env.event_queue.append({
        'completion_tick': 10,
        'agent': 'blue_dmz',
        'action': MockLongAction('blue_dmz'),
        'effect': ActionEffect(True, {}, {}),
        'target_ip': '10.0.0.1'
    })
    
    # Step the environment with no new actions
    obs, rewards, terminate, truncate, infos = env.step({})
    
    # Expected: Jump to tick 10 (since it's the next event)
    assert env.current_tick == 10
    
    # delta_t = 10 - 0 = 10
    # delta_t_norm = 10 / 50 = 0.2
    for agent in env.possible_agents:
        assert 'delta_t' in infos[agent]
        assert infos[agent]['delta_t'] == 10.0
        assert 'delta_t_norm' in infos[agent]
        assert np.isclose(infos[agent]['delta_t_norm'], 0.2)
        
        # Check observation key
        assert 'delta_t' in obs[agent]
        assert np.isclose(obs[agent]['delta_t'][0], 0.2)

def test_subnet_filtering():
    """Verify that agents only see logs from their own subnets."""
    env = NetForgeRLEnv(scenario_config={'scenario_type': 'apt_espionage'})
    env.reset()
    
    # Push a log explicitly to the DMZ subnet
    env.siem_logger._push_to_buffer("DMZ_ALERT_XML", "192.168.1.0/24", env.global_state)
    # Push a log explicitly to the Internal subnet
    env.siem_logger._push_to_buffer("INTERNAL_ALERT_XML", "10.0.0.0/24", env.global_state)
    
    # Step the environment
    obs, rewards, terminate, truncate, infos = env.step({})
    
    # Blue DMZ agent should encode DMZ_ALERT_XML but NOT Internal
    # Since they are averaged/maxed, the embedding will be non-zero for both.
    # However, we can check the length of filtered logs inside SIEMLogger.
    
    dmz_logs = env.siem_logger.get_filtered_logs(env.global_state, subnet_tag='dmz')
    assert "DMZ_ALERT_XML" in dmz_logs
    assert "INTERNAL_ALERT_XML" not in dmz_logs
    
    internal_logs = env.siem_logger.get_filtered_logs(env.global_state, subnet_tag='internal')
    assert "INTERNAL_ALERT_XML" in internal_logs
    assert "DMZ_ALERT_XML" not in internal_logs

def test_green_agent_xml_fidelity():
    """Verify that GreenAgent produces XML-style strings."""
    from netforge_rl.agents.green_agent import GreenAgent
    from netforge_rl.core.state import GlobalNetworkState, Host, Subnet
    
    state = GlobalNetworkState()
    subnet = Subnet("192.168.1.0/24", "DMZ")
    state.add_subnet(subnet)
    host = Host("192.168.1.1", "Target", "192.168.1.0/24")
    state.register_host(host)
    
    ga = GreenAgent()
    # Force high probability of noise for testing
    import random
    random.seed(42)
    
    # Generate 100 samples to find at least one XML
    found_xml = False
    for _ in range(100):
        noise = ga.generate_noise(1, state)
        for alert in noise['alerts']:
            if '<Event' in alert['data'] and 'xmlns' in alert['data']:
                found_xml = True
                break
        if found_xml: break
    
    assert found_xml, "GreenAgent should have produced at least one XML encoded log."
