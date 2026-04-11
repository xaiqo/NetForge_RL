import pytest
from unittest.mock import patch
from netforge_rl.environment.parallel_env import NetForgeRLEnv
from netforge_rl.actions.red.exploits import ExploitEternalBlue
from netforge_rl.core.action import ActionEffect


@pytest.fixture
def env(env_config):
    env = NetForgeRLEnv(env_config)
    env.reset(seed=42)
    return env


class MagicMockAction:
    def __init__(self, cost=1, duration=1):
        self.cost = cost
        self.duration = duration
        self.target_ip = '1.2.3.4'

    def validate(self, state):
        return True

    def execute(self, state):
        return ActionEffect(success=True, state_deltas={}, observation_data={})


@pytest.mark.fast
def test_soc_budget_limit(env):
    """Verify that SOC (Blue) is limited to 2 active actions."""
    env.reset(seed=42)
    agent = 'blue_dmz'
    env.global_state.agent_energy[agent] = 50

    # Manually fill the queue with 2 agents
    env.event_queue.append(
        {
            'completion_tick': 10,
            'agent': 'blue_internal',
            'action': MagicMockAction(),
            'effect': ActionEffect(success=True, state_deltas={}, observation_data={}),
            'target_ip': None,
        }
    )
    env.event_queue.append(
        {
            'completion_tick': 10,
            'agent': 'blue_restricted',
            'action': MagicMockAction(),
            'effect': ActionEffect(success=True, state_deltas={}, observation_data={}),
            'target_ip': None,
        }
    )

    # Attempt to add a 3rd action via step
    initial_energy = env.global_state.agent_energy[agent]
    env.step({agent: 0})

    # Reward/Energy check: 3rd action should be ignored, so energy should not decrease
    assert env.global_state.agent_energy[agent] == initial_energy
    # Queue should be empty now because the 2 original resolved at tick 10
    assert len(env.event_queue) == 0


@pytest.mark.fast
def test_agent_energy_exhaustion(env):
    """Verify that actions are skipped if agent energy is insufficient."""
    env.reset(seed=42)
    agent = 'red_operator'
    env.global_state.agent_energy[agent] = 2

    env.step({agent: 0})
    assert len([e for e in env.event_queue if e['agent'] == agent]) == 0


@pytest.mark.fast
def test_dhcp_reallocation(env):
    """Verify that DHCP reallocation triggers every 40 ticks."""
    env.reset(seed=42)
    initial_ips = set(env.global_state.all_hosts.keys())

    for _ in range(40):
        env.step({})

    new_ips = set(env.global_state.all_hosts.keys())
    assert initial_ips != new_ips


@pytest.mark.fast
def test_honeytoken_trap_alert(env):
    """Verify that hitting a honeytoken generates high-severity alert."""
    env.reset(seed=42)
    agent = 'red_operator'

    # 1. Setup a honeytoken host
    # Choose a valid host from the DMZ (192.168.1.0/24)
    target_ip = next(
        ip
        for ip, h in env.global_state.all_hosts.items()
        if h.subnet_cidr == '192.168.1.0/24'
    )
    host = env.global_state.all_hosts[target_ip]
    host.contains_honeytokens = True
    host.vulnerabilities = ['MS17-010']

    # Ensure the red agent has some foothold to allow routing
    env.global_state.agent_knowledge[agent] = {target_ip}
    env.global_state.action_history[agent] = {f'DiscoverNetworkServices:{target_ip}'}

    # 2. Mock a successful EternalBlue execution
    expected_effect = ActionEffect(
        success=True,
        state_deltas={f'hosts/{target_ip}/privilege': 'User'},
        observation_data={'exploit': target_ip},
    )

    # 3. Trigger it at tick 0. Duration 6 -> matures at tick 6.
    with patch.object(ExploitEternalBlue, 'execute', return_value=expected_effect):
        # We manually queue it to ensure 100% control over the event queue state
        action = ExploitEternalBlue(agent, target_ip)
        env.event_queue.append(
            {
                'agent': agent,
                'action': action,
                'completion_tick': 6,
                'effect': expected_effect,
                'target_ip': target_ip,
            }
        )

        # Advance 6 pseudo-ticks
        for _ in range(6):
            env.step({})

        # 4. Final verification
        all_logs = env.global_state.siem_log_buffer
        honey_alerts = [
            log[0]
            for log in all_logs
            if isinstance(log[0], dict)
            and log[0].get('signature') == 'HONEYTOKEN_TRIGGERED'
        ]

        assert len(honey_alerts) > 0, (
            f'HONEYTOKEN_TRIGGERED missing. Buffer content: {all_logs}'
        )
        assert honey_alerts[0]['severity'] == 10
        assert honey_alerts[0]['target'] == target_ip
