from typing import TYPE_CHECKING, Dict
from marl_cyborg.scenarios.base_scenario import BaseScenario

if TYPE_CHECKING:
    from marl_cyborg.core.state import GlobalNetworkState


class RansomwareScenario(BaseScenario):
    """
    Scenario: Red Team aggressively deploys ransomware.

    - Red is highly rewarded for system_integrity compromise (Impact actions).
    - Red ignores stealth (virtually no noise penalty).
    - Blue loses massive points for impacted systems and must isolate quickly.
    """

    def __init__(self, agents):
        self.agents = agents

    def calculate_reward(
        self, agent_id: str, global_state: 'GlobalNetworkState'
    ) -> float:
        reward = 0.0

        red_impact_count = sum(
            1
            for h in global_state.all_hosts.values()
            if getattr(h, 'system_integrity', 'clean') == 'compromised'
        )

        if 'red' in agent_id.lower():
            # Massive reward for each encrypted host
            reward += red_impact_count * 50.0

        elif 'blue' in agent_id.lower():
            for h in global_state.all_hosts.values():
                is_isolated = h.status == 'isolated'
                is_compromised = (
                    getattr(h, 'system_integrity', 'clean') == 'compromised'
                )

                if is_compromised and not is_isolated:
                    reward -= 50.0  # Massive penalty for active ransomware
                elif is_isolated and getattr(h, 'privilege', 'None') in [
                    'User',
                    'Root',
                ]:
                    reward += 10.0  # Successfully quarantined an infected host
                elif not is_compromised and not is_isolated:
                    reward += 1.0  # General uptime reward

        return reward

    def check_termination(self, global_state: 'GlobalNetworkState') -> Dict[str, bool]:
        terminate = {agent: False for agent in self.agents}

        # If all critical Corporate/Secure hosts are compromised, episode ends
        target_hosts = [
            h
            for h in global_state.all_hosts.values()
            if h.subnet_cidr in ['10.0.0.0/24', '10.0.1.0/24']
        ]

        if target_hosts and all(
            getattr(h, 'system_integrity', 'clean') == 'compromised'
            for h in target_hosts
        ):
            return {agent: True for agent in self.agents}

        return terminate
