from typing import TYPE_CHECKING, Dict
from marl_cyborg.scenarios.base_scenario import BaseScenario

if TYPE_CHECKING:
    from marl_cyborg.core.state import GlobalNetworkState


class AptEspionageScenario(BaseScenario):
    """
    Scenario: Red Team acts as an Advanced Persistent Threat.

    - Red is rewarded for uninterrupted stealthy persistence.
    - Red is penalized heavily if discovered or isolated by Blue.
    """

    def __init__(self, agents):
        self.agents = agents

    def calculate_reward(
        self, agent_id: str, global_state: 'GlobalNetworkState'
    ) -> float:
        reward = 0.0

        if 'red' in agent_id.lower():
            for h in global_state.all_hosts.values():
                # Reward persistence
                if h.privilege in ['User', 'Root'] and h.status == 'online':
                    reward += 1.0
                # Extreme penalty if caught/isolated
                elif h.privilege in ['User', 'Root'] and h.status == 'isolated':
                    reward -= 20.0

        elif 'blue' in agent_id.lower():
            for h in global_state.all_hosts.values():
                is_infected = h.privilege in ['User', 'Root']
                is_isolated = h.status == 'isolated'

                if not is_infected and not is_isolated:
                    reward += 1.0  # Uptime
                elif is_infected and not is_isolated:
                    reward -= 5.0  # Exfiltration / espionage penalty
                elif is_infected and is_isolated:
                    reward += 20.0  # Successfully rooted out the APT

        return reward

    def check_termination(self, global_state: 'GlobalNetworkState') -> Dict[str, bool]:
        # If Blue isolates all infected hosts, the APT is defeated
        terminate = {agent: False for agent in self.agents}

        infected_hosts = [
            h
            for h in global_state.all_hosts.values()
            if h.privilege in ['User', 'Root']
        ]
        if infected_hosts and all(h.status == 'isolated' for h in infected_hosts):
            # Terminate episode if Red has no active footholds left
            return {agent: True for agent in self.agents}

        return terminate
