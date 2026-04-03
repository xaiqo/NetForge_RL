from typing import TYPE_CHECKING, Dict
from netforge_rl.scenarios.base_scenario import BaseScenario

if TYPE_CHECKING:
    from netforge_rl.core.state import GlobalNetworkState
    from netforge_rl.core.action import ActionEffect


class AptEspionageScenario(BaseScenario):
    """
    Scenario: Red Team acts as an Advanced Persistent Threat.
    """

    def __init__(self, agents):
        self.agents = agents

    def calculate_reward(
        self,
        agent_id: str,
        global_state: 'GlobalNetworkState',
        effect: 'ActionEffect' = None,
    ) -> float:
        reward = 0.0

        if effect:
            # Action Cost Penalty
            if getattr(effect, 'cost', 0) > 0:
                reward -= (effect.cost * 0.1)

            if 'red' in agent_id.lower() and effect.success:
                action_obj = getattr(effect, 'action', None)
                action_name = type(action_obj).__name__ if action_obj else "Unknown"
                
                # RECON Reward
                if 'Discover' in action_name or 'Scan' in action_name:
                    reward += 2.0
                
                # BREACH Reward
                if 'Exploit' in action_name or 'Pivot' in action_name:
                    reward += 10.0
                
                # EXFIL Reward
                if 'Exfiltrate' in action_name or 'Dump' in action_name or 'Impact' in action_name:
                    reward += 20.0

                if 'shared' in str(effect.observation_data):
                    reward += 5.0

                if 'Failed against Decoy' in str(effect.observation_data.values()):
                    reward -= 15.0

        if 'red' in agent_id.lower():
            # Persistence Reward
            total_persistence = 0.0
            for h in global_state.all_hosts.values():
                if h.privilege in ['User', 'Root'] and h.status == 'online':
                    total_persistence += 5.0
                elif h.privilege in ['User', 'Root'] and h.status == 'isolated':
                    total_persistence -= 20.0
            reward += total_persistence

        elif 'blue' in agent_id.lower():
            for h in global_state.all_hosts.values():
                is_infected = h.privilege in ['User', 'Root']
                is_isolated = h.status == 'isolated'

                if not is_infected and not is_isolated:
                    reward += 1.0 
                elif is_infected and not is_isolated:
                    reward -= 5.0 
                elif is_infected and is_isolated:
                    reward += 20.0 

        return reward

    def check_termination(self, global_state: 'GlobalNetworkState') -> Dict[str, bool]:
        terminate = {agent: False for agent in self.agents}
        infected_hosts = [h for h in global_state.all_hosts.values() if h.privilege in ['User', 'Root']]
        if infected_hosts and all(h.status == 'isolated' for h in infected_hosts):
            return {agent: True for agent in self.agents}
        return terminate
