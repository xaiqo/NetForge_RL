from netforge_rl.core.action import BaseAction, ActionEffect
from netforge_rl.core.registry import action_registry



@action_registry.register('red_commander', 3)
class ShareIntelligence(BaseAction):
    """Explicitly shares the current agent's 'Fog of War' knowledge graph with

    an allied agent.

    A crucial mechanic for Multi-Agent cooperation. For example, a Commander might do a loud
    Subnet scan (costing 5 Energy) and then use this cheap action (cost: 1) to push the intel
    to an Operator agent doing the actual silent exploiting.

    Args:
        agent_id (str): The identifier of the agent sending the intelligence.
        target_agent_id (str): The allied agent identifier receiving the intelligence.
    """

    def __init__(self, agent_id: str, target_agent_id: str):
        # We overload target_ip with the target agent string since it's an internal physics action
        super().__init__(agent_id, target_ip=target_agent_id, cost=1)
        self.target_agent_id = target_agent_id

    def validate(self, global_state) -> bool:
        """Validates the capability of transferring intelligence.

        Args:
            global_state (GlobalNetworkState): Current simulation physics context.

        Returns:
            bool: True if both sender and receiver exist in the simulation.
        """
        if self.agent_id not in global_state.agent_knowledge:
            return False
        return True

    def execute(self, global_state) -> ActionEffect:
        """Generates the state deltas necessary to copy all known IPs from

        sender to receiver.

        Args:
            global_state (GlobalNetworkState): Current network blueprint.

        Returns:
            ActionEffect: Delta map appending all known IPs to the target agent.
        """
        knowledge_deltas = {}

        if self.agent_id in global_state.agent_knowledge:
            known_ips = global_state.agent_knowledge[self.agent_id]
            for known_ip in known_ips:
                # "knowledge/red_operator/10.0.0.5" -> "True"
                knowledge_deltas[f'knowledge/{self.target_agent_id}/{known_ip}'] = (
                    'True'
                )

        return ActionEffect(
            success=True,
            state_deltas=knowledge_deltas,
            observation_data={'shared_intel_with': self.target_agent_id},
        )
