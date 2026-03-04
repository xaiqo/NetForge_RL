from marl_cyborg.core.action import BaseAction, ActionEffect


class Impact(BaseAction):
    """
    Executes the final localized objective of the Cyber Kill Chain (e.g., Ransomware/Wiper).

    Irreversibly encrypts or destroys data on a fully compromised root host,
    triggering massive score penalties for the Blue Team.

    Args:
        agent_id (str): The identifier of the Red agent executing the impact.
        target_ip (str): The IP address of the target host.
    """

    def __init__(self, agent_id: str, target_ip: str):
        super().__init__(agent_id, target_ip=target_ip)

    def validate(self, global_state) -> bool:
        """
        Confirms target is accessible prior to the impact execution.

        Args:
            global_state (GlobalNetworkState): Current simulator context.

        Returns:
            bool: True if execution is unimpeded.
        """
        return True

    def execute(self, global_state) -> ActionEffect:
        """
        Calculates the physics delta resulting in the total loss of system integrity.

        Args:
            global_state (GlobalNetworkState): Baseline network configuration.

        Returns:
            ActionEffect: A delta explicitly assigning the 'compromised' integrity flag.
        """
        return ActionEffect(
            success=True,
            state_deltas={f'hosts/{self.target_ip}/system_integrity': 'compromised'},
            observation_data={'impact': 'executed'},
        )
