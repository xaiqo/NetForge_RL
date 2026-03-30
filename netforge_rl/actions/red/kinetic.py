from netforge_rl.core.action import BaseAction, ActionEffect
from netforge_rl.core.registry import action_registry

@action_registry.register('red_operator', 20)
class OverloadPLC(BaseAction):
    """Initiates a devastating Kinetic Impact on a compromised Cyber-Physical OT Node.

    If the target PLC is compromised to Root level and belongs to the Operational Technology
    infrastructure, this action radically forces hardware temperatures past catastrophic thresholds.

    Args:
        agent_id (str): Reference string for the agent executing the attack.
        target_ip (str): IP address belonging to a PLC_Firmware host inside the OT_Subnet.
    """

    def __init__(self, agent_id: str, target_ip: str):
        super().__init__(
            agent_id, 
            target_ip=target_ip, 
            cost=20,  # High Energy
            financial_cost=1000,  # High Financial Requirement
            duration=10, 
            required_prior_state='DiscoverNetworkServices'
        )

    def validate(self, global_state) -> bool:
        """Ensures the target exists, is routeable, and is ACTUALLY an OT device."""
        if not super().validate(global_state):
            return False
            
        host = global_state.all_hosts.get(self.target_ip)
        if not host:
            return False
            
        # Target must be physically OT Infrastructure
        if host.os != 'PLC_Firmware' or host.subnet_cidr != '10.0.99.0/24':
            return False

        # Red must have maximum execution privileges over the mechanical interface
        if host.privilege != 'Root':
            return False

        return global_state.can_route_to(self.target_ip)

    def execute(self, global_state) -> ActionEffect:
        import random

        host = global_state.all_hosts.get(self.target_ip)
        if not host:
            return ActionEffect(success=False, state_deltas={}, observation_data={})

        current_temperature = getattr(host, 'temperature', 50.0)
        
        # Inject rapid thermal escalation +90 to +150 delta
        spike = random.uniform(90.0, 150.0)
        new_temp = current_temperature + spike

        deltas = {
            f'hosts/{self.target_ip}/temperature': new_temp,
            f'hosts/{self.target_ip}/system_integrity': 'kinetic_destruction'
        }

        # Stuxnet-level alert severity for the Blue Team SIEM
        obs_data = {
            'action': 'overload_plc',
            'status': 'kinetic_impact_achieved',
            'terminal_temperature': new_temp
        }

        return ActionEffect(
            success=True,
            state_deltas=deltas,
            observation_data=obs_data,
            eta=self.duration
        )
