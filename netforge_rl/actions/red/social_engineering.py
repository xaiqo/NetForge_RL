import random
from netforge_rl.core.action import BaseAction, ActionEffect
from netforge_rl.core.commands import (
    EstablishSessionCommand,
    UpdateHostPrivilegeCommand,
)
from netforge_rl.core.registry import action_registry


@action_registry.register('red_operator', 21)
class SpearPhishing(BaseAction):
    """Executes a targeted Social Engineering campaign against a Corporate End-User.

    Unlike standard Exploits, SpearPhishing leverages email protocols and bypasses
    perimeter firewalls and DMZ routing constraints entirely. Its success probability
    is purely dictated by the `human_vulnerability_score` of the human operator
    assigned to the generated Endpoint, simulating clicks on malicious attachments.

    Args:
        agent_id (str): Reference ID of the Red operating unit.
        target_ip (str): IP address of the target User Node (typically Corporate/Secure subnet).
    """

    def __init__(self, agent_id: str, target_ip: str):
        super().__init__(
            agent_id,
            target_ip=target_ip,
            cost=2,
            financial_cost=50,  # Costs minor operational budget to purchase domain infrastructure
            duration=15,  # High duration (waiting for users to organically check email)
            required_prior_state=None,  # Can be shot blindly without structural discovery
        )

    def validate(self, global_state) -> bool:
        """Overrides parent zone constraints to simulate out-of-band email protocol delivery."""
        if not self.target_ip or self.target_ip not in global_state.all_hosts:
            return False

        host = global_state.all_hosts[self.target_ip]
        # Nobody reads emails on PLCs or dedicated Servers; restricted to Windows Endpoints here
        if 'Windows' not in getattr(host, 'os', ''):
            return False

        return True

    def execute(self, global_state) -> ActionEffect:
        host = global_state.all_hosts.get(self.target_ip)

        # Pull the phishability score generated procedurally
        phish_chance = getattr(host, 'human_vulnerability_score', 0.1)

        if random.random() > phish_chance:
            return ActionEffect(
                success=False,
                state_deltas=[],
                observation_data={
                    'phishing': 'failed',
                    'reason': 'user reported suspicious email',
                },
            )

        # Build OOP Delta List granting User-level reverse shell from the clicked attachment
        deltas = [
            UpdateHostPrivilegeCommand(
                self.target_ip, 'User', compromised_by=self.agent_id
            ),
            EstablishSessionCommand(
                self.agent_id, self.target_ip, port=443
            ),  # Emulate C2 over HTTPS
        ]

        return ActionEffect(
            success=True,
            state_deltas=deltas,
            observation_data={
                'phishing': 'success',
                'status': 'C2 Session Established via user execution',
            },
            eta=self.duration,
        )
