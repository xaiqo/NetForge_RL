import random
import string
from netforge_rl.core.action import BaseAction, ActionEffect
from netforge_rl.core.registry import action_registry


@action_registry.register('RotateKerberos', 'blue')
class RotateKerberos(BaseAction):
    """
    Apex Zero-Trust Action: Rotates Domain Kerberos TGT Keys globally.
    This invalidates all currently held Enterprise Admin tokens, severing Red's ZTNA lateral movement.
    It impacts the entirely network graph, but burns significant Business Downtime.
    """

    def __init__(self, agent_id: str, target_ip: str):
        # target_ip is effectively ignored since this is a global action, but retained for API parity.
        super().__init__(agent_id, target_ip)
        self.duration = 4
        self.compute_cost = 80

    def validate(self, global_state) -> bool:
        # Global action; validate the blue agent has enough funds (highly expensive)
        if self.agent_id in global_state.agent_funds:
            if global_state.agent_funds[self.agent_id] < 5000:
                return False
        return True

    def execute(self, global_state) -> ActionEffect:
        class RotateKerberosCommand:
            def __init__(self, agent_id):
                self.agent_id = agent_id

            def execute(self, state):
                # 1. Burn the massive funding cost
                if self.agent_id in state.agent_funds:
                    state.agent_funds[self.agent_id] -= 5000
                state.business_downtime_score += 1500.0

                # 2. Flush all Red Agent Inventories globally
                for agent in state.agent_inventory:
                    state.agent_inventory[agent].clear()

                # 3. Generate a new valid Domain Token string
                random_suffix = ''.join(
                    random.choices(string.ascii_uppercase + string.digits, k=6)
                )
                new_token = f'Enterprise_Admin_Token_{random_suffix}'

                # 4. Migrate the global environment physics to require the NEW token
                for host in state.all_hosts.values():
                    # Update what the host requires
                    if 'Enterprise_Admin_Token' in host.system_tokens:
                        host.system_tokens.remove('Enterprise_Admin_Token')
                        host.system_tokens.append(new_token)

                    # Also update wildcard tokens from any previous rotations
                    old_tokens = [
                        t
                        for t in host.system_tokens
                        if t.startswith('Enterprise_Admin_Token_')
                    ]
                    for t in old_tokens:
                        host.system_tokens.remove(t)
                        host.system_tokens.append(new_token)

                    # Update what the Domain Controllers hold in memory
                    if 'Enterprise_Admin_Token' in host.cached_credentials:
                        host.cached_credentials.remove('Enterprise_Admin_Token')
                        host.cached_credentials.append(new_token)

                    old_cache = [
                        t
                        for t in host.cached_credentials
                        if t.startswith('Enterprise_Admin_Token_')
                    ]
                    for t in old_cache:
                        host.cached_credentials.remove(t)
                        host.cached_credentials.append(new_token)

        deltas = {'identity_flush': RotateKerberosCommand(self.agent_id)}

        return ActionEffect(
            success=True,
            state_deltas=deltas,
            observation_data={
                'alert': 'CRITICAL: Global Domain Keys Rotated. Enterprise Network re-verified.'
            },
            eta=self.duration,
        )
