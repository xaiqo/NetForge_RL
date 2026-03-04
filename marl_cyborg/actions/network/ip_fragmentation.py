from typing import TYPE_CHECKING

from marl_cyborg.core.action import BaseAction, ActionEffect

if TYPE_CHECKING:
    from marl_cyborg.core.state import GlobalNetworkState


class IPFragmentationAction(BaseAction):
    """
    Network Layer Evasion Attack:
    Splits malicious payloads across multiple IP frames to bypass standard single-frame IDS.
    """

    def __init__(
        self, agent_id: str, target_ip: str, payload_type: str = 'reverse_shell'
    ):
        super().__init__(agent_id=agent_id, target_ip=target_ip)
        self.payload_type = payload_type
        self.fragment_size = 8  # bytes

    def validate(self, global_state: 'GlobalNetworkState') -> bool:
        # Attacker must have an active route to the target IP
        return global_state.routing_table.has_route(self.agent_id, self.target_ip)

    def execute(self, global_state: 'GlobalNetworkState') -> ActionEffect:
        target_host = global_state.get_host(self.target_ip)

        # If Blue Team IDS does not support protocol reassembly, attack succeeds silently
        ids_present = target_host.has_service('IDS')
        ids_reassembles_packets = global_state.get_service_config('IDS').get(
            'deep_packet_inspection', False
        )

        success = False
        state_deltas = {}
        observation_data = {}

        if ids_present and ids_reassembles_packets:
            # Blue Team catches the anomaly
            observation_data['alert'] = 'IDS_SIGNATURE_IP_FRAGMENTATION_DETECTED'
            success = False
        else:
            # Bypass successful, implant session
            state_deltas[f'hosts.{self.target_ip}.sessions'] = {
                'add': {'agent_id': self.agent_id, 'privilege': 'user'}
            }
            success = True

        return ActionEffect(
            success=success,
            state_deltas=state_deltas,
            observation_data=observation_data,
        )
