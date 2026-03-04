import numpy as np
from typing import Any, List


class BaseObservation:
    """Represents the local view of the network from a single Agent's

    perspective.

    In MARL, Red and Blue teams receive fundamentally different subsets
    of the global state.
    """

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.visible_hosts = {}
        self.detected_anomalies = []
        self.active_sessions = []

        # Array of floats representing the Commander's directive (e.g., target subnet index)
        self.objective_vector = np.zeros(5, dtype=np.float32)

        # Tracks anomalies like 802.11 Deauths, Fragmented IP packets, etc.
        self.network_telemetry = {}

    def update_from_state(self, global_state: Any, action_effects: List[Any]):
        """Filters the global state down to only what is observable by this

        specific agent.

        Since we don't have the fully simulated GlobalNetworkState yet,
        we generate dynamic dummy telemetry that structurally mimics the
        CAGE challenge dictionaries.
        """
        # Parse realistic data from the OOP GlobalNetworkState
        if global_state:
            # Enforce True Partial Observability (Fog of War)
            # Agents only receive tensor data for hosts within their active knowledge graph
            known_ips = global_state.agent_knowledge.get(self.agent_id, set())
            for ip in known_ips:
                if ip in global_state.all_hosts:
                    host = global_state.all_hosts[ip]
                    self.visible_hosts[ip] = {
                        'state': 'compromised'
                        if host.privilege in ['User', 'Root']
                        else 'clean',
                        'status': host.status,
                        'decoy': host.decoy,  # For Blue Team sensor logic
                    }

        if 'commander' in self.agent_id.lower():
            self.network_telemetry['global_alert_level'] = np.random.uniform(0, 1)
            self.network_telemetry['total_isolated_subnets'] = np.random.randint(0, 5)

        if 'operator' in self.agent_id.lower():
            self.objective_vector[2] = 1.0

    def to_numpy(self, max_size: int = 256) -> np.ndarray:
        """Serializes the object-oriented observation into a fixed-size Tensor

        for RL Neural Networks.

        This must be mathematically rigorous. If a node isn't seen, its
        index must be explicitly 0.
        """
        vector = np.zeros(max_size, dtype=np.float32)
        idx = 0

        if 'global_alert_level' in self.network_telemetry and idx < max_size:
            vector[idx] = self.network_telemetry['global_alert_level']
            idx += 1

        if 'total_isolated_subnets' in self.network_telemetry and idx < max_size:
            vector[idx] = (
                float(self.network_telemetry['total_isolated_subnets']) / 10.0
            )  # Normalized
            idx += 1

        for val in self.objective_vector:
            if idx < max_size:
                vector[idx] = val
                idx += 1

        for ip, data in self.visible_hosts.items():
            if idx + 2 >= max_size:
                break

            ip_val = float(ip.split('.')[-1]) / 255.0  # Normalize IP tail
            state_val = (
                1.0
                if data.get('state') == 'compromised'
                else -1.0
                if data.get('state') == 'clean'
                else 0.0
            )

            vector[idx] = ip_val
            vector[idx + 1] = state_val
            idx += 2

        return vector
