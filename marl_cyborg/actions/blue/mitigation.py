from marl_cyborg.core.action import BaseAction, ActionEffect


class IsolateHost(BaseAction):
    """Disconnects a compromised host completely from the network

    infrastructure.

    This prevents lateral movement or data exfiltration but incurs an availability
    penalty on the Blue Team's scoring mechanism.

    Args:
        agent_id (str): The unique identifier of the defending Blue agent.
        target_ip (str): The IP address of the host to dynamically isolate.
    """

    def __init__(self, agent_id: str, target_ip: str):
        super().__init__(agent_id, target_ip=target_ip)

    def validate(self, global_state) -> bool:
        """Validates if the target host theoretically exists and can be

        isolated.

        Args:
            global_state (GlobalNetworkState): Engine baseline state.

        Returns:
            bool: True if the action passes initial routing or authority checks.
        """
        return True

    def execute(self, global_state) -> ActionEffect:
        """Implements the zero-trust isolation delta across the specific node.

        Args:
            global_state (GlobalNetworkState): Snapshot of current network topology.

        Returns:
            ActionEffect: A state delta changing the node's status to 'isolated'.
        """
        return ActionEffect(
            success=True,
            state_deltas={f'hosts/{self.target_ip}/status': 'isolated'},
            observation_data={'alert': 'Host isolated securely.'},
        )


class RestoreHost(BaseAction):
    """Re-establishes network connectivity for a previously isolated host.

    Reverses the `IsolateHost` effect, bringing the node back online and
    restoring critical business availability.

    Args:
        agent_id (str): The unique identifier of the defending Blue agent.
        target_ip (str): The isolated node's IP address.
    """

    def __init__(self, agent_id: str, target_ip: str):
        super().__init__(agent_id, target_ip=target_ip)

    def validate(self, global_state) -> bool:
        """Evaluates requirements for network restoration natively.

        Args:
            global_state (GlobalNetworkState): Engine baseline state.

        Returns:
            bool: Always True in base simulation constraints.
        """
        return True

    def execute(self, global_state) -> ActionEffect:
        """Removes the isolation quarantine delta from the designated host.

        Args:
            global_state: Network configuration array.

        Returns:
            ActionEffect: State delta returning the status to 'online'.
        """
        return ActionEffect(
            success=True,
            state_deltas={f'hosts/{self.target_ip}/status': 'online'},
            observation_data={'alert': 'Host restored.'},
        )


class Remove(BaseAction):
    """Evicts unauthorized threat actors from a compromised element.

    Targets and kills anomalous processes, rolling local user privileges back
    to a stable state without requiring a full system format.

    Args:
        agent_id (str): Referencing Blue agent framework ID.
        target_ip (str): Host identifier.
    """

    def __init__(self, agent_id: str, target_ip: str):
        super().__init__(agent_id, target_ip=target_ip)

    def validate(self, global_state) -> bool:
        """Checks Blue operational bounds prior to execution.

        Args:
            global_state: Reference engine configuration.

        Returns:
            bool: Action clearance bool.
        """
        return True

    def execute(self, global_state) -> ActionEffect:
        """Translates the threat eviction into a measurable privilege reduction

        delta.

        Args:
            global_state: Reference engine configuration.

        Returns:
            ActionEffect: State vector scrubbing privilege parameters down to 'None'.
        """
        return ActionEffect(
            success=True,
            state_deltas={f'hosts/{self.target_ip}/privilege': 'None'},
            observation_data={'alert': 'Unauthorized access removed.'},
        )


class RestoreFromBackup(BaseAction):
    """Executes a bare-metal imaging recovery to purge advanced persistent

    threats (APTs).

    An extreme but definitive mitigation vector that eradicates persistent malware,
    but takes significantly more time and cost than localized `Remove` actions.

    Args:
        agent_id (str): The orchestrating Blue agent ID string.
        target_ip (str): The endpoint requiring catastrophic intervention.
    """

    def __init__(self, agent_id: str, target_ip: str):
        super().__init__(agent_id, target_ip=target_ip)

    def validate(self, global_state) -> bool:
        """Ensures execution feasibility regarding orchestration limits.

        Args:
            global_state: Simulation context.

        Returns:
            bool: Access valid.
        """
        return True

    def execute(self, global_state) -> ActionEffect:
        """Computes a comprehensive reversion of the host node's state back to

        pristine.

        Args:
            global_state: Simulation context.

        Returns:
            ActionEffect: Multi-delta payload restoring privileges, uptime, and system integrity simultaneously.
        """
        return ActionEffect(
            success=True,
            state_deltas={
                f'hosts/{self.target_ip}/privilege': 'None',
                f'hosts/{self.target_ip}/status': 'online',
                f'hosts/{self.target_ip}/system_integrity': 'clean',
            },
            observation_data={'alert': 'Host restored from backup image.'},
        )


class ConfigureACL(BaseAction):
    """
    Dynamically modifies the implicit routing Firewall to block specific port
    traffic inbound to a protected subnet.

    Args:
        agent_id (str): Operating Blue Agent ID.
        target_subnet (str): The CIDR block of the subnet to protect (e.g., '10.0.1.0/24').
        port (int): The destination port to drop (e.g., 445).
    """

    def __init__(self, agent_id: str, target_subnet: str, port: int):
        super().__init__(agent_id, target_ip=target_subnet, cost=2)
        self.port = port

    def validate(self, global_state) -> bool:
        """
        Validates if the target subnet exists in the architecture.
        """
        return self.target_ip in global_state.subnets

    def execute(self, global_state) -> ActionEffect:
        """
        Calculates the physics delta to apply the firewall block rule.
        """
        safe_subnet = self.target_ip.replace('/', '_slash_')
        return ActionEffect(
            success=True,
            state_deltas={f'firewall/block/{safe_subnet}/{self.port}': 'True'},
            observation_data={
                'alert': f'ACL configured: Drop Port {self.port} to {self.target_ip}'
            },
        )
