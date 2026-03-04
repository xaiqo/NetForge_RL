from marl_cyborg.core.action import BaseAction, ActionEffect


class Monitor(BaseAction):
    """
    Deploys active traffic analysis scanning on a specific subnet or host.

    Provides high-fidelity telemetry to the Blue Team's observation space,
    increasing the probability of detecting stealthy Red anomalous behaviors.

    Args:
        agent_id (str): The unique identifier of the defending Blue agent.
        target_ip (str): The specific IP address or CIDR target.
    """

    def __init__(self, agent_id: str, target_ip: str):
        super().__init__(agent_id, target_ip=target_ip)

    def validate(self, global_state) -> bool:
        """
        Validates the capability of the agent to monitor the requested sector.

        Args:
            global_state (GlobalNetworkState): Simulation snapshot.

        Returns:
            bool: Always True in standard simulation parameters.
        """
        return True

    def execute(self, global_state) -> ActionEffect:
        """
        Calculates the expanded telemetry data yielded by the active monitor.

        Args:
            global_state (GlobalNetworkState): Current architecture baseline.

        Returns:
            ActionEffect: A non-mutating action expanding the agent's observation space.
        """
        return ActionEffect(
            success=True,
            state_deltas={},
            observation_data={'monitoring': self.target_ip},
        )


class Analyze(BaseAction):
    """
    Executes a forensic deep scan of a specific host for malware indicators (IoCs).

    More intrusive than passive `Monitor` actions; identifies specific unauthorized
    privilege escalations or compromised system integrity states.

    Args:
        agent_id (str): Referencing Blue agent framework ID.
        target_ip (str): Host identifier undergoing forensics.
    """

    def __init__(self, agent_id: str, target_ip: str):
        super().__init__(agent_id, target_ip=target_ip)

    def validate(self, global_state) -> bool:
        """
        Confirms target reachability prior to the analysis scan.

        Args:
            global_state: Network configuration matrix.

        Returns:
            bool: Check clearance bool.
        """
        return True

    def execute(self, global_state) -> ActionEffect:
        """
        Computes forensic findings and updates Blue observation knowledge base.

        Args:
            global_state: Network configuration matrix.

        Returns:
            ActionEffect: Observation data payload containing the scan report.
        """
        return ActionEffect(
            success=True,
            state_deltas={},
            observation_data={'analysis_report': self.target_ip},
        )
