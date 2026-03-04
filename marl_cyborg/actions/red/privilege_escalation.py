from marl_cyborg.core.action import BaseAction, ActionEffect


class PrivilegeEscalate(BaseAction):
    """Executes a generic local privilege escalation exploit on a compromised

    host.

    Elevates an agent's access from standard 'User' to 'Root' or 'SYSTEM', granting
    unrestricted control over the endpoint for subsequent impact actions.

    Args:
        agent_id (str): The unique identifier of the Red agent.
        target_ip (str): The IP address of the already compromised host.
    """

    def __init__(self, agent_id: str, target_ip: str):
        super().__init__(agent_id, target_ip=target_ip)

    def validate(self, global_state) -> bool:
        """Validates the pre-conditions for privilege escalation natively.

        Args:
            global_state (GlobalNetworkState): Snapshot of the network environment.

        Returns:
            bool: True if escalation is physically feasible.
        """
        return True

    def execute(self, global_state) -> ActionEffect:
        """Applies the mathematical delta to elevate the agent's privilege

        level.

        Args:
            global_state (GlobalNetworkState): Current network blueprint.

        Returns:
            ActionEffect: A delta upgrading the specific host's privilege to 'Root'.
        """
        return ActionEffect(
            success=True,
            state_deltas={
                f'hosts/{self.target_ip}/privilege': 'Root',
                f'hosts/{self.target_ip}/compromised_by': self.agent_id,
            },
            observation_data={'privilege': 'escalated'},
        )


class JuicyPotato(BaseAction):
    """Simulates the JuicyPotato local privilege escalation vector leveraging

    DCOM on Windows.

    Abuses `SeImpersonatePrivilege` to elevate a service account to `NT AUTHORITY\\SYSTEM`.

    Args:
        agent_id (str): Reference to the executing Red operator.
        target_ip (str): Target IPv4 string.
    """

    def __init__(self, agent_id: str, target_ip: str):
        super().__init__(agent_id, target_ip=target_ip)

    def validate(self, global_state) -> bool:
        """Validates target compatibility (e.g., Windows OS assumption).

        Args:
            global_state: Network state.

        Returns:
            bool: True assuming the agent has obtained baseline 'User' access.
        """
        return True

    def execute(self, global_state) -> ActionEffect:
        """Processes the DCOM impersonation attack delta. Fails if target OS is

        not Windows.

        Args:
            global_state: Network state.

        Returns:
            ActionEffect: State vector replacing access rights with 'Root'.
        """
        host = global_state.all_hosts.get(self.target_ip)
        if host and 'Windows' not in host.os:
            return ActionEffect(
                success=False,
                state_deltas={},
                observation_data={'privilege': 'failed - OS is not Windows'},
            )

        return ActionEffect(
            success=True,
            state_deltas={
                f'hosts/{self.target_ip}/privilege': 'Root',
                f'hosts/{self.target_ip}/compromised_by': self.agent_id,
            },
            observation_data={'privilege': 'JuicyPotato elevated'},
        )


class V4L2KernelExploit(BaseAction):
    """Executes a specific kernel-level vulnerability via Video4Linux (V4L2) on

    Linux targets.

    Targets memory corruption in outdated kernel modules to spawn a root shell.

    Args:
        agent_id (str): Reference to the executing Red operator.
        target_ip (str): Target IPv4 string.
    """

    def __init__(self, agent_id: str, target_ip: str):
        super().__init__(agent_id, target_ip=target_ip)

    def validate(self, global_state) -> bool:
        """Validates routing or baseline access requirements.

        Args:
            global_state: Network state.

        Returns:
            bool: Execution clearance boolean.
        """
        return True

    def execute(self, global_state) -> ActionEffect:
        """Resolves the exploit outcome altering the target's privilege table.

        Fails if target is patched or not a Linux host.

        Args:
            global_state: Network state.

        Returns:
            ActionEffect: Physics engine state modifications.
        """
        host = global_state.all_hosts.get(self.target_ip)
        if host and ('Linux' not in host.os or 'V4L2' not in host.vulnerabilities):
            return ActionEffect(
                success=False,
                state_deltas={},
                observation_data={
                    'privilege': 'failed - target patched or incompatible OS'
                },
            )

        return ActionEffect(
            success=True,
            state_deltas={
                f'hosts/{self.target_ip}/privilege': 'Root',
                f'hosts/{self.target_ip}/compromised_by': self.agent_id,
            },
            observation_data={'privilege': 'V4L2 Kernel escalated'},
        )
