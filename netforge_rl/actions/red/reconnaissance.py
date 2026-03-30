from netforge_rl.core.action import BaseAction, ActionEffect
from netforge_rl.core.registry import action_registry


@action_registry.register('red_commander', 0)
class NetworkScan(BaseAction):
    """Executes a wide network scan across a specified subnet to map active IP

    addresses.

    This action represents the initial reconnaissance phase of the Cyber Kill Chain,
    typically mapping to MITRE ATT&CK T1046 (Network Service Scanning).

    Args:
        agent_id (str): The unique identifier of the Red agent executing the scan.
        target_subnet (str): The CIDR block of the target subnet (e.g., "10.0.0.0/24").
    """

    def __init__(self, agent_id: str, target_subnet: str):
        super().__init__(agent_id, target_ip=target_subnet, cost=5)

    def validate(self, global_state) -> bool:
        """Validates whether the agent has physical or logical routing to the

        target subnet.

        Args:
            global_state (GlobalNetworkState): The current state of the architecture.

        Returns:
            bool: True if the subnet is reachable, False otherwise.
        """
        return True

    def execute(self, global_state) -> ActionEffect:
        """Processes the scan without mutating the state, returning

        observations.

        Args:
            global_state (GlobalNetworkState): The current state of the architecture.

        Returns:
            ActionEffect: The computational result updating the agent's observation space.
        """
        return ActionEffect(
            success=True,
            state_deltas={},
            observation_data={'discovered_subnet': self.target_ip},
            eta=3,
        )


@action_registry.register('red_commander', 1)
class DiscoverRemoteSystems(BaseAction):
    """Executes a targeted Ping Sweep against a subnet to explicitly identify

    host machines.

    This action simulates ICMP Echo Requests (Ping Sweeps) or ARP broadcasts to find
    live endpoints, susceptible to deception from Blue team honeypots.

    Args:
        agent_id (str): The unique identifier of the Red agent.
        target_subnet (str): The CIDR target (e.g., "10.0.0.0/24").
    """

    def __init__(self, agent_id: str, target_subnet: str):
        super().__init__(agent_id, target_ip=target_subnet, cost=3)

    def validate(self, global_state) -> bool:
        """Validates routing path availability to the target broadcast address.

        Args:
            global_state (GlobalNetworkState): The current state of the architecture.

        Returns:
            bool: True if reachable, False otherwise.
        """
        return True

    def execute(self, global_state) -> ActionEffect:
        """Identifies active hosts in the subnet. Accounts for misinformation

        campaigns where Blue agents supply fake decoy arrays.

        Args:
            global_state (GlobalNetworkState): The current network state.

        Returns:
            ActionEffect: Contains the parsed array of active (or spoofed) hosts.
        """
        fake_data = False
        active_hosts = []
        for host in global_state.all_hosts.values():
            if host.subnet_cidr == self.target_ip:
                active_hosts.append(host.ip)
                if host.decoy in ['active', 'Apache', 'SSHD', 'Tomcat']:
                    fake_data = True

        obs_data = {'ping_sweep': self.target_ip, 'hosts': active_hosts}
        if fake_data:
            obs_data['hosts'] = ['10.x.x.99', '10.x.x.100']

        knowledge_deltas = {
            f'knowledge/{self.agent_id}/{ip}': 'True' for ip in obs_data['hosts']
        }

        return ActionEffect(
            success=True, state_deltas=knowledge_deltas, observation_data=obs_data
        )


@action_registry.register('red_commander', 2)
class DiscoverNetworkServices(BaseAction):
    """Executes an intrusive port scan against a specific host to enumerate

    running daemons.

    Often simulates an `nmap -sS -sV` scan to identify vulnerable service banners on open ports.

    Args:
        agent_id (str): The unique identifier of the Red agent.
        target_ip (str): The IP address of the target host.
    """

    def __init__(self, agent_id: str, target_ip: str):
        super().__init__(agent_id, target_ip=target_ip, cost=2, duration=3)

    def validate(self, global_state) -> bool:
        """Confirms target host is active and packet routing is unblocked by

        firewalls.

        Args:
            global_state (GlobalNetworkState): The current network state.

        Returns:
            bool: True if the specified host is reachable.
        """
        return True

    def execute(self, global_state) -> ActionEffect:
        """Returns the exposed service ports on the target. Interacts heavily

        with decoy and honeypot configurations deployed by the Blue Agent.

        Args:
            global_state (GlobalNetworkState): The current architecture state.

        Returns:
            ActionEffect: A list of discovered service banners corresponding to the IP.
        """
        obs_data = {'port_scan': self.target_ip}
        if self.target_ip in global_state.all_hosts:
            host = global_state.all_hosts[self.target_ip]
            if host.decoy in ['active', 'Apache']:
                obs_data['services'] = ['Fake_Apache_80', 'Fake_SSH_2222']
            elif host.decoy == 'SSHD':
                obs_data['services'] = ['Fake_SSH_22']
            elif host.decoy == 'Tomcat':
                obs_data['services'] = ['Fake_Tomcat_8080']
            else:
                obs_data['services'] = host.services
                obs_data['os'] = host.os
                obs_data['vulnerabilities'] = host.vulnerabilities

        # Update knowledge that we scanned this host and add to history
        knowledge_deltas = {
            f'knowledge/{self.agent_id}/{self.target_ip}': 'True',
            f'history/{self.agent_id}/DiscoverNetworkServices:{self.target_ip}': 'add',
        }

        return ActionEffect(
            success=True, state_deltas=knowledge_deltas, observation_data=obs_data
        )
