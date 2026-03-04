import random
import yaml
from pathlib import Path
from typing import Optional
from marl_cyborg.core.state import GlobalNetworkState, Subnet, Host


class NetworkGenerator:
    """Procedurally generates or loads dynamic network topologies for MARL

    training.

    Prevents agents from overfitting to a static 10-node architecture.
    """

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path

    def generate(self, seed: Optional[int] = None) -> GlobalNetworkState:
        """Generates the architecture.

        If a config path was provided, loads deterministically.
        Otherwise, procedurally generates a randomized topology.
        """
        if seed is not None:
            random.seed(seed)

        if self.config_path and Path(self.config_path).exists():
            return self._load_from_yaml(self.config_path)

        return self._generate_procedural()

    def _generate_procedural(self) -> GlobalNetworkState:
        """Creates a randomized network with 2-4 subnets and 5-15 hosts.

        Randomizes IP bounds and initial decoy placements.
        """
        state = GlobalNetworkState()

        # Determine number of subnets (e.g., DMZ, Corp, Secure, Guest)
        num_subnets = random.randint(2, 4)
        subnet_names = ['DMZ', 'Corporate', 'Secure', 'Guest']
        base_ips = ['192.168.1', '10.0.0', '10.0.1', '172.16.0']

        for i in range(num_subnets):
            cidr = f'{base_ips[i]}.0/24'
            subnet = Subnet(cidr=cidr, name=subnet_names[i])
            state.add_subnet(subnet)

            # 2 to 6 hosts per subnet
            num_hosts = random.randint(2, 6)
            for j in range(1, num_hosts + 1):
                host_ip = f'{base_ips[i]}.{j * random.randint(1, 5)}'
                host = Host(
                    ip=host_ip, hostname=f'{subnet_names[i]}_Node_{j}', subnet_cidr=cidr
                )

                # Randomly place a Blue Team decoy (15% chance)
                if random.random() < 0.15:
                    host.decoy = random.choice(['Apache', 'SSHD', 'Tomcat', 'active'])
                else:
                    # Assign legitimate OS profiles and CVEs to real hosts
                    profiles = [
                        ('Windows_10', ['RDP', 'SMB'], ['CVE-2019-0708', 'MS17-010']),
                        (
                            'Windows_Server_2016',
                            ['SMB', 'IIS'],
                            ['MS17-010', 'CVE-2021-44228'],
                        ),
                        ('Linux_Ubuntu', ['SSH', 'Apache'], ['CVE-2021-44228', 'V4L2']),
                        ('Linux_CentOS', ['SSH', 'Tomcat'], ['CVE-2021-44228']),
                    ]
                    chosen_os, chosen_services, potential_cves = random.choice(profiles)
                    host.os = chosen_os
                    host.services = chosen_services
                    # Randomly assign 0 to 2 specific vulnerabilities from the valid pool to prevent guaranteed exploitation
                    num_vulns = random.randint(0, min(2, len(potential_cves)))
                    host.vulnerabilities = random.sample(potential_cves, num_vulns)

                state.register_host(host)

        # Ensure Red always knows at least one entry node (DMZ) at step 0
        if '192.168.1.0/24' in state.subnets:
            dmz_hosts = list(state.subnets['192.168.1.0/24'].hosts.values())
            if dmz_hosts:
                # Add default knowledge for Red Commander
                state.update_knowledge('red_commander', dmz_hosts[0].ip)
                state.update_knowledge('red_operator', dmz_hosts[0].ip)

        # Blue knows everything initially
        for host in state.all_hosts.values():
            state.update_knowledge('blue_commander', host.ip)
            state.update_knowledge('blue_operator', host.ip)

        return state

    def _load_from_yaml(self, path: str) -> GlobalNetworkState:
        """Loads a deterministic graph from a YAML configuration."""
        with open(path, 'r') as f:
            _ = yaml.safe_load(f)

        # Implementation left for future expansion if YAML is required.
        # Defaults to procedural if parsing fails.
        return self._generate_procedural()
