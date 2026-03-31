import random
import yaml
from pathlib import Path
from typing import Optional
from netforge_rl.core.state import GlobalNetworkState, Subnet, Host


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
        """Creates a randomized network using NetworkX hierarchical patterns.

        Enforces a constant size of 50 hosts for Neural Network dimension consistency.
        Active topology spans 15-30 nodes; the rest are instantiated as inactive padding.
        """
        import networkx as nx

        state = GlobalNetworkState()
        G = nx.DiGraph()

        # Generate hierarchy parameters
        num_subnets = random.randint(3, 4)
        subnet_names = ['DMZ', 'Corporate', 'Secure', 'Guest'][:num_subnets]
        base_ips = ['192.168.1', '10.0.0', '10.0.1', '172.16.0'][:num_subnets]

        # 25% Chance to spawn a critical Cyber-Physical OT Subnet
        if random.random() < 0.25:
            subnet_names.append('OT_Subnet')
            base_ips.append('10.0.99')

        active_hosts = []
        domain_controllers = []

        # Build Subnets and distribute hosts
        for i, name in enumerate(subnet_names):
            cidr = f'{base_ips[i]}.0/24'
            subnet = Subnet(cidr=cidr, name=name)
            state.add_subnet(subnet)

            # Weight more hosts into Corp and Secure zones
            num_hosts = (
                random.randint(3, 8)
                if name in ['Corporate', 'Secure']
                else random.randint(2, 5)
            )

            for j in range(1, num_hosts + 1):
                host_ip = f'{base_ips[i]}.{j * random.randint(1, 3)}'

                # Check for duplicates due to random gap intervals
                while host_ip in [h.ip for h in active_hosts]:
                    host_ip = f'{base_ips[i]}.{j * random.randint(1, 10)}'

                host = Host(ip=host_ip, hostname=f'{name}_Node_{j}', subnet_cidr=cidr)

                # Assign Decoys vs Real Systems
                if random.random() < 0.15 and name != 'OT_Subnet':
                    host.decoy = random.choice(['Apache', 'SSHD', 'Tomcat', 'active'])
                else:
                    if name == 'OT_Subnet':
                        chosen_os = 'PLC_Firmware'
                        chosen_services = ['Modbus', 'S7Comm']
                        potential_cves = ['CVE-2010-2772', 'Stuxnet_0day']
                        setattr(host, 'temperature', float(random.randint(40, 60)))
                        setattr(host, 'pressure', float(random.randint(90, 110)))
                    else:
                        profiles = [
                            (
                                'Windows_Server_2016',
                                ['SMB', 'IIS'],
                                ['MS17-010', 'CVE-2021-44228'],
                            ),
                            (
                                'Windows_10',
                                ['RDP', 'SMB'],
                                ['CVE-2019-0708', 'MS17-010'],
                            ),
                            (
                                'Linux_Ubuntu',
                                ['SSH', 'Apache'],
                                ['CVE-2021-44228', 'V4L2'],
                            ),
                            ('Linux_CentOS', ['SSH', 'Tomcat'], ['CVE-2021-44228']),
                        ]
                        chosen_os, chosen_services, potential_cves = random.choice(
                            profiles
                        )

                    host.os = chosen_os
                    host.services = chosen_services
                    host.cvss_score = round(random.uniform(3.5, 9.8), 1)

                    # Human error dynamics: Linux admins fall for phishing less often than generalized Windows Corporate users
                    base_phish = (
                        random.uniform(0.1, 0.4)
                        if 'Linux' in chosen_os
                        else random.uniform(0.3, 0.9)
                    )
                    host.human_vulnerability_score = round(base_phish, 2)

                    num_vulns = random.randint(0, min(2, len(potential_cves)))
                    host.vulnerabilities = random.sample(potential_cves, num_vulns)

                    # Designate Domain Controllers only in Corp or Secure Windows servers
                    if 'Windows' in chosen_os and name in ['Corporate', 'Secure']:
                        if random.random() < 0.3:
                            domain_controllers.append(host)

                active_hosts.append(host)
                state.register_host(host)
                G.add_node(host.ip, type=name)

        # Assure at least 1 Domain Controller exists
        if domain_controllers:
            random.choice(domain_controllers).is_domain_controller = True
        else:
            # Force upgrade a random Windows host
            win_hosts = [h for h in active_hosts if 'Windows' in h.os]
            if win_hosts:
                random.choice(win_hosts).is_domain_controller = True

        # Fill strictly to 50 nodes for Neural Network shape constant
        padding_needed = 50 - len(state.all_hosts)
        for p in range(padding_needed):
            pad_ip = f'169.254.0.{p + 1}'
            pad_host = Host(
                ip=pad_ip, hostname=f'Pad_Node_{p}', subnet_cidr='169.254.0.0/16'
            )
            pad_host.status = 'isolated'  # Native Action Masking bounds
            state.register_host(pad_host)

        self._configure_procedural_vision(state)
        return state

    def _configure_procedural_vision(self, state: GlobalNetworkState):
        """Builds fog-of-war vision depending on the layout."""
        # Red baseline starts in DMZ
        for host in state.all_hosts.values():
            if host.subnet_cidr == '192.168.1.0/24' and host.status != 'isolated':
                state.update_knowledge('red_commander', host.ip)
                state.update_knowledge('red_operator', host.ip)
                break

        # Blue knows all active topology natively but is blind to zero-padded isolated objects
        for host in state.all_hosts.values():
            if host.status != 'isolated':
                state.update_knowledge('blue_commander', host.ip)
                state.update_knowledge('blue_operator', host.ip)

    def _load_from_yaml(self, path: str) -> GlobalNetworkState:
        """Loads a deterministic graph from a YAML configuration."""
        with open(path, 'r') as f:
            _ = yaml.safe_load(f)

        # Implementation left for future expansion if YAML is required.
        # Defaults to procedural if parsing fails.
        return self._generate_procedural()
