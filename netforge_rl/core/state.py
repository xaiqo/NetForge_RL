import numpy as np
from typing import Dict, Set, Any


class Host:
    def __init__(self, ip: str, hostname: str, subnet_cidr: str):
        self.ip = ip
        self.hostname = hostname
        self.subnet_cidr = subnet_cidr
        self.status = 'online'  # "online" or "isolated"
        self.privilege = 'None'  # "None", "User", "Root"
        self.decoy = 'inactive'  # "inactive" or "active"
        self.compromised_by = 'None'  # Tracks agent ID responsible for breach
        self.edr_active = False  # Track endpoint monitoring telemetry status
        self.os: str = 'Unknown'  # OS profile assigned by NetworkGenerator
        self.services: list = []  # Running services (SSH, SMB, etc.)
        self.vulnerabilities: list = []  # CVEs present on this host
        self.is_domain_controller: bool = False  # Allows Pass-the-Hash if Rooted
        self.human_vulnerability_score: float = (
            0.5  # Phishability indicator (0.0 to 1.0)
        )
        self.contains_honeytokens: bool = (
            False  # Triggers 100% confidence active deception traps
        )
        # Identity-Driven Zero Trust Networking Arrays
        self.cached_credentials: list = []  # Dumped via LSASS
        self.system_tokens: list = []  # Required to breach or ping node natively

    def __repr__(self):
        return (
            f'<Host {self.ip} | Priv: {self.privilege} | Breach: {self.compromised_by}>'
        )


class Subnet:
    def __init__(self, cidr: str, name: str):
        self.cidr = cidr
        self.name = name
        self.hosts: Dict[str, Host] = {}

    def add_host(self, host: Host):
        self.hosts[host.ip] = host


class Firewall:
    def __init__(self, name: str):
        self.name = name
        self.rules: Dict[tuple[str, int], str] = {}

    def block_port(self, target_subnet: str, port: int):
        self.rules[(target_subnet, port)] = 'block'

    def is_blocked(self, target_subnet: str, port: int) -> bool:
        return self.rules.get((target_subnet, port)) == 'block'


class GlobalNetworkState:
    """The Single Source of Truth for the H-MARL Physics Engine.

    Tracks all Subnets, Hosts, and current privilege/isolation statuses.
    """

    def __init__(self):
        self.subnets: Dict[str, Subnet] = {}
        self.all_hosts: Dict[str, Host] = {}
        self.firewalls: Dict[str, Firewall] = {}

        # Tracks which IPs each agent currently knows about (Fog of War)
        self.agent_knowledge: Dict[str, Set[str]] = {}
        # Tracks logical identity tokens/hashes stolen during lateral movement (Zero Trust)
        self.agent_inventory: Dict[str, set] = {}

        # Tracks remaining energy/budget for temporal action constraints
        self.agent_energy: Dict[str, int] = {}
        # Advanced Attack Economics Constraints
        self.agent_funds: Dict[str, int] = {}
        self.agent_compute: Dict[str, int] = {}
        self.business_downtime_score: float = 0.0

        # Tracks asynchronous execution locks (ETA system)
        self.agent_locked_until: Dict[str, int] = {}
        self.action_history: Dict[str, set] = {}
        self.pending_effects: list = []
        self.siem_log_buffer: list = []
        self.current_tick: int = 0
        self.active_sessions: Dict[str, list] = {}
        self.subnet_bandwidth: Dict[str, int] = {}

    def update_knowledge(self, agent_id: str, ip: str):
        """Adds an IP address to the agent's knowledge graph."""
        if agent_id not in self.agent_knowledge:
            self.agent_knowledge[agent_id] = set()
        self.agent_knowledge[agent_id].add(ip)

    def add_subnet(self, subnet: Subnet):
        self.subnets[subnet.cidr] = subnet

    def register_host(self, host: Host):
        """Registers a host to both the global fast-lookup and its specific

        subnet.
        """
        self.all_hosts[host.ip] = host
        if host.subnet_cidr in self.subnets:
            self.subnets[host.subnet_cidr].add_host(host)

    def apply_delta(self, delta_key: Any, delta_value: Any = None):
        """Dynamically mutates the network graph.

        Now supports standard OOP `IStateDeltaCommand` objects executing their
        own state mutations, while retaining legacy string-path parsing for compatibility.
        """
        # Command Pattern Standard Execution
        if hasattr(delta_key, 'execute') and callable(getattr(delta_key, 'execute')):
            delta_key.execute(self)
            return

        # Legacy String parsing (Deprecation Path)
        if not isinstance(delta_key, str):
            from netforge_rl.core.commands import IStateDeltaCommand

            if isinstance(delta_key, IStateDeltaCommand):
                delta_key.execute(self)
            return

        parts = delta_key.split('/')
        if parts[0] == 'hosts' and len(parts) == 3:
            ip = parts[1]
            attribute = parts[2]

            if ip in self.all_hosts:
                host = self.all_hosts[ip]
                # Directly mutate the object property via setattr
                if hasattr(host, attribute):
                    setattr(host, attribute, delta_value)

        elif parts[0] == 'knowledge' and len(parts) == 3:
            agent_id = parts[1]
            ip = parts[2]
            self.update_knowledge(agent_id, ip)

        elif parts[0] == 'firewall' and parts[1] == 'block' and len(parts) == 4:
            subnet = parts[2].replace('_slash_', '/')
            port = int(parts[3])
            if 'global' not in self.firewalls:
                self.firewalls['global'] = Firewall('global')
            self.firewalls['global'].block_port(subnet, port)

        elif parts[0] == 'history' and len(parts) == 3:
            agent_id = parts[1]
            record = parts[2]
            if agent_id not in self.action_history:
                self.action_history[agent_id] = set()
            self.action_history[agent_id].add(record)

    def can_route_to(
        self, target_ip: str, port: int = None, agent_id: str = None
    ) -> bool:
        """Evaluates complex network topology rules for routing
        reachability and explicit firewall port blocks. Now enforces
        strict Zero-Trust Identity rules.
        """
        if target_ip not in self.all_hosts:
            return False

        host = self.all_hosts[target_ip]
        if host.status == 'isolated':
            return False

        target_subnet = host.subnet_cidr

        if port is not None:
            for firewall in self.firewalls.values():
                if firewall.is_blocked(target_subnet, port):
                    return False

        if target_subnet == '192.168.1.0/24':  # DMZ
            return True

        has_dmz_pivot = any(
            h.privilege in ['User', 'Root']
            for h in self.all_hosts.values()
            if h.subnet_cidr == '192.168.1.0/24'
        )

        if target_subnet == '10.0.0.0/24':  # Corporate
            return has_dmz_pivot

        has_corp_pivot = any(
            h.privilege in ['User', 'Root']
            for h in self.all_hosts.values()
            if h.subnet_cidr == '10.0.0.0/24'
        )

        if target_subnet == '10.0.1.0/24':  # Secure
            if not (has_dmz_pivot or has_corp_pivot):
                return False

            # ZERO TRUST IDENTITY CHECK
            # If the Red agent attempts to cross into Secure, they MUST have the Domain Admin Token!
            if agent_id and agent_id.startswith('red'):
                agent_hash_inventory = self.agent_inventory.get(agent_id, set())
                # If ANY token listed in the target's required system_tokens matches the agent's inventory
                # OR if the target specifically requires 'Enterprise_Admin_Token', verify it.
                if 'Enterprise_Admin_Token' not in agent_hash_inventory:
                    return False

            return True

        return False

    def get_adjacency_matrix(self) -> np.ndarray:
        """Returns a 100x100 adjacency matrix representing routing capabilities between all hosts."""
        import numpy as np

        adj = np.zeros((100, 100), dtype=np.float32)

        # We need a stable ordering of IPs, so we sort them
        sorted_ips = sorted(list(self.all_hosts.keys()))

        for i, src_ip in enumerate(sorted_ips):
            for j, dst_ip in enumerate(sorted_ips):
                if i == j:
                    adj[i, j] = 1.0
                elif self.can_route_to(dst_ip):
                    # Simplification: if it can route to dst, we mark an edge.
                    # A more accurate version would check if src_ip can route to dst_ip,
                    # but can_route_to doesn't take src_ip. It assumes global routing rules based on subnets.
                    adj[i, j] = 1.0

        return adj

    def reallocate_dhcp(self):
        """Simulates dynamic mid-episode restructuring of the network.

        Shuffles the IP addresses of Hosts on Internal and Secure
        subnets. Strips the stale IPs from agent knowledge vectors
        mechanically without notification.
        """
        import random

        for subnet in self.subnets.values():
            if '192.168.1' in subnet.cidr:
                continue  # Skip DMZ so red agents don't completely lose initial routing access

            hosts = list(subnet.hosts.values())
            if not hosts:
                continue

            base_ip = subnet.cidr.split('.0/')[0]
            new_ips = random.sample(range(1, 250), len(hosts))

            new_subnet_hosts = {}
            for i, host in enumerate(hosts):
                # Erase old routing (guard against duplicate/stale IPs)
                self.all_hosts.pop(host.ip, None)

                # Assign new IP
                host.ip = f'{base_ip}.{new_ips[i]}'

                # Establish new routing table entries
                self.all_hosts[host.ip] = host
                new_subnet_hosts[host.ip] = host

            subnet.hosts = new_subnet_hosts
