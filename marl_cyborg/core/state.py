from typing import Dict, Set


class Host:
    def __init__(self, ip: str, hostname: str, subnet_cidr: str):
        self.ip = ip
        self.hostname = hostname
        self.subnet_cidr = subnet_cidr
        self.status = 'online'  # "online" or "isolated"
        self.privilege = 'None'  # "None", "User", "Root"
        self.decoy = 'inactive'  # "inactive" or "active"
        self.compromised_by = 'None'  # Tracks agent ID responsible for breach

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
        # Tracks remaining energy/budget for temporal action constraints
        self.agent_energy: Dict[str, int] = {}
        # Tracks asynchronous execution locks (ETA system)
        self.agent_locked_until: Dict[str, int] = {}
        self.pending_effects: list = []

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

    def apply_delta(self, delta_key: str, delta_value: str):
        """Dynamically mutates the network graph based on dot-notation paths.

        Example: apply_delta("hosts/10.0.0.5/status", "isolated")
        Example: apply_delta("knowledge/red_agent_0/10.0.0.5", "True")
        """
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

    def can_route_to(self, target_ip: str, port: int = None) -> bool:
        """Evaluates complex network topology rules for routing
        reachability and explicit firewall port blocks.
        """
        if target_ip not in self.all_hosts:
            return False

        target_subnet = self.all_hosts[target_ip].subnet_cidr

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
            return has_dmz_pivot or has_corp_pivot

        return False

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
                # Erase old routing
                del self.all_hosts[host.ip]

                # Assign new IP
                host.ip = f'{base_ip}.{new_ips[i]}'

                # Establish new routing table entries
                self.all_hosts[host.ip] = host
                new_subnet_hosts[host.ip] = host

            subnet.hosts = new_subnet_hosts
