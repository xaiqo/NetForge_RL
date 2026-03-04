from typing import Any
import random
import numpy as np


class BLineAgent:
    """
    Scripted Red Agent that executes the exact B-Line killchain:

    DiscoverRemoteSystems -> DiscoverNetworkServices -> ExploitRemoteService -> PrivilegeEscalate -> Impact
    """

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.known_subnets = ['10.0.0.0/24', '192.168.1.0/24', '10.0.1.0/24']
        self.known_hosts = []
        self.exploited_hosts = []
        self.root_hosts = []
        self.impacted_hosts = []
        self.step_count = 0

    def get_action(self, observation: np.ndarray, global_state) -> Any:
        from marl_cyborg.actions import (
            DiscoverRemoteSystems,
            DiscoverNetworkServices,
            ExploitRemoteService,
            PrivilegeEscalate,
            Impact,
        )

        self.step_count += 1

        # 1. Discover Subnets if we don't know network yet
        if not self.known_hosts or self.step_count < 3:
            target_subnet = self.known_subnets[
                self.step_count % len(self.known_subnets)
            ]
            # Oracle gets to peek at true state to simulate finding hosts
            for host in global_state.all_hosts.values():
                if (
                    host.subnet_cidr == target_subnet
                    and host.ip not in self.known_hosts
                ):
                    self.known_hosts.append(host.ip)
            return DiscoverRemoteSystems(self.agent_id, target_subnet)

        # 2. Exploit known hosts if reachable
        unexploited = [
            h
            for h in self.known_hosts
            if h not in self.exploited_hosts and global_state.can_route_to(h)
        ]
        if unexploited:
            target = random.choice(unexploited)
            self.exploited_hosts.append(target)
            return ExploitRemoteService(self.agent_id, target)

        # 3. Escalate privileges
        unescalated = [h for h in self.exploited_hosts if h not in self.root_hosts]
        if unescalated:
            target = random.choice(unescalated)
            self.root_hosts.append(target)
            return PrivilegeEscalate(self.agent_id, target)

        # 4. Impact fully compromised nodes
        unimpacted = [h for h in self.root_hosts if h not in self.impacted_hosts]
        if unimpacted:
            target = random.choice(unimpacted)
            self.impacted_hosts.append(target)
            return Impact(self.agent_id, target)

        # Fallback to random scanning
        target = random.choice(self.known_hosts) if self.known_hosts else '127.0.0.1'
        return DiscoverNetworkServices(self.agent_id, target)
