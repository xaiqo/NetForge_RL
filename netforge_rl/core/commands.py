from abc import ABC, abstractmethod
from typing import Any, Optional


class IStateDeltaCommand(ABC):
    """Abstract Command interface for Object-Oriented state mutation.
    Allows for decoupled physics application dynamically processed by the Resolve engine.
    """
    @abstractmethod
    def execute(self, global_state: Any):
        pass

    @property
    @abstractmethod
    def target_ip(self) -> Optional[str]:
        """Exposes the primary target IP so the Action Resolver can detect temporal collisions."""
        pass


class UpdateKnowledgeCommand(IStateDeltaCommand):
    def __init__(self, agent_id: str, ip: str, value: Any = True):
        self.agent_id = agent_id
        self._target_ip = ip
        self.value = value

    @property
    def target_ip(self) -> Optional[str]:
        return self._target_ip

    def execute(self, global_state: Any):
        global_state.update_knowledge(self.agent_id, self.target_ip)


class UpdateHostPrivilegeCommand(IStateDeltaCommand):
    def __init__(self, ip: str, privilege: str, compromised_by: Optional[str] = None):
        self._target_ip = ip
        self.privilege = privilege
        self.compromised_by = compromised_by

    @property
    def target_ip(self) -> Optional[str]:
        return self._target_ip

    def execute(self, global_state: Any):
        if self._target_ip in global_state.all_hosts:
            host = global_state.all_hosts[self._target_ip]
            host.privilege = self.privilege
            if self.compromised_by:
                host.compromised_by = self.compromised_by


class UpdateHostStatusCommand(IStateDeltaCommand):
    def __init__(self, ip: str, status: str):
        self._target_ip = ip
        self.status = status

    @property
    def target_ip(self) -> Optional[str]:
        return self._target_ip

    def execute(self, global_state: Any):
        if self._target_ip in global_state.all_hosts:
            global_state.all_hosts[self._target_ip].status = self.status


class UpdateServiceCommand(IStateDeltaCommand):
    def __init__(self, ip: str, service: str, action: str = 'remove'):
        self._target_ip = ip
        self.service = service
        self.action = action

    @property
    def target_ip(self) -> Optional[str]:
        return self._target_ip

    def execute(self, global_state: Any):
        if self._target_ip in global_state.all_hosts:
            host = global_state.all_hosts[self._target_ip]
            if self.action == 'remove' and self.service in host.services:
                host.services.remove(self.service)
            elif self.action == 'add' and self.service not in host.services:
                host.services.append(self.service)


class BlockPortCommand(IStateDeltaCommand):
    def __init__(self, subnet: str, port: int):
        self.subnet = subnet
        self.port = port

    @property
    def target_ip(self) -> Optional[str]:
        return None  # Targets a subnet firewall, not a single node

    def execute(self, global_state: Any):
        if 'global' not in global_state.firewalls:
            # We import here to avoid circular dependencies if needed depending on global state structure
            from netforge_rl.core.state import Firewall
            global_state.firewalls['global'] = Firewall('global')
        global_state.firewalls['global'].block_port(self.subnet, self.port)


class AddHistoryCommand(IStateDeltaCommand):
    def __init__(self, agent_id: str, record: str):
        self.agent_id = agent_id
        self.record = record

    @property
    def target_ip(self) -> Optional[str]:
        return None  # Targeting agent logic

    def execute(self, global_state: Any):
        if self.agent_id not in global_state.action_history:
            global_state.action_history[self.agent_id] = set()
        global_state.action_history[self.agent_id].add(self.record)


class UpdateDecoyCommand(IStateDeltaCommand):
    def __init__(self, ip: str, decoy_type: str):
        self._target_ip = ip
        self.decoy_type = decoy_type

    @property
    def target_ip(self) -> Optional[str]:
        return self._target_ip

    def execute(self, global_state: Any):
        if self._target_ip in global_state.all_hosts:
            global_state.all_hosts[self._target_ip].decoy = self.decoy_type


class EstablishSessionCommand(IStateDeltaCommand):
    def __init__(self, agent_id: str, ip: str, port: int):
        self.agent_id = agent_id
        self._target_ip = ip
        self.port = port

    @property
    def target_ip(self) -> Optional[str]:
        return self._target_ip

    def execute(self, global_state: Any):
        if self.agent_id not in global_state.active_sessions:
            global_state.active_sessions[self.agent_id] = []
        global_state.active_sessions[self.agent_id].append({'ip': self._target_ip, 'port': self.port})


class DropSessionCommand(IStateDeltaCommand):
    def __init__(self, ip: str):
        self._target_ip = ip

    @property
    def target_ip(self) -> Optional[str]:
        return self._target_ip

    def execute(self, global_state: Any):
        for agent_id, sessions in global_state.active_sessions.items():
            global_state.active_sessions[agent_id] = [s for s in sessions if s['ip'] != self._target_ip]


class ConsumeBandwidthCommand(IStateDeltaCommand):
    def __init__(self, subnet: str, amount: int):
        self.subnet = subnet
        self.amount = amount

    @property
    def target_ip(self) -> Optional[str]:
        return None  # Targets a subnet-wide telemetry pipe, not a single node

    def execute(self, global_state: Any):
        if self.subnet not in global_state.subnet_bandwidth:
            global_state.subnet_bandwidth[self.subnet] = 0
            
        global_state.subnet_bandwidth[self.subnet] += self.amount
        
        # Volumetric SIEM Trigger Rule
        # If any subnet spikes above 1000 units in a single tick, generate a SIEM log.
        if global_state.subnet_bandwidth[self.subnet] > 1000:
            volumetric_alert = {'type': 'volumetric_anomaly', 'subnet': self.subnet, 'severity': 'High'}
            if volumetric_alert not in global_state.siem_log_buffer:
                global_state.siem_log_buffer.append(volumetric_alert)
