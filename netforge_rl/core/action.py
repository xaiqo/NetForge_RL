from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, TYPE_CHECKING, Union, List

if TYPE_CHECKING:
    from netforge_rl.core.state import GlobalNetworkState
    from netforge_rl.core.commands import IStateDeltaCommand


class ActionEffect:
    """Encapsulates the resulting state changes from an action for conflict

    resolution.
    """

    def __init__(
        self,
        success: bool,
        state_deltas: Union[Dict[str, Any], List['IStateDeltaCommand']],
        observation_data: Dict[str, Any],
        eta: int = 0,
    ):
        self.success = success
        self.state_deltas = state_deltas
        self.observation_data = observation_data
        self.eta = eta


class BaseAction(ABC):
    """Modular Base Action for the MARL CybORG Environment.

    All highly specific network attacks (Layer 2 - Layer 7) inherit from this class.
    """

    def __init__(
        self,
        agent_id: str,
        target_ip: Optional[str] = None,
        source_ip: Optional[str] = None,
        cost: int = 1,
        financial_cost: int = 0,
        compute_cost: int = 0,
        duration: int = 1,
        required_prior_state: Optional[str] = None,
    ):
        self.agent_id = agent_id
        self.target_ip = target_ip
        self.source_ip = source_ip
        self.cost = cost
        self.financial_cost = financial_cost
        self.compute_cost = compute_cost
        self.duration = duration
        self.required_prior_state = required_prior_state

    def validate(self, global_state: 'GlobalNetworkState') -> bool:
        """Checks if the action is physically possible in the current network
        state (e.g., is there a route, are preconditions met).
        """
        if self.target_ip and self.target_ip not in global_state.all_hosts:
            return False

        if self.required_prior_state:
            # Check Action History state logic
            agent_history = global_state.action_history.get(self.agent_id, set())
            expected_record = f'{self.required_prior_state}:{self.target_ip}'
            if expected_record not in agent_history:
                return False

        if self.target_ip:
            host = global_state.all_hosts[self.target_ip]
            # Simple declarative Zone constraints example
            if 'red' in self.agent_id.lower() and host.subnet_cidr == '10.0.1.0/24':
                # Secure Data targets cannot be touched without pivoting via DMZ or Internal User privileges first
                has_dmz = any(
                    h.privilege in ['User', 'Root']
                    for h in global_state.all_hosts.values()
                    if h.subnet_cidr == '192.168.1.0/24'
                )
                has_internal = any(
                    h.privilege in ['User', 'Root']
                    for h in global_state.all_hosts.values()
                    if h.subnet_cidr == '10.0.0.0/24'
                )
                if not (has_dmz or has_internal):
                    return False

        return True

    @abstractmethod
    def execute(self, global_state: 'GlobalNetworkState') -> ActionEffect:
        """Computes the theoretical effect of the action.

        Note: State is NOT mutated directly here. Mutations are returned via ActionEffect
        to allow the Environment to resolve simultaneous multi-agent collisions.
        """
        pass
