from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from marl_cyborg.core.state import GlobalNetworkState


class ActionEffect:
    """Encapsulates the resulting state changes from an action for conflict resolution."""

    def __init__(
        self,
        success: bool,
        state_deltas: Dict[str, Any],
        observation_data: Dict[str, Any],
    ):
        self.success = success
        self.state_deltas = state_deltas
        self.observation_data = observation_data


class BaseAction(ABC):
    """
    Modular Base Action for the MARL CybORG Environment.
    All highly specific network attacks (Layer 2 - Layer 7) inherit from this class.
    """

    def __init__(
        self,
        agent_id: str,
        target_ip: Optional[str] = None,
        source_ip: Optional[str] = None,
    ):
        self.agent_id = agent_id
        self.target_ip = target_ip
        self.source_ip = source_ip

    @abstractmethod
    def validate(self, global_state: 'GlobalNetworkState') -> bool:
        """
        Checks if the action is physically possible in the current network state
        (e.g., is there a route? is the port open?).
        """
        pass

    @abstractmethod
    def execute(self, global_state: 'GlobalNetworkState') -> ActionEffect:
        """
        Computes the theoretical effect of the action.
        Note: State is NOT mutated directly here. Mutations are returned via ActionEffect
        to allow the Environment to resolve simultaneous multi-agent collisions.
        """
        pass
