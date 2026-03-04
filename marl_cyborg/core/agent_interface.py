from abc import ABC, abstractmethod
from typing import Optional
from marl_cyborg.core.observation import BaseObservation
from marl_cyborg.core.action import BaseAction


class AgentInterface(ABC):
    """
    Defines the contract for Agents interacting with the MARL Environment.
    Can be backed by an RL Policy, a Heuristic Script, or a Human CLI.
    """

    def __init__(self, agent_id: str, team_name: str):
        self.agent_id = agent_id
        self.team_name = team_name  # e.g., "Red", "Blue", "Green"
        self.current_observation: Optional[BaseObservation] = None

    @abstractmethod
    def get_action(self, observation: BaseObservation) -> BaseAction:
        """
        Given the current observation, policy decides the next logical BaseAction.
        """
        pass
