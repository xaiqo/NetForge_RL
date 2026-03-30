import abc
import numpy as np
from pettingzoo import ParallelEnv
from typing import Dict, Tuple, Any


class BaseNetForgeRLEnv(ParallelEnv, abc.ABC):
    """Abstract Base Class for all Continuous-Time MARL environments in CybORG.

    This guarantees that future environments (e.g., custom network
    topologies, different RLlib integrations, or new MARL libraries)
    strictly adhere to the native PettingZoo Parallel API standard while
    using CybORG's physics engine.
    """

    @abc.abstractmethod
    def __init__(self, scenario_config: dict):
        """Initializes the active scenario and network state."""
        pass

    @abc.abstractmethod
    def reset(
        self, seed=None, options=None
    ) -> Tuple[Dict[str, np.ndarray], Dict[str, dict]]:
        """Resets the environment safely and returns the initial observation

        tensors.
        """
        pass

    @abc.abstractmethod
    def step(
        self, agent_actions: Dict[str, Any]
    ) -> Tuple[
        Dict[str, np.ndarray],
        Dict[str, float],
        Dict[str, bool],
        Dict[str, bool],
        Dict[str, dict],
    ]:
        """The core physics loop bridging actions to state mutations.

        Must strictly return: (observations, rewards, terminations, truncations, infos)
        """
        pass

