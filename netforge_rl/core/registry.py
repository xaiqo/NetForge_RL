from typing import Dict, Type, Optional, Callable
import inspect


class ActionRegistry:
    """A Factory Registry for dynamically tracking and instantiating
    BaseAction subclasses without monolithic if/else blocks.

    Adheres strictly to the Open-Closed Principle.
    """

    def __init__(self):
        # Maps (team, action_group_id) -> ActionClass
        self._actions: Dict[str, Dict[int, Type]] = {
            'red': {},
            'red_commander': {},
            'blue': {},
            'blue_commander': {},
        }

    def register(self, team: str, group_id: int) -> Callable:
        """Class decorator for registering an Action."""

        def decorator(cls):
            if team not in self._actions:
                self._actions[team] = {}
            self._actions[team][group_id] = cls
            return cls

        return decorator

    def get_action_class(self, agent_id: str, group_id: int) -> Optional[Type]:
        """Retrieves the class constructor for a specific integer offset."""
        if 'red' in agent_id.lower():
            team = 'red_commander' if 'commander' in agent_id.lower() else 'red'
        else:
            team = 'blue_commander' if 'commander' in agent_id.lower() else 'blue'

        return self._actions.get(team, {}).get(group_id)

    def instantiate_action(
        self, agent_id: str, action_data: object, target_ips: list
    ) -> Optional[object]:
        """Factory method to resolve the generic action payload to an instance.

        Supports legacy integer decoding or advanced Hierarchical MultiDiscrete
        arrays: [action_type_id, target_ip_index].
        """
        if not target_ips:
            target_ips = ['127.0.0.1']

        if (
            isinstance(action_data, (list, tuple))
            or type(action_data).__name__ == 'ndarray'
        ):
            # Hierarchical MultiDiscrete format
            action_type_id = int(action_data[0])
            target_index = int(action_data[1])
            target_ip = target_ips[target_index % len(target_ips)]
        else:
            # Legacy PettingZoo flat discrete space math
            action_int = int(action_data)
            target_ip = target_ips[action_int % len(target_ips)]
            action_group = action_int // len(target_ips)

            if 'red' in agent_id.lower():
                mod = 4 if 'commander' in agent_id.lower() else 11
            else:
                mod = 5 if 'commander' in agent_id.lower() else 7

            action_type_id = action_group % mod

        ActionCls = self.get_action_class(agent_id, action_type_id)
        if not ActionCls:
            return None

        # Pass required kwargs dynamically based on the action archetype
        # Determine accepted arguments dynamically
        sig = inspect.signature(ActionCls.__init__)
        params = sig.parameters

        kwargs = {'agent_id': agent_id}
        if 'target_ip' in params:
            kwargs['target_ip'] = target_ip
        elif 'target_subnet' in params:
            # Approximate subnet from target_ip for actions requiring Subnets
            parts = target_ip.split('.')
            kwargs['target_subnet'] = f'{parts[0]}.{parts[1]}.{parts[2]}.0/24'
        elif 'target_agent_id' in params:
            # Map target_agent_id randomly or conventionally for Coordination actions
            kwargs['target_agent_id'] = (
                'red_operator' if agent_id == 'red_commander' else 'red_commander'
            )

        return ActionCls(**kwargs)


action_registry = ActionRegistry()
