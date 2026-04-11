from typing import Dict
from netforge_rl.core.action import ActionEffect


class ConflictResolutionEngine:
    """Strategy pattern engine defining the physical constraints of action collisions.
    Mathematically resolves simultaneous temporal collisions.
    """

    @staticmethod
    def resolve(effects: Dict[str, ActionEffect]) -> Dict[str, ActionEffect]:
        """Core physics engine.

        Priority: Blue Defensive actions generally supersede Red Offensive actions
        on the exact same network node if executed in the exact same elapsed fractional tick.
        """
        red_agents = [a for a in effects if 'red' in a.lower()]
        blue_agents = [a for a in effects if 'blue' in a.lower()]

        # 1. Compile all Blue defensive targets
        blue_defended_nodes = {}
        for blue_id in blue_agents:
            eff = effects[blue_id]
            if eff is not None and eff.success:
                if isinstance(eff.state_deltas, dict):
                    for delta_key in eff.state_deltas.keys():
                        if 'hosts/' in delta_key:
                            target_ip = delta_key.split('/')[1]
                            blue_defended_nodes[target_ip] = True
                elif isinstance(eff.state_deltas, list):
                    for delta_obj in eff.state_deltas:
                        if getattr(delta_obj, 'target_ip', None):
                            blue_defended_nodes[delta_obj.target_ip] = True

        # 2. Evaluate Red attacks against the compiled simultaneous defenses
        for red_id in red_agents:
            red_eff = effects[red_id]
            if red_eff is None or not red_eff.success:
                continue

            collision_detected = False

            # Check dictionary deltas
            if isinstance(red_eff.state_deltas, dict):
                for delta_key in list(red_eff.state_deltas.keys()):
                    if 'hosts/' in delta_key:
                        target_ip = delta_key.split('/')[1]
                        if target_ip in blue_defended_nodes:
                            collision_detected = True
                            break
            # Check command object deltas
            elif isinstance(red_eff.state_deltas, list):
                for delta_obj in red_eff.state_deltas:
                    if getattr(delta_obj, 'target_ip', None) in blue_defended_nodes:
                        collision_detected = True
                        break

            if collision_detected:
                # Nullify Red's attack effect entirely and alert the network telemetry
                effects[red_id].success = False
                effects[red_id].state_deltas = (
                    [] if isinstance(red_eff.state_deltas, list) else {}
                )
                effects[red_id].observation_data['alert'] = (
                    'TEMPORAL_COLLISION_DEFENSE_SUPREMACY'
                )

        return effects
