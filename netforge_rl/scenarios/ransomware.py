from typing import TYPE_CHECKING, Dict
from netforge_rl.scenarios.base_scenario import BaseScenario

if TYPE_CHECKING:
    from netforge_rl.core.state import GlobalNetworkState
    from netforge_rl.core.action import ActionEffect


class RansomwareScenario(BaseScenario):
    """
    Scenario: Red Team aggressively deploys ransomware.

    Reward Design Principles:
    ─────────────────────────
    • Action-level rewards are given ONCE on the step the action succeeds.
    • NO per-step state compounding (avoids runaway accumulation).
    • Episode-end bonus/penalty based on final network state.
    • Red and Blue reward magnitudes are balanced (~±5 per action).
    """

    def __init__(self, agents):
        self.agents = agents

    def calculate_reward(
        self,
        agent_id: str,
        global_state: 'GlobalNetworkState',
        effect: 'ActionEffect' = None,
    ) -> float:
        reward = 0.0

        # Small energy cost penalty for any action
        if effect and getattr(effect, 'cost', 0) > 0:
            reward -= effect.cost * 0.05

        if 'red' in agent_id.lower():
            reward += self._red_reward(agent_id, global_state, effect)
        elif 'blue' in agent_id.lower():
            reward += self._blue_reward(agent_id, global_state, effect)

        return reward

    # ── Red Team Rewards ──────────────────────────────────────

    def _red_reward(
        self,
        agent_id: str,
        global_state: 'GlobalNetworkState',
        effect: 'ActionEffect' = None,
    ) -> float:
        reward = 0.0

        if not effect:
            return reward

        # ── ONE-TIME action bonuses (only on success) ─────────
        if effect.success and effect.state_deltas:
            for delta_key, delta_val in effect.state_deltas.items():
                # Initial compromise (None → User)
                if 'privilege' in delta_key and delta_val == 'User':
                    reward += 3.0

                # Privilege escalation (User → Root)
                elif 'privilege' in delta_key and delta_val == 'Root':
                    reward += 5.0

                # Ransomware impact (system_integrity → compromised)
                elif 'system_integrity' in delta_key and delta_val == 'compromised':
                    reward += 10.0

                # Setting compromised_by (confirms exploitation)
                elif 'compromised_by' in delta_key and delta_val != 'None':
                    reward += 2.0

                # OT / SCADA Catastrophic Win
                elif (
                    'system_integrity' in delta_key
                    and delta_val == 'kinetic_destruction'
                ):
                    reward += 10000.0

        # ── Observation-based rewards ─────────────────────────
        if effect.observation_data:
            obs = effect.observation_data

            # Reconnaissance discoveries
            if 'discovered_hosts' in obs:
                discovered = obs['discovered_hosts']
                count = len(discovered) if isinstance(discovered, (list, set)) else 1
                reward += count * 0.5

            if 'scan_results' in obs:
                reward += 0.3

            # Intelligence sharing
            if 'shared' in obs:
                reward += 1.0

            # Penalties for failures
            if 'Failed against Decoy' in str(obs.values()):
                reward -= 3.0
            elif 'kernel panic' in str(obs.values()):
                reward -= 5.0

        # ── Failed action penalty ─────────────────────────────
        if not effect.success:
            reward -= 0.1  # Small penalty for wasted turn

        return reward

    # ── Blue Team Rewards ─────────────────────────────────────

    def _blue_reward(
        self,
        agent_id: str,
        global_state: 'GlobalNetworkState',
        effect: 'ActionEffect' = None,
    ) -> float:
        reward = 0.0

        # ── ONE-TIME action bonuses ───────────────────────────
        if effect and effect.success and effect.state_deltas:
            for delta_key, delta_val in effect.state_deltas.items():
                # Successful isolation
                if 'status' in delta_key and delta_val == 'isolated':
                    ip = delta_key.split('/')[1] if '/' in delta_key else None
                    if ip:
                        host = global_state.all_hosts.get(ip)
                        if host and host.compromised_by != 'None':
                            reward += 5.0  # Correctly quarantined a compromised host
                        else:
                            reward -= 2.0  # False positive — isolated a clean host

                # Successful restoration/cleanup
                elif 'privilege' in delta_key and delta_val == 'None':
                    reward += 3.0  # Successfully cleaned a host

                elif 'status' in delta_key and delta_val == 'online':
                    reward += 1.0  # Restored connectivity

                # Deployed a decoy
                elif 'decoy' in delta_key and delta_val != 'inactive':
                    reward += 1.0  # Proactive defense

                # Failed to prevent Kinetic Destruction of SCADA framework
                elif (
                    'system_integrity' in delta_key
                    and delta_val == 'kinetic_destruction'
                ):
                    reward -= 10000.0

        # ── Per-step network health (small, bounded) ──────────
        # Only count the RATIO of healthy hosts to avoid scale issues
        total_hosts = max(len(global_state.all_hosts), 1)
        healthy = sum(
            1
            for h in global_state.all_hosts.values()
            if h.compromised_by == 'None' and h.status != 'isolated'
        )
        health_ratio = healthy / total_hosts
        reward += health_ratio * 1.0  # 0.0 to 1.0 per step

        # Small penalty proportional to compromised hosts
        compromised = sum(
            1
            for h in global_state.all_hosts.values()
            if h.compromised_by != 'None' and h.status != 'isolated'
        )
        if compromised > 0:
            reward -= (compromised / total_hosts) * 2.0  # 0.0 to -2.0

        # ── Business Downtime Penalty (Economics) ─────────────
        total_isolated = sum(
            1
            for h in global_state.all_hosts.values()
            if h.status == 'isolated' and h.subnet_cidr != '169.254.0.0/16'
        )
        if total_isolated > 0:
            business_loss = (total_isolated / total_hosts) * 5.0
            global_state.business_downtime_score += business_loss
            reward -= business_loss

        # ── Failed action penalty ─────────────────────────────
        if effect and not effect.success:
            reward -= 0.1

        return reward

    def check_termination(self, global_state: 'GlobalNetworkState') -> Dict[str, bool]:
        terminate = {agent: False for agent in self.agents}

        # If all critical Corporate/Secure hosts are compromised, episode ends
        target_hosts = [
            h
            for h in global_state.all_hosts.values()
            if h.subnet_cidr in ['10.0.0.0/24', '10.0.1.0/24']
        ]

        if target_hosts and all(
            getattr(h, 'system_integrity', 'clean') == 'compromised'
            for h in target_hosts
        ):
            return {agent: True for agent in self.agents}

        # Terminal Fail-State for Blue: A PLC has been physically destroyed
        if any(
            getattr(h, 'system_integrity', 'clean') == 'kinetic_destruction'
            for h in global_state.all_hosts.values()
        ):
            return {agent: True for agent in self.agents}

        return terminate
