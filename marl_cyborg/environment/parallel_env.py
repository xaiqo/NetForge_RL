from typing import Dict, Tuple
import numpy as np
import gymnasium as gym

from marl_cyborg.core.action import BaseAction, ActionEffect
from marl_cyborg.core.observation import BaseObservation
from marl_cyborg.core.state import GlobalNetworkState, Subnet, Host
from marl_cyborg.environment.base_env import BaseMarlCyborg


class ParallelMarlCyborg(BaseMarlCyborg):
    """
    MARL Environment for CybORG.
    Follows the PettingZoo Parallel API standard for simultaneous Multi-Agent execution
    and relies exclusively on Gymnasium spaces natively.
    """

    metadata = {'render_modes': ['ansi'], 'name': 'marl_cyborg_v3'}

    def __init__(self, scenario_config: dict):
        self.global_state = self._initialize_network(scenario_config)
        self.possible_agents = [
            'red_commander',
            'red_operator',
            'blue_commander',
            'blue_operator',
        ]
        self.agents = self.possible_agents[:]

        # Native Gymnasium Spaces for PettingZoo API
        self.observation_spaces = {
            agent: gym.spaces.Box(low=-1.0, high=1.0, shape=(256,), dtype=np.float32)
            for agent in self.possible_agents
        }
        self.action_spaces = {
            agent: gym.spaces.Discrete(
                256
            )  # Expanded to natively support advanced actions across 40+ IPs
            for agent in self.possible_agents
        }
        self.max_steps = 100
        self.current_step = 0

    def _initialize_network(self, config):
        """Builds a deterministic 10-Node architecture across 3 Subnets for training."""
        state = GlobalNetworkState()

        corp_net = Subnet(cidr='10.0.0.0/24', name='Corporate')
        dmz_net = Subnet(cidr='192.168.1.0/24', name='DMZ')
        secure_net = Subnet(cidr='10.0.1.0/24', name='Secure')

        state.add_subnet(corp_net)
        state.add_subnet(dmz_net)
        state.add_subnet(secure_net)

        # Add entry nodes in DMZ
        state.register_host(
            Host(ip='192.168.1.5', hostname='Web_A', subnet_cidr='192.168.1.0/24')
        )
        state.register_host(
            Host(ip='192.168.1.6', hostname='Web_B', subnet_cidr='192.168.1.0/24')
        )

        # Add internal Corporate nodes
        for i in range(10, 16):
            state.register_host(
                Host(
                    ip=f'10.0.0.{i}', hostname=f'User_PC_{i}', subnet_cidr='10.0.0.0/24'
                )
            )

        # Add secure database nodes
        state.register_host(
            Host(ip='10.0.1.100', hostname='DB_Primary', subnet_cidr='10.0.1.0/24')
        )
        state.register_host(
            Host(ip='10.0.1.101', hostname='DB_Backup', subnet_cidr='10.0.1.0/24')
        )

        return state

    def reset(
        self, seed=None, options=None
    ) -> Tuple[Dict[str, np.ndarray], Dict[str, dict]]:
        """
        Resets the network state to initial configuration natively (Gymnasium style + PettingZoo).
        """
        self.agents = self.possible_agents[:]
        observations = {}
        for agent_id in self.agents:
            obs = BaseObservation(agent_id)
            obs.update_from_state(self.global_state, [])
            observations[agent_id] = obs.to_numpy(max_size=256)
        self.current_step = 0

        return observations, {agent: {} for agent in self.agents}

    def observation_space(self, agent):
        return self.observation_spaces[agent]

    def action_space(self, agent):
        return self.action_spaces[agent]

    def step(
        self, agent_actions: Dict[str, int]
    ) -> Tuple[
        Dict[str, BaseObservation],
        Dict[str, float],
        Dict[str, bool],
        Dict[str, bool],
        Dict[str, dict],
    ]:
        """
        Simultaneous Step Execution Logic:
        1. VALIDATION: Check if actions are physically possible.
        2. EXECUTION: Compute intended state changes (ActionEffects) WITHOUT mutating state yet.
        3. CONFLICT RESOLUTION: E.g., if Blue drops a connection while Red exploits it, Blue wins.
        4. MUTATION: Apply final resolved effects to the true global state.
        5. OBSERVATION: Re-calculate what each agent can see.
        """
        intended_effects = {}
        for agent, action_int in agent_actions.items():
            if isinstance(action_int, BaseAction):
                action = action_int
            else:
                action = self._decode_action(agent, int(action_int))

            if action.validate(self.global_state):
                intended_effects[agent] = action.execute(self.global_state)
            else:
                intended_effects[agent] = ActionEffect(
                    success=False, state_deltas={}, observation_data={}
                )

        resolved_effects = self._resolve_conflicts(intended_effects)

        self._apply_state_deltas(resolved_effects)

        observations = {}
        rewards = {}
        terminate = {agent: False for agent in self.agents}
        self.current_step += 1
        is_truncated = self.current_step >= self.max_steps
        truncate = {agent: is_truncated for agent in self.agents}

        for agent in self.agents:
            obs = BaseObservation(agent)
            obs.update_from_state(self.global_state, resolved_effects)

            obs_array = obs.to_numpy(max_size=256)
            if 'operator' in agent:
                commander_id = agent.replace('operator', 'commander')
                if commander_id in agent_actions:
                    cmd_action = agent_actions[commander_id]
                    # Normalize the Discrete(100) action to a float between 0.0 and 1.0
                    cmd_val = (
                        (float(cmd_action) / 100.0)
                        if not isinstance(cmd_action, BaseAction)
                        else 1.0
                    )
                    obs_array[0] = cmd_val

            observations[agent] = obs_array

            # Reward shaping applied here natively
            rewards[agent] = self._calculate_reward(agent, self.global_state)

        self.agents = [
            agent
            for agent in self.agents
            if not terminate[agent] and not truncate[agent]
        ]

        return observations, rewards, terminate, truncate, {a: {} for a in self.agents}

    def render(self):
        """Standard PettingZoo GUI logging render hook."""
        pass

    def _decode_action(self, agent_id: str, action_int: int) -> BaseAction:
        from marl_cyborg.actions import (
            IsolateHost,
            RestoreHost,
            Monitor,
            Analyze,
            DeployDecoy,
            Remove,
            RestoreFromBackup,
            DecoyApache,
            DecoySSHD,
            DecoyTomcat,
            Misinform,
            NetworkScan,
            DiscoverRemoteSystems,
            DiscoverNetworkServices,
            ExploitRemoteService,
            PrivilegeEscalate,
            Impact,
            ExploitBlueKeep,
            ExploitEternalBlue,
            ExploitHTTP_RFI,
            JuicyPotato,
            V4L2KernelExploit,
        )

        target_ips = sorted(list(self.global_state.all_hosts.keys()))
        if not target_ips:
            target_ips = ['127.0.0.1']

        target_ip = target_ips[action_int % len(target_ips)]
        action_group = action_int // len(target_ips)

        if 'red' in agent_id.lower():
            action_type = action_group % 11
            if action_type == 0:
                return NetworkScan(agent_id, '10.0.0.0/24')
            elif action_type == 1:
                return DiscoverRemoteSystems(agent_id, '10.0.0.0/24')
            elif action_type == 2:
                return DiscoverNetworkServices(agent_id, target_ip)
            elif action_type == 3:
                return ExploitRemoteService(agent_id, target_ip)
            elif action_type == 4:
                return PrivilegeEscalate(agent_id, target_ip)
            elif action_type == 5:
                return Impact(agent_id, target_ip)
            elif action_type == 6:
                return ExploitBlueKeep(agent_id, target_ip)
            elif action_type == 7:
                return ExploitEternalBlue(agent_id, target_ip)
            elif action_type == 8:
                return ExploitHTTP_RFI(agent_id, target_ip)
            elif action_type == 9:
                return JuicyPotato(agent_id, target_ip)
            else:
                return V4L2KernelExploit(agent_id, target_ip)
        else:
            action_type = action_group % 11
            if action_type == 0:
                return IsolateHost(agent_id, target_ip)
            elif action_type == 1:
                return RestoreHost(agent_id, target_ip)
            elif action_type == 2:
                return Monitor(agent_id, target_ip)
            elif action_type == 3:
                return Analyze(agent_id, target_ip)
            elif action_type == 4:
                return DeployDecoy(agent_id, target_ip)
            elif action_type == 5:
                return Remove(agent_id, target_ip)
            elif action_type == 6:
                return RestoreFromBackup(agent_id, target_ip)
            elif action_type == 7:
                return DecoyApache(agent_id, target_ip)
            elif action_type == 8:
                return DecoySSHD(agent_id, target_ip)
            elif action_type == 9:
                return DecoyTomcat(agent_id, target_ip)
            else:
                return Misinform(agent_id, target_ip)

    def _resolve_conflicts(
        self, effects: Dict[str, ActionEffect]
    ) -> Dict[str, ActionEffect]:
        """
        Core physics engine.
        Mathematically resolves simultaneous temporal collisions.
        Priority: Blue Defensive actions generally supersede Red Offensive actions
        on the exact same network node if executed in the exact same fraction of a second.
        """
        # Separate offensive and defensive intents
        red_agents = [a for a in effects if 'red' in a.lower()]
        blue_agents = [a for a in effects if 'blue' in a.lower()]

        # 1. Compile all Blue defensive targets and actions for this timestep
        blue_defended_nodes = {}
        for blue_id in blue_agents:
            eff = effects[blue_id]
            if eff.success:
                # E.g., eff.state_deltas might contain: {"hosts.10.0.0.5.port.80": "closed"}
                for delta_key, delta_val in eff.state_deltas.items():
                    if 'hosts/' in delta_key:
                        target_ip = delta_key.split('/')[1]
                        if target_ip not in blue_defended_nodes:
                            blue_defended_nodes[target_ip] = []
                        blue_defended_nodes[target_ip].append(delta_val)

        # 2. Evaluate Red attacks against the compiled simultaneous defenses
        for red_id in red_agents:
            red_eff = effects[red_id]
            if not red_eff.success:
                continue  # Already failed natively, ignore

            collision_detected = False
            for delta_key in list(red_eff.state_deltas.keys()):
                if 'hosts/' in delta_key:
                    target_ip = delta_key.split('/')[1]

                    # If Red is targeting a node that Blue is simultaneously modifying
                    if target_ip in blue_defended_nodes:
                        # For now, we apply a hard Zero-Trust temporal priority: Blue Defense always wins ties
                        collision_detected = True
                        break

            if collision_detected:
                # Nullify Red's attack effect entirely and alert the network telemetry
                effects[red_id].success = False
                effects[red_id].state_deltas = {}
                effects[red_id].observation_data['alert'] = (
                    'TEMPORAL_COLLISION_DEFENSE_SUPREMACY'
                )

        return effects

    def _apply_state_deltas(self, effects: Dict[str, ActionEffect]):
        """
        Applies validated deltas to the GlobalNetworkState.
        Only called AFTER temporal collisions have been mathematically resolved.
        """
        for agent_id, effect in effects.items():
            if effect.success:
                for delta_key, delta_val in effect.state_deltas.items():
                    self.global_state.apply_delta(delta_key, delta_val)

    def _calculate_reward(self, agent_id: str, state) -> float:
        """
        Reward Equations:
        R_red = Sum(Phi * Compromised) - (w2 * Noise) - Cost
        R_blue = (w3 * Uptime) + (w4 * Mitigation) - (w5 * exp(FalsePositives))
        """
        if 'red' in agent_id.lower():
            reward = 0.0
            # +10 per compromised node
            compromised_count = sum(
                1 for h in state.all_hosts.values() if h.privilege in ['User', 'Root']
            )
            reward += compromised_count * 10.0
            # Flat stealth penalty to discourage infinite blind scanning
            reward -= 0.1
            return reward

        elif 'blue' in agent_id.lower():
            reward = 0.0
            for h in state.all_hosts.values():
                is_infected = h.privilege in ['User', 'Root']
                is_isolated = h.status == 'isolated'

                if not is_infected and not is_isolated:
                    reward += (
                        1.0  # Uptime of clean host (Confidentiality & Availability)
                    )
                elif not is_infected and is_isolated:
                    reward -= 5.0  # False Positive Isolation Penalty (Catastrophic Business Interruption)
                elif is_infected and is_isolated:
                    reward += 10.0  # True Positive Mitigation Reward (Zero-Trust execution successful)
                elif is_infected and not is_isolated:
                    reward -= 10.0  # Security breach penalty (APT lateral progression)

            return reward

        return 0.0
