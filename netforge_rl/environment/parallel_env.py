from typing import Dict, Tuple
import numpy as np
import gymnasium as gym

from netforge_rl.core.action import BaseAction, ActionEffect
from netforge_rl.core.observation import BaseObservation
from netforge_rl.core.registry import action_registry
from netforge_rl.core.physics import ConflictResolutionEngine
from netforge_rl.environment.base_env import BaseNetForgeRLEnv
from netforge_rl.topologies.network_generator import NetworkGenerator
from netforge_rl.agents.green_agent import GreenAgent
from netforge_rl.sim2real.bridge import Sim2RealBridge
from netforge_rl.siem.siem_logger import SIEMLogger
from netforge_rl.nlp.log_encoder import LogEncoder, EMBEDDING_DIM


class NetForgeRLEnv(BaseNetForgeRLEnv):
    """MARL Environment for CybORG.

    Follows the PettingZoo Parallel API standard for simultaneous Multi-
    Agent execution and relies exclusively on Gymnasium spaces natively.
    """

    metadata = {'render_modes': ['ansi'], 'name': 'netforge_rl_v3'}

    def __init__(self, scenario_config: dict):
        # Default to procedural generation if no specific architecture config is provided
        topology_path = (
            scenario_config.get('topology_path') if scenario_config else None
        )
        self.network_generator = NetworkGenerator(config_path=topology_path)

        scenario_type = (
            scenario_config.get('scenario_type', 'ransomware')
            if scenario_config
            else 'ransomware'
        )
        self.log_latency = (
            scenario_config.get('log_latency', 2) if scenario_config else 2
        )
        self.green_agent = GreenAgent()
        self.possible_agents = [
            'red_commander',
            'red_operator',
            'blue_commander',
            'blue_operator',
        ]
        self.agents = self.possible_agents[:]

        if scenario_type.lower() == 'ransomware':
            from netforge_rl.scenarios.ransomware import RansomwareScenario

            self.scenario = RansomwareScenario(self.agents)
        else:
            from netforge_rl.scenarios.apt_espionage import AptEspionageScenario

            self.scenario = AptEspionageScenario(self.agents)

        self.global_state = self.network_generator.generate()
        self.resolution_engine = ConflictResolutionEngine()

        # Sim2Real Bridge — defaults to 'sim' (mock) for training speed.
        # Set sim2real_mode='real' in scenario_config for Docker evaluation.
        sim2real_mode = (
            scenario_config.get('sim2real_mode', 'sim') if scenario_config else 'sim'
        )
        self.sim2real_bridge = Sim2RealBridge(mode=sim2real_mode)
        self.global_state.sim2real_bridge = self.sim2real_bridge

        # NLP-SIEM Pipeline — stochastic event log generation + encoding.
        # SIEMLogger converts action effects → Windows Event XML strings.
        # LogEncoder converts those strings → 128-dim LSTM-compatible vectors.
        nlp_backend = (
            scenario_config.get('nlp_backend', 'tfidf') if scenario_config else 'tfidf'
        )
        self.siem_logger = SIEMLogger()
        self.log_encoder = LogEncoder(backend=nlp_backend)

        # Native Gymnasium Spaces for PettingZoo API + RLlib Mapping
        # Blue agents receive a 'siem_embedding' key with the encoded SIEM log vector.
        # Red agents also get the key (zeroed) to keep obs space shapes uniform across agents.
        self.observation_spaces = {
            agent: gym.spaces.Dict(
                {
                    'obs': gym.spaces.Box(
                        low=-1.0, high=1.0, shape=(256,), dtype=np.float32
                    ),
                    'action_mask': gym.spaces.Box(
                        low=0, high=1, shape=(62,), dtype=np.int8
                    ),
                    'siem_embedding': gym.spaces.Box(
                        low=-1.0, high=1.0, shape=(EMBEDDING_DIM,), dtype=np.float32
                    ),
                }
            )
            for agent in self.possible_agents
        }
        self.action_spaces = {
            agent: gym.spaces.MultiDiscrete(
                [12, 50]
            )  # [Action Type (max 12), Target IP Index (max 50 padded)]
            for agent in self.possible_agents
        }
        self.max_ticks = 1000
        self.current_tick = 0
        self.event_queue = []

    def reset(
        self, seed=None, options=None
    ) -> Tuple[Dict[str, np.ndarray], Dict[str, dict]]:
        """Resets the network state to initial configuration natively

        (Gymnasium style + PettingZoo).
        """
        # Teardown any running containers from the previous episode
        self.sim2real_bridge.teardown_all()
        self.global_state = self.network_generator.generate(seed=seed)
        # Re-attach bridge to freshly generated state
        self.global_state.sim2real_bridge = self.sim2real_bridge
        self.agents = self.possible_agents[:]
        self.global_state.agent_energy = {agent: 50 for agent in self.agents}
        self.global_state.agent_funds = {
            agent: 10000 if 'blue' in agent else 5000 for agent in self.agents
        }
        self.global_state.agent_compute = {agent: 1000 for agent in self.agents}
        self.global_state.business_downtime_score = 0.0
        # Clear SIEM log buffer on new episode
        self.global_state.siem_log_buffer = []
        observations = {}
        for agent_id in self.agents:
            obs = BaseObservation(agent_id)
            obs.update_from_state(self.global_state, [])
            observations[agent_id] = {
                'obs': obs.to_numpy(max_size=256),
                'action_mask': self.action_mask(agent_id),
                'siem_embedding': np.zeros(EMBEDDING_DIM, dtype=np.float32),
            }
        self.current_tick = 0
        self.event_queue = []

        return observations, {agent: {} for agent in self.agents}

    def observation_space(self, agent):
        return self.observation_spaces[agent]

    def action_space(self, agent):
        return self.action_spaces[agent]

    def action_mask(self, agent: str) -> np.ndarray:
        """Returns a binary mask denoting valid and distinct action integers for the agent,
        pruning out computationally redundant modulo duplicates.
        """
        # RLlib explicitly requires MultiDiscrete action masks to be concatenated flat boolean layers.
        # Action space: [12 types, 50 IPs]. Therefore Mask shape = (62,)
        mask = np.zeros(62, dtype=np.int8)

        # 1. Action Type Dimension (0-11)
        if 'red' in agent.lower():
            valid_action_types = 4 if 'commander' in agent.lower() else 9
        else:
            valid_action_types = 5 if 'commander' in agent.lower() else 7
        mask[:valid_action_types] = 1

        # 2. Target IP Dimension (12-61)
        target_ips = sorted(list(self.global_state.all_hosts.keys()))
        num_targets = min(len(target_ips), 50)
        mask[12 : 12 + num_targets] = 1

        return mask

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

        1. PROCESS NEW ACTIONS: Validate budgets and enqueue async events.
        2. INTERRUPTION LOGIC: Immediate cancel operations for specific defensive tasks.
        3. ADVANCE TIME: `current_tick` progresses by 1.
        4. RESOLVE MATURE EVENTS: Apply ActionEffects that reach `completion_tick`.
        5. OBSERVATION: Agents receive POMDP updates every tick.
        """
        intended_effects = {}

        # 1. PROCESS NEW ACTIONS
        blue_active_actions_count = sum(
            1 for event in self.event_queue if 'blue' in event['agent'].lower()
        )

        for agent, action_int in agent_actions.items():
            # Validate temporal locks
            if self.current_tick < self.global_state.agent_locked_until.get(agent, 0):
                continue

            if isinstance(action_int, BaseAction):
                action = action_int
            else:
                target_ips = sorted(list(self.global_state.all_hosts.keys()))
                action = action_registry.instantiate_action(
                    agent, action_int, target_ips
                )
                if action is None:
                    continue  # Invalid action/unmapped action bounds

            # SOC Budget Check (Max 2 active defensive actions)
            if 'blue' in agent.lower():
                if blue_active_actions_count >= 2:
                    continue  # SOC is busy, silently ignore
                blue_active_actions_count += 1

            # Validate temporal energy constraints
            if self.global_state.agent_energy.get(agent, 0) < action.cost:
                continue

            # Expend energy and validate state
            self.global_state.agent_energy[agent] -= action.cost

            if action.validate(self.global_state):
                eta = getattr(action, 'duration', 1)
                completion_tick = self.current_tick + eta

                # Generate intended effect (though state might shift by completion time)
                effect = action.execute(self.global_state)

                self.global_state.agent_locked_until[agent] = completion_tick
                self.event_queue.append(
                    {
                        'completion_tick': completion_tick,
                        'agent': agent,
                        'action': action,
                        'effect': effect,
                        'target_ip': getattr(action, 'target_ip', None),
                    }
                )

        # 2. INTERRUPTION LOGIC (e.g., IsolateHost Immediately Cancels Ongoing Attacks)
        for event in list(self.event_queue):
            if (
                type(event['action']).__name__ == 'IsolateHost'
                and event['completion_tick'] > self.current_tick
            ):
                # Isolate is queued or starting now; interrupt Red
                target_to_isolate = event['target_ip']
                for red_event in list(self.event_queue):
                    if (
                        'red' in red_event['agent'].lower()
                        and red_event['target_ip'] == target_to_isolate
                    ):
                        if red_event in self.event_queue:
                            self.event_queue.remove(red_event)
                        # Unlock Red agent since their attack was disrupted
                        self.global_state.agent_locked_until[red_event['agent']] = (
                            self.current_tick
                        )

        # 3. ADVANCE TIME
        self.current_tick += 1
        self.global_state.current_tick = self.current_tick
        self.global_state.subnet_bandwidth.clear()

        # GENERATE BACKGROUND NOISE & DELAYED ALERTS
        noise_data = self.green_agent.generate_noise(
            self.current_tick, self.global_state
        )
        for anomaly in noise_data.get('alerts', []):
            anomaly['arrival_tick'] = self.current_tick + self.log_latency
            self.global_state.siem_log_buffer.append(anomaly)

        # 4. RESOLVE MATURE EVENTS
        intended_effects = {}
        action_metadata = {}
        remaining_events = []
        for event in self.event_queue:
            if self.current_tick >= event['completion_tick']:
                agent = event['agent']
                intended_effects[agent] = event['effect']
                action_metadata[agent] = {
                    'name': type(event['action']).__name__,
                    'target_ip': event.get('target_ip'),
                }
            else:
                remaining_events.append(event)
        self.event_queue = remaining_events

        resolved_effects = self.resolution_engine.resolve(intended_effects)

        self._apply_state_deltas(resolved_effects)

        # NLP-SIEM: generate structured event logs from resolved action effects
        for res_agent, res_effect in resolved_effects.items():
            meta = action_metadata.get(res_agent, {})
            action_name = meta.get('name', 'UnknownAction')
            target_ip = meta.get('target_ip') or res_effect.observation_data.get(
                'exploit'
            )
            self.siem_logger.log_action(
                action_name=action_name,
                effect=res_effect,
                global_state=self.global_state,
                agent_id=res_agent,
                target_ip=res_effect.observation_data.get('exploit'),
            )

        # Generate True Positive telemetry from attacks that hit SIEM
        for res_agent, res_effect in resolved_effects.items():
            if 'red' in res_agent and res_effect.success:
                target_ip = res_effect.observation_data.get('exploit', 'unknown')

                # Active Deception intercept
                host = self.global_state.all_hosts.get(target_ip)
                is_honeytoken_trap = host and host.contains_honeytokens

                signature = (
                    'HONEYTOKEN_TRIGGERED'
                    if is_honeytoken_trap
                    else 'RED_ACTION_DETECTED'
                )
                severity = 10 if is_honeytoken_trap else 5
                log_delay = 0 if is_honeytoken_trap else self.log_latency

                self.global_state.siem_log_buffer.append(
                    {
                        'type': 'anomaly',
                        'source': res_agent,
                        'target': target_ip,
                        'signature': signature,
                        'severity': severity,
                        'false_positive': False,
                        'arrival_tick': self.current_tick + log_delay,
                    }
                )

        # Generate background SIEM noise every tick
        self.siem_logger.log_background_noise(self.global_state)

        observations = {}
        rewards = {}
        terminate = self.scenario.check_termination(self.global_state)

        # Trigger dynamic topology mutations mid-episode
        if self.current_tick % 40 == 0:
            self.global_state.reallocate_dhcp()

        is_truncated = self.current_tick >= self.max_ticks
        truncate = {agent: is_truncated for agent in self.agents}

        # Encode recent SIEM logs once per step (shared cost for all Blue agents)
        recent_logs = self.siem_logger.get_recent_logs(self.global_state, n=8)
        siem_vec = self.log_encoder.encode_buffer(recent_logs, agg='mean')

        for agent in self.agents:
            obs = BaseObservation(agent)
            obs.update_from_state(self.global_state, resolved_effects)

            obs_array = obs.to_numpy(max_size=256)
            if 'operator' in agent:
                commander_id = agent.replace('operator', 'commander')
                if commander_id in agent_actions:
                    cmd_action = agent_actions[commander_id]
                    cmd_val = (
                        (float(cmd_action[0]) / 12.0)
                        if getattr(cmd_action, '__iter__', False)
                        and not isinstance(cmd_action, BaseAction)
                        else 1.0
                    )
                    obs_array[0] = cmd_val

            # Blue agents receive the live SIEM embedding; Red gets zeros.
            # This gives Blue an information advantage that models real SOC telemetry.
            if 'blue' in agent:
                agent_siem_vec = siem_vec
            else:
                agent_siem_vec = np.zeros(EMBEDDING_DIM, dtype=np.float32)

            observations[agent] = {
                'obs': obs_array,
                'action_mask': self.action_mask(agent),
                'siem_embedding': agent_siem_vec,
            }
            agent_effect = resolved_effects.get(agent)
            rewards[agent] = self._calculate_reward(
                agent, self.global_state, agent_effect
            )

        self.agents = [
            agent
            for agent in self.agents
            if not terminate[agent] and not truncate[agent]
        ]

        # ── Build info dicts with security metrics for callbacks ──
        infos = self._extract_agent_infos(observations, resolved_effects)

        return observations, rewards, terminate, truncate, infos

    def render(self):
        """Standard PettingZoo GUI logging render hook."""
        pass

    def _decode_action(self, agent_id: str, action_int: int) -> BaseAction:
        target_ips = sorted(list(self.global_state.all_hosts.keys()))
        return action_registry.instantiate_action(agent_id, action_int, target_ips)

    def _apply_state_deltas(self, effects: Dict[str, ActionEffect]):
        """Applies validated deltas to the GlobalNetworkState.

        Only called AFTER temporal collisions have been mathematically resolved.
        """
        for agent_id, effect in effects.items():
            if effect.success:
                if isinstance(effect.state_deltas, dict):
                    for delta_key, delta_val in effect.state_deltas.items():
                        self.global_state.apply_delta(delta_key, delta_val)
                elif isinstance(effect.state_deltas, list):
                    for delta_cmd in effect.state_deltas:
                        self.global_state.apply_delta(delta_cmd)

    def _calculate_reward(
        self, agent_id: str, state, effect: ActionEffect = None
    ) -> float:
        """Delegates reward logic directly to the localized Scenario module."""
        return self.scenario.calculate_reward(agent_id, state, effect)

    def _extract_agent_infos(self, observations: dict, resolved_effects: dict) -> dict:
        """Extracts security metrics for TensorBoard and CSV logging callbacks.

        Args:
            observations: Dictionary of agent observations for this step.
            resolved_effects: Dictionary of resolved action effects.

        Returns:
            Dictionary mapping agent_id to an info dictionary with security metrics.
        """
        infos = {}
        for agent in list(observations.keys()):
            agent_effect = resolved_effects.get(agent)
            info: dict = {}

            # Count security-relevant events from this step
            false_positives = 0
            successful_exploits = 0
            hosts_isolated = 0
            services_restored = 0

            if (
                agent_effect
                and agent_effect.success
                and isinstance(agent_effect.state_deltas, dict)
            ):
                for delta_key, delta_val in agent_effect.state_deltas.items():
                    if 'status' in delta_key and delta_val == 'isolated':
                        hosts_isolated += 1
                        # Check if the isolated host was actually compromised
                        parts = delta_key.split('/')
                        if len(parts) >= 2:
                            ip = parts[1]
                            host = self.global_state.all_hosts.get(ip)
                            if host and host.compromised_by == 'None':
                                false_positives += 1  # Isolated a clean host
                    elif 'privilege' in delta_key and delta_val in ('User', 'Root'):
                        successful_exploits += 1
                    elif 'status' in delta_key and delta_val == 'online':
                        services_restored += 1

            info['false_positives'] = float(false_positives)
            info['successful_exploits'] = float(successful_exploits)
            info['hosts_isolated'] = float(hosts_isolated)
            info['services_restored'] = float(services_restored)

            # Extra context for analysis
            info['agent_energy'] = float(self.global_state.agent_energy.get(agent, 0))
            info['compromised_hosts'] = float(
                sum(
                    1
                    for h in self.global_state.all_hosts.values()
                    if h.compromised_by != 'None'
                )
            )
            info['isolated_hosts'] = float(
                sum(
                    1
                    for h in self.global_state.all_hosts.values()
                    if h.status == 'isolated'
                )
            )

            infos[agent] = info

        return infos
