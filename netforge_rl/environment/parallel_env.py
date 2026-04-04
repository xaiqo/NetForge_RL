from typing import Dict, Tuple
import numpy as np
import gymnasium as gym

from netforge_rl.core.action import BaseAction, ActionEffect
from netforge_rl.core.observation import BaseObservation
from netforge_rl.core.registry import action_registry
import netforge_rl.actions  # 🧬 Fusion: Trigger action registration decorators
from netforge_rl.core.physics import ConflictResolutionEngine
from netforge_rl.environment.base_env import BaseNetForgeRLEnv
from netforge_rl.topologies.network_generator import NetworkGenerator
from netforge_rl.agents.green_agent import GreenAgent
from netforge_rl.sim2real.bridge import Sim2RealBridge
from netforge_rl.siem.siem_logger import SIEMLogger
from netforge_rl.nlp.log_encoder import LogEncoder, EMBEDDING_DIM


# Normalization constant for Neural ODE integration
MAX_ACTION_DURATION = 50.0


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
            'red_operator',
            'blue_dmz',
            'blue_internal',
            'blue_restricted',
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
                        low=0, high=1, shape=(32 + 100,), dtype=np.int8
                    ),
                    'siem_embedding': gym.spaces.Box(
                        low=-1.0, high=1.0, shape=(EMBEDDING_DIM,), dtype=np.float32
                    ),
                    'delta_t': gym.spaces.Box(
                        low=0.0, high=1.0, shape=(1,), dtype=np.float32
                    ),
                }
            )
            for agent in self.possible_agents
        }
        self.action_spaces = {
            agent: gym.spaces.MultiDiscrete(
                [32, 100]
            )  # [Action Type (max 32), Target IP Index (max 100 padded)]
            for agent in self.possible_agents
        }
        self.max_ticks = scenario_config.get('max_ticks', 1000)
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
        # SIEM log buffer and research metrics
        self.global_state.siem_log_buffer = []
        self.episode_metrics = {
            'infection_times': {}, # IP -> tick
            'detection_times': {}, # IP -> tick (first SIEM alert)
            'isolation_times': {}, # IP -> tick
            'exfiltrated_data': 0.0,
            'sla_uptime_sum': 0.0,
            'steps_count': 0
        }
        
        observations = {}
        for agent_id in self.agents:
            obs = BaseObservation(agent_id)
            obs.update_from_state(self.global_state, [])
            observations[agent_id] = {
                'obs': obs.to_numpy(max_size=256),
                'action_mask': self.action_mask(agent_id),
                'siem_embedding': np.zeros(EMBEDDING_DIM, dtype=np.float32),
                'delta_t': np.zeros(1, dtype=np.float32),
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
        # Action space: [max 32 types, 100 IPs]. Therefore Mask shape = (132,)
        mask = np.zeros(132, dtype=np.int8)

        if 'red' in agent.lower():
            valid_action_types = 17
        else:
            valid_action_types = 15
        mask[:valid_action_types] = 1

        mask[32 : 32 + 100] = 1

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
        5. OBSERVATION: Agents receive POMDP updates with normalized Delta T info.
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
                effect.action = action  # 🧬 Link for reward attribution

                self.global_state.agent_locked_until[agent] = completion_tick
                self.event_queue.append(
                    {
                        'completion_tick': completion_tick,
                        'agent': agent,
                        'action': action,
                        'effect': effect,
                        'target_ip': getattr(action, 'target_ip', None),
                        'start_tick': self.current_tick,
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

        # 3. ADVANCE TIME (EVENT-DRIVEN JUMP)
        prev_tick = self.current_tick
        if self.event_queue:
            # Jump to the next event completion time
            next_event_tick = min(
                event['completion_tick'] for event in self.event_queue
            )
            self.current_tick = max(self.current_tick + 1, next_event_tick)
        else:
            # No events queued; advance by 1
            self.current_tick += 1

        delta_t = float(self.current_tick - prev_tick)
        delta_t_norm = delta_t / MAX_ACTION_DURATION

        self.global_state.current_tick = self.current_tick
        self.global_state.subnet_bandwidth.clear()

        # GENERATE BACKGROUND NOISE & DELAYED ALERTS
        noise_data = self.green_agent.generate_noise(
            self.current_tick, self.global_state
        )
        for anomaly in noise_data.get('alerts', []):
            # Arrival tick logic stays for delayed observation if needed,
            # but for now we push raw strings + subnets to buffer
            self.siem_logger._push_to_buffer(
                anomaly['data'], anomaly['subnet'], self.global_state
            )

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

                # Use templates for TP to ensure high-fidelity raw logs
                from netforge_rl.siem.event_templates import sysmon_1

                log_string = sysmon_1(res_agent, process='exploit_payload')

                self.siem_logger._push_to_buffer(
                    log_string,
                    host.subnet_cidr if host else 'unknown',
                    self.global_state,
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

        # Encode subnet-specific SIEM logs for decentralized Blue agents
        agent_siem_vecs = {}
        for agent in self.agents:
            if 'blue' in agent.lower():
                # Extract subnet tag (e.g., 'blue_dmz' -> 'dmz')
                subnet_tag = agent.split('_')[1] if '_' in agent else 'dmz'
                subset_logs = self.siem_logger.get_filtered_logs(
                    self.global_state, subnet_tag=subnet_tag, n=8
                )
                agent_siem_vecs[agent] = self.log_encoder.encode_buffer(
                    subset_logs, agg='mean'
                )

        for agent in self.agents:
            obs = BaseObservation(agent)
            obs.update_from_state(self.global_state, resolved_effects)

            obs_array = obs.to_numpy(max_size=256)

            # Blue agents receive subnet-specific SIEM embeddings; Red gets zeros.
            if 'blue' in agent.lower():
                agent_siem_vec = agent_siem_vecs.get(
                    agent, np.zeros(EMBEDDING_DIM, dtype=np.float32)
                )
            else:
                agent_siem_vec = np.zeros(EMBEDDING_DIM, dtype=np.float32)

            observations[agent] = {
                'obs': obs_array,
                'action_mask': self.action_mask(agent),
                'siem_embedding': agent_siem_vec,
                'delta_t': np.array([delta_t_norm], dtype=np.float32),
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

        # Add temporal metadata for Neural ODE cells
        for agent in self.agents:
            if agent in infos:
                infos[agent]['delta_t'] = delta_t
                infos[agent]['delta_t_norm'] = delta_t_norm

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
            
            if agent_effect:
                target_ip = getattr(agent_effect.action, 'target_ip', None)
                if target_ip and target_ip in self.global_state.all_hosts:
                    ordered_hosts = sorted(list(self.global_state.all_hosts.keys()))
                    info['target_ip_index'] = ordered_hosts.index(target_ip)
                else:
                    info['target_ip_index'] = None
            else:
                info['target_ip_index'] = None

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

            sla_final = (self.episode_metrics['sla_uptime_sum'] / self.episode_metrics['steps_count'] 
                         if self.episode_metrics['steps_count'] > 0 else 1.0)
            info['SLA_Uptime_Percentage'] = float(sla_final)
            
            # Calculate MTTC (Mean Time To Containment)
            mttc_vals = []
            for ip, t_iso in self.episode_metrics['isolation_times'].items():
                if ip in self.episode_metrics['infection_times']:
                    mttc_vals.append(t_iso - self.episode_metrics['infection_times'][ip])
            info['MTTC'] = float(sum(mttc_vals) / len(mttc_vals)) if mttc_vals else 0.0
            
            # Cumulative Impact
            info['Total_Exfiltrated_Data'] = float(self.episode_metrics['exfiltrated_data'])

            infos[agent] = info

        return infos

    def global_state_vector(self) -> np.ndarray:
        """Returns a flattened 512-dim vector representing the true global network physics.
        Used primarily for Centralized Critics (MAPPO, QMIX) during training.
        """
        vec = []
        ordered_hosts = sorted(list(self.global_state.all_hosts.keys()))
        
        for i in range(50):
            if i < len(ordered_hosts):
                host = self.global_state.all_hosts[ordered_hosts[i]]
                priv = {"None": 0.0, "User": 0.5, "Root": 1.0}.get(host.privilege, 0.0)
                status = 1.0 if host.status == "online" else 0.0
                decoy = 1.0 if host.decoy != "inactive" else 0.0
                vec.extend([priv, status, decoy])
            else:
                vec.extend([0.0, 0.0, 0.0])
        
        vec.append(self.global_state.business_downtime_score / 100.0)
        vec.append(float(self.current_tick) / float(self.max_ticks))
        
        for agent in self.possible_agents:
            vec.append(float(self.global_state.agent_energy.get(agent, 0)) / 100.0)

        result = np.zeros(512, dtype=np.float32)
        v_arr = np.array(vec, dtype=np.float32)
        result[:len(v_arr)] = v_arr
        return result
