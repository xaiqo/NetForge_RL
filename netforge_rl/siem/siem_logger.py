"""
SIEMLogger — generates stochastic human-readable Windows/Sysmon event logs
from action effects every tick.

The log buffer lives on GlobalNetworkState.siem_log_buffer (already defined).
Blue agents read from this buffer at observation time; it is the primary
input to the NLP encoder in Pillar 2.
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

from netforge_rl.siem.event_templates import ACTION_EVENT_MAP

if TYPE_CHECKING:
    from netforge_rl.core.action import ActionEffect
    from netforge_rl.core.state import GlobalNetworkState


# Max log lines buffered on GlobalNetworkState per episode (rolling window)
SIEM_BUFFER_MAX = 64

# Probability that a SUCCESSFUL action generates a high-fidelity log
P_LOG_ON_SUCCESS = 0.90
# Probability that a FAILED action generates a log (noisy / partial telemetry)
P_LOG_ON_FAILURE = 0.50
# Probability of generating a DECOY/benign log on any tick (background noise)
P_BACKGROUND_NOISE = 0.15


class SIEMLogger:
    """
    Stochastic SIEM event generator.

    On each action resolution, log_action() samples the appropriate
    Windows Event ID / Sysmon template and pushes the string into
    GlobalNetworkState.siem_log_buffer for observation encoding.
    """

    def __init__(self, seed: int | None = None):
        self._rng = random.Random(seed)

    def log_action(
        self,
        action_name: str,
        effect: 'ActionEffect',
        global_state: 'GlobalNetworkState',
        agent_id: str,
        target_ip: str | None = None,
    ) -> str | None:
        """
        Potentially generate a SIEM log line for this action's outcome.

        Returns the generated log string (or None if no log was produced).
        """
        p_threshold = P_LOG_ON_SUCCESS if effect.success else P_LOG_ON_FAILURE
        if self._rng.random() > p_threshold:
            return None  # This action was not detected / logged

        # Pick a source IP — prefer the agent's known foothold in DMZ
        src_ip = self._infer_src_ip(agent_id, global_state)
        tgt_ip = target_ip or src_ip

        log_line = self._generate_event(action_name, src_ip, tgt_ip)
        if log_line:
            self._push_to_buffer(log_line, global_state)
        return log_line

    def log_background_noise(self, global_state: 'GlobalNetworkState') -> None:
        """
        Inject benign background network activity every tick.

        Simulates the constant low-level noise present in real enterprise
        networks — Kerberos renewals, DNS queries, NTLM auth, etc.
        This forces the Blue agent to learn signal vs. noise discrimination.
        """
        if self._rng.random() > P_BACKGROUND_NOISE:
            return

        # Pick two random live hosts and generate a benign connection event
        live_hosts = [
            h
            for h in global_state.all_hosts.values()
            if h.status == 'online' and '169.254' not in h.ip
        ]
        if len(live_hosts) < 2:
            return

        src, dst = self._rng.sample(live_hosts, 2)
        # Sample a benign template from the default bucket
        templates = ACTION_EVENT_MAP.get('_default', [])
        if not templates:
            return
        weights, callables = zip(*templates)
        total = sum(weights)
        norm_weights = [w / total for w in weights]
        chosen = self._rng.choices(callables, weights=norm_weights, k=1)[0]
        log_line = chosen(src.ip, dst.ip)
        self._push_to_buffer(f'[BACKGROUND] {log_line}', global_state)

    def get_recent_logs(
        self,
        global_state: 'GlobalNetworkState',
        n: int = 8,
    ) -> list[str]:
        """Return the N most recent SIEM log lines from the buffer."""
        return list(global_state.siem_log_buffer[-n:])

    def _generate_event(self, action_name: str, src_ip: str, tgt_ip: str) -> str | None:
        templates = ACTION_EVENT_MAP.get(action_name, ACTION_EVENT_MAP['_default'])
        if not templates:
            return None
        weights, callables = zip(*templates)
        total = sum(weights)
        norm_weights = [w / total for w in weights]
        chosen = self._rng.choices(callables, weights=norm_weights, k=1)[0]
        try:
            return chosen(src_ip, tgt_ip)
        except Exception:
            return None

    def _infer_src_ip(self, agent_id: str, global_state: 'GlobalNetworkState') -> str:
        """Best-guess the agent's active source IP from known compromised hosts."""
        known = global_state.agent_knowledge.get(agent_id, set())
        for ip in known:
            host = global_state.all_hosts.get(ip)
            if host and host.privilege in ('User', 'Root'):
                return ip
        # Fallback — first known IP
        if known:
            return next(iter(known))
        return '10.0.0.1'

    def _push_to_buffer(
        self, log_line: str, global_state: 'GlobalNetworkState'
    ) -> None:
        global_state.siem_log_buffer.append(log_line)
        # Rolling window — evict oldest entries beyond max
        if len(global_state.siem_log_buffer) > SIEM_BUFFER_MAX:
            global_state.siem_log_buffer.pop(0)
