# Quick Start

Get NetForge RL running in under 5 minutes.

## Installation

```bash
# Clone the repository
git clone https://github.com/xaiqo/NetForge_RL.git
cd NetForge_RL/Cyborg

# Install core package
pip install -e .

# Install dev extras (pytest, ruff, tensorboard)
pip install -e ".[dev]"
```

## Minimal Environment Loop

```python
from netforge_rl.environment.parallel_env import NetForgeRLEnv

# Create environment (sim mode = fast mock hypervisor, no Docker required)
env = NetForgeRLEnv({
    'scenario_type': 'ransomware',  # or 'apt_espionage'
    'sim2real_mode': 'sim',         # 'real' for Docker evaluation
    'nlp_backend': 'tfidf',         # 'transformer' for sentence-transformers
})

obs, info = env.reset(seed=42)
print("Agents:", env.agents)
print("Obs keys:", list(obs['blue_commander'].keys()))
# → ['obs', 'action_mask', 'siem_embedding']

for step in range(100):
    actions = {agent: env.action_space(agent).sample() for agent in env.agents}
    obs, rewards, terms, truncs, infos = env.step(actions)

    if all(terms.values()) or all(truncs.values()):
        obs, info = env.reset()
```

## Observation Space

Each agent receives a `Dict` observation:

| Key | Shape | Description |
|-----|-------|-------------|
| `obs` | `(256,)` float32 | Structured network state features |
| `action_mask` | `(62,)` int8 | Binary mask of valid actions |
| `siem_embedding` | `(128,)` float32 | Encoded SIEM log vector (Blue only, zeros for Red) |

## Action Space

`MultiDiscrete([12, 50])` — select `[ActionType, TargetIPIndex]`.

Use the `action_mask` to avoid invalid action selections in your policy.

## Enable Real Docker Execution

```python
# Requires: pip install docker
# Requires: docker/netforge_isolated_network.sh to be run once

env = NetForgeRLEnv({
    'sim2real_mode': 'real',  # Spawns Vulhub containers
})
```

## Verify Installation

```bash
python -m pytest tests/ -m fast -v
```
