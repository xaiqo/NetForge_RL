# Training with RLlib + LSTM

## Setup

```bash
pip install "ray[rllib]" torch
```

## LSTM Policy Configuration

```python
from ray.rllib.algorithms.ppo import PPOConfig

config = (
    PPOConfig()
    .environment("NetForgeRLEnv")
    .framework("torch")
    .training(
        model={
            "use_lstm": True,
            "lstm_cell_size": 256,
            "lstm_use_prev_action": True,
        }
    )
    .multi_agent(
        policies={
            "red_policy": ...,
            "blue_policy": ...,
        }
    )
)
```

## Using the SIEM Embedding

The `siem_embedding` key in the observation Dict is automatically handled by RLlib's Dict observation preprocessor. To give it special treatment in a custom model, use `input_dict["obs"]["siem_embedding"]` in your forward pass.
