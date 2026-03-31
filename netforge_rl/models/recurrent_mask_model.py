import torch
from torch import nn

from ray.rllib.models.torch.recurrent_net import RecurrentNetwork as TorchRNN
from ray.rllib.utils.annotations import override
from ray.rllib.utils.typing import ModelConfigDict, TensorType
from typing import List, Tuple


class MaskedLSTMModel(TorchRNN, nn.Module):
    """
    A custom PyTorch model integrating native RLlib LSTM cells with strict Action Masking.

    We subclass TorchRNN to allow Ray to handle complex `seq_lens` padding and tensor
    BPTT dimension tracking natively. We extract the mask out of the flattened array manually.
    """

    def __init__(
        self,
        obs_space,
        action_space,
        num_outputs: int,
        model_config: ModelConfigDict,
        name: str,
    ):
        nn.Module.__init__(self)
        super().__init__(obs_space, action_space, num_outputs, model_config, name)

        self.cell_size = model_config.get('custom_model_config', {}).get(
            'lstm_cell_size', 128
        )

        # 1. Feature Extractor (Dense Layers)
        # Input size is 256 sliced from the flattened 318 Dict space
        self.fc1 = nn.Linear(256, 128)
        self.fc2 = nn.Linear(128, 128)

        # 2. LSTM Memory Unit
        self.lstm = nn.LSTM(
            input_size=128,
            hidden_size=self.cell_size,
            batch_first=True,
        )

        # 3. Action Type & Logit Masking Arrays
        self.action_branch = nn.Linear(self.cell_size, num_outputs)
        self.value_branch = nn.Linear(self.cell_size, 1)

        self._cur_value = None

    @override(TorchRNN)
    def forward_rnn(
        self, inputs: TensorType, state: List[TensorType], seq_lens: TensorType
    ) -> Tuple[TensorType, List[TensorType]]:
        # Ray flatly concatenates spaces in alphanumeric order.
        # action_mask Box(62)
        # obs Box(256)
        # Therefore: action_mask is [:62], obs is [62:]
        action_mask = inputs[:, :, :62]
        obs = inputs[:, :, 62:]

        # 1. Core Embeddings over Observation Sequence
        x = nn.functional.relu(self.fc1(obs))
        x = nn.functional.relu(self.fc2(x))

        # 2. Evaluate Temporal Memory
        h_in, c_in = state[0].unsqueeze(0), state[1].unsqueeze(0)
        x, (h_out, c_out) = self.lstm(x, (h_in, c_in))

        # 3. Finalize Output Logit Distribution Branches
        logits = self.action_branch(x)
        self._cur_value = torch.reshape(self.value_branch(x), [-1])

        # 4. Apply Action Mask dynamically over the sequence batch
        masked_logits = torch.where(
            action_mask == 0.0,
            torch.tensor(-1e10, device=logits.device, dtype=logits.dtype),
            logits,
        )

        return masked_logits, [h_out.squeeze(0), c_out.squeeze(0)]

    @override(TorchRNN)
    def value_function(self) -> TensorType:
        assert self._cur_value is not None, (
            'Evaluate forward_rnn() before value_function() call.'
        )
        return self._cur_value

    @override(TorchRNN)
    def get_initial_state(self) -> List[TensorType]:
        return [
            torch.zeros(self.cell_size, dtype=torch.float32),
            torch.zeros(self.cell_size, dtype=torch.float32),
        ]
