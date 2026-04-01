import pytest
import numpy as np
from netforge_rl.environment.parallel_env import NetForgeRLEnv


@pytest.fixture
def env_sim_local(env_config):
    env = NetForgeRLEnv(env_config)
    env.reset(seed=42)
    return env


@pytest.mark.fast
def test_env_reset_shapes(env_sim_local):
    """Verify that reset returns correct observation shapes for all agents."""
    obs, infos = env_sim_local.reset(seed=42)

    for agent, data in obs.items():
        assert 'obs' in data
        assert 'action_mask' in data
        assert 'siem_embedding' in data

        # Check shapes
        assert data['obs'].shape == (256,)
        assert data['action_mask'].shape == (62,)
        assert data['siem_embedding'].shape == (128,)

        # Check types
        assert data['obs'].dtype == np.float32
        assert data['action_mask'].dtype == np.int8
        assert data['siem_embedding'].dtype == np.float32


@pytest.mark.fast
def test_env_reset_siem_zeros(env_sim_local):
    """Verify that siem_embedding is zeros after reset."""
    obs, _ = env_sim_local.reset(seed=42)
    for data in obs.values():
        assert np.allclose(data['siem_embedding'], 0.0)


@pytest.mark.fast
def test_env_action_space_consistency(env_sim_local):
    """Verify action space shapes."""
    for agent in env_sim_local.agents:
        space = env_sim_local.action_space(agent)
        # MultiDiscrete([12, 50])
        assert space.nvec[0] == 12
        assert space.nvec[1] == 50
