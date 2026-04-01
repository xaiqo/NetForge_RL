import pytest
import numpy as np
from netforge_rl.environment.parallel_env import NetForgeRLEnv


@pytest.fixture
def env_sim_local(env_config):
    env = NetForgeRLEnv(env_config)
    env.reset(seed=42)
    return env


@pytest.mark.fast
def test_env_step_interaction(env_sim_local):
    """Verify that stepping returns rewards and observations for all agents."""
    env_sim_local.reset(seed=42)
    actions = {
        agent: env_sim_local.action_space(agent).sample()
        for agent in env_sim_local.agents
    }
    obs, rewards, terms, truncs, infos = env_sim_local.step(actions)
    assert len(obs) > 0
    assert len(rewards) > 0
    for r in rewards.values():
        assert isinstance(r, (int, float, np.float32, np.float64))


@pytest.mark.fast
def test_env_episode_truncation(env_sim_local):
    """Verify that episode truncates after max_ticks."""
    env_sim_local.max_ticks = 2
    env_sim_local.reset(seed=42)
    actions = {a: env_sim_local.action_space(a).sample() for a in env_sim_local.agents}
    obs, rewards, terms, truncs, _ = env_sim_local.step(actions)
    assert all(not t for t in truncs.values())
    actions = {a: env_sim_local.action_space(a).sample() for a in env_sim_local.agents}
    obs, rewards, terms, truncs, _ = env_sim_local.step(actions)
    assert all(t for t in truncs.values())


@pytest.mark.fast
def test_blue_siem_embedding_update(env_sim_local):
    """Verify that Blue agents receive non-zero embedding as logs arrive."""
    env_sim_local.reset(seed=42)

    # Inject a realistic log to ensure non-zero embedding
    fake_log = "<Event xmlns='...'><System><EventID>4624</EventID></System></Event>"
    env_sim_local.siem_logger._push_to_buffer(fake_log, env_sim_local.global_state)

    # Step to refresh observations
    actions = {a: env_sim_local.action_space(a).sample() for a in env_sim_local.agents}
    obs, _, _, _, _ = env_sim_local.step(actions)

    # Check Blue agents
    blue_checked = False
    for agent in ['blue_commander', 'blue_operator']:
        if agent in obs:
            blue_checked = True
            emb = obs[agent]['siem_embedding']
            # If LogEncoder is working, a non-empty string should result in non-zero vector
            assert not np.allclose(emb, 0.0), f'Embedding for {agent} is zero'

    assert blue_checked, 'No blue agents found in observations'

    # Red agent should still have zeros (Fog of War)
    for agent in ['red_commander', 'red_operator']:
        if agent in obs:
            assert np.allclose(obs[agent]['siem_embedding'], 0.0), (
                f'Embedding for {agent} is non-zero'
            )
