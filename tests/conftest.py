import pytest
from netforge_rl.environment.parallel_env import NetForgeRLEnv
from netforge_rl.sim2real.bridge import Sim2RealBridge
from netforge_rl.siem.siem_logger import SIEMLogger
from netforge_rl.nlp.log_encoder import LogEncoder


@pytest.fixture
def env_config():
    """Default environment configuration for testing."""
    return {
        'scenario_type': 'ransomware',
        'sim2real_mode': 'sim',
        'nlp_backend': 'tfidf',
        'max_ticks': 100,
        'log_latency': 2,
    }


@pytest.fixture
def env_sim(env_config):
    """A NetForgeRLEnv instance in sim mode, reset with seed 42."""
    env = NetForgeRLEnv(env_config)
    env.reset(seed=42)
    return env


@pytest.fixture
def global_state():
    """A GlobalNetworkState instance initialized with seed 0 via NetworkGenerator."""
    from netforge_rl.topologies.network_generator import NetworkGenerator

    gen = NetworkGenerator()
    state = gen.generate(seed=0)
    return state


@pytest.fixture
def mock_bridge():
    """A Sim2RealBridge in sim mode."""
    return Sim2RealBridge(mode='sim')


@pytest.fixture
def siem_logger():
    """A SIEMLogger instance."""
    return SIEMLogger(seed=0)


@pytest.fixture
def log_encoder():
    """A LogEncoder instance with tfidf backend."""
    return LogEncoder(backend='tfidf')


@pytest.fixture
def red_agent_id():
    return 'red_operator_0'


@pytest.fixture
def blue_agent_id():
    return 'blue_operator_0'
