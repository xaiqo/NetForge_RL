import pytest
import numpy as np
from netforge_rl.nlp.log_encoder import LogEncoder, EMBEDDING_DIM


@pytest.fixture
def encoder():
    return LogEncoder(backend='tfidf')


@pytest.mark.fast
def test_encoder_single_line(encoder):
    """Verify that a single log line encodes to the correct shape."""
    log = '4624 - Success Logon by SYSTEM from 192.168.1.5'
    vec = encoder.encode(log)

    assert isinstance(vec, np.ndarray)
    assert vec.shape == (EMBEDDING_DIM,)
    assert vec.dtype == np.float32
    # Check L2 normalization
    assert np.isclose(np.linalg.norm(vec), 1.0, atol=1e-5)


@pytest.mark.fast
def test_encoder_empty_input(encoder):
    """Verify that empty input returns a zero vector."""
    vec = encoder.encode('')
    assert np.allclose(vec, 0.0)

    vec_none = encoder.encode(None)
    assert np.allclose(vec_none, 0.0)


@pytest.mark.fast
def test_encoder_buffer_aggregation(encoder):
    """Verify aggregation of multiple log lines."""
    logs = [
        '4624 - Success Logon',
        'Sysmon 3 - Network Connection',
        '4688 - Process Created',
    ]

    # Mean aggregation
    vec_mean = encoder.encode_buffer(logs, agg='mean')
    assert vec_mean.shape == (EMBEDDING_DIM,)

    # Max aggregation
    vec_max = encoder.encode_buffer(logs, agg='max')
    assert vec_max.shape == (EMBEDDING_DIM,)

    # They should be different
    assert not np.allclose(vec_mean, vec_max)


@pytest.mark.fast
def test_encoder_caching(encoder):
    """Verify that caching produces identical results for identical strings."""
    log = 'Repeated Log Line for Cache Test'
    vec1 = encoder.encode(log)
    vec2 = encoder.encode(log)

    # Should use the same object or identical values
    assert np.array_equal(vec1, vec2)
