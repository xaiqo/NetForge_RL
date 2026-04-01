import pytest
from netforge_rl.siem.siem_logger import SIEM_BUFFER_MAX
from netforge_rl.core.action import ActionEffect


@pytest.mark.fast
def test_siem_log_action(siem_logger, global_state):
    """Verify that actions generate logs in the global buffer."""
    # Find a DMZ host dynamically
    target_ip = None
    for ip, host in global_state.all_hosts.items():
        if host.subnet_cidr == '192.168.1.0/24':
            target_ip = ip
            break

    if not target_ip:
        pytest.skip('No DMZ host found in global_state')

    red_agent = 'red_operator'
    global_state.update_knowledge(red_agent, target_ip)
    host = global_state.all_hosts[target_ip]
    host.privilege = 'Root'

    effect = ActionEffect(
        success=True, state_deltas={}, observation_data={'exploit': target_ip}
    )

    initial_buffer_size = len(global_state.siem_log_buffer)
    # log_action uses the logger's RNG, which is seeded in conftest
    siem_logger.log_action(
        'ExploitEternalBlue', effect, global_state, red_agent, target_ip
    )

    # P_LOG_ON_SUCCESS is 0.9. With seed 0, it should trigger.
    assert len(global_state.siem_log_buffer) > initial_buffer_size
    latest_log = global_state.siem_log_buffer[-1]
    assert target_ip in latest_log


@pytest.mark.fast
def test_siem_buffer_rolling(siem_logger, global_state):
    """Verify the SIEM buffer rolls over at SIEM_BUFFER_MAX."""
    # Fill buffer
    for i in range(SIEM_BUFFER_MAX + 10):
        siem_logger._push_to_buffer(f'Log_{i}', global_state)

    assert len(global_state.siem_log_buffer) == SIEM_BUFFER_MAX
    assert global_state.siem_log_buffer[-1] == f'Log_{SIEM_BUFFER_MAX + 9}'


@pytest.mark.fast
def test_log_background_noise(siem_logger, global_state):
    """Verify that background noise can be logged."""
    # Enforce some online hosts
    for h in global_state.all_hosts.values():
        if '169.254' not in h.ip:
            h.status = 'online'

    initial_size = len(global_state.siem_log_buffer)

    # Try multiple times to overcome RNG P_BACKGROUND_NOISE (0.15)
    for _ in range(50):
        siem_logger.log_background_noise(global_state)
        if len(global_state.siem_log_buffer) > initial_size:
            break

    assert len(global_state.siem_log_buffer) > initial_size
    latest_log = global_state.siem_log_buffer[-1]
    assert '[BACKGROUND]' in latest_log
