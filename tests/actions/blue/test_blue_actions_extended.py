import pytest
from netforge_rl.actions.blue.mitigation import (
    Remove,
    RestoreFromBackup,
    SecurityAwarenessTraining,
)


@pytest.fixture
def blue_agent():
    return 'blue_operator'


def apply_deltas(state, deltas):
    if isinstance(deltas, dict):
        for key, val in deltas.items():
            state.apply_delta(key, val)
    elif isinstance(deltas, list):
        for cmd in deltas:
            if hasattr(cmd, 'execute'):
                cmd.execute(state)


@pytest.mark.fast
def test_remove_action_execution(global_state, blue_agent):
    """Verify Remove clears unauthorized privileges."""
    target_ip = next(
        ip for ip, h in global_state.all_hosts.items() if '169.254' not in ip
    )
    host = global_state.all_hosts[target_ip]
    host.privilege = 'User'
    host.compromised_by = 'red_operator'

    action = Remove(agent_id=blue_agent, target_ip=target_ip)
    result = action.execute(global_state)
    assert result.success is True

    apply_deltas(global_state, result.state_deltas)
    assert host.privilege == 'None'
    assert host.compromised_by == 'None'


@pytest.mark.fast
def test_restore_from_backup_execution(global_state, blue_agent):
    """Verify RestoreFromBackup performs full host scrub."""
    target_ip = next(
        ip for ip, h in global_state.all_hosts.items() if '169.254' not in ip
    )
    host = global_state.all_hosts[target_ip]
    host.privilege = 'Root'
    host.status = 'kernel_panic'
    host.system_integrity = 'corrupt'

    action = RestoreFromBackup(agent_id=blue_agent, target_ip=target_ip)
    result = action.execute(global_state)
    assert result.success is True

    apply_deltas(global_state, result.state_deltas)
    assert host.privilege == 'None'
    assert host.status == 'online'
    assert host.system_integrity == 'clean'


@pytest.mark.fast
def test_security_awareness_training(global_state, blue_agent):
    """Verify Training reduces vulnerability across a subnet."""
    subnet_cidr = '192.168.1.0/24'
    # Ensure hosts in subnet have a vulnerability score
    for h in global_state.subnets[subnet_cidr].hosts.values():
        h.human_vulnerability_score = 0.8

    action = SecurityAwarenessTraining(agent_id=blue_agent, target_subnet=subnet_cidr)
    result = action.execute(global_state)
    assert result.success is True

    apply_deltas(global_state, result.state_deltas)

    # Check all hosts in the target subnet
    for h in global_state.subnets[subnet_cidr].hosts.values():
        assert h.human_vulnerability_score == 0.16  # 0.8 * 0.2
