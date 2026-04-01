import pytest
from netforge_rl.actions.blue.mitigation import IsolateHost, RestoreHost, ConfigureACL


@pytest.fixture
def blue_agent():
    return 'blue_operator'


def apply_deltas(state, deltas):
    """Helper to apply deltas which can be a dict or a list."""
    if isinstance(deltas, dict):
        for key, val in deltas.items():
            state.apply_delta(key, val)
    elif isinstance(deltas, list):
        for cmd in deltas:
            if hasattr(cmd, 'execute'):
                cmd.execute(state)
            else:
                # Fallback for simple dict-like entries in list if any
                pass


@pytest.mark.fast
def test_isolate_host_execution(global_state, blue_agent):
    """Verify IsolateHost disconnects the target."""
    target_ip = next(
        ip for ip, h in global_state.all_hosts.items() if '169.254' not in ip
    )
    host = global_state.all_hosts[target_ip]
    host.status = 'online'

    action = IsolateHost(agent_id=blue_agent, target_ip=target_ip)
    result = action.execute(global_state)
    assert result.success is True

    apply_deltas(global_state, result.state_deltas)
    assert host.status == 'isolated'


@pytest.mark.fast
def test_restore_host_execution(global_state, blue_agent):
    """Verify RestoreHost re-enables the target."""
    target_ip = next(
        ip for ip, h in global_state.all_hosts.items() if '169.254' not in ip
    )
    host = global_state.all_hosts[target_ip]
    host.status = 'isolated'
    host.privilege = 'Root'

    action = RestoreHost(agent_id=blue_agent, target_ip=target_ip)
    result = action.execute(global_state)
    assert result.success is True

    apply_deltas(global_state, result.state_deltas)
    assert host.status == 'online'
    assert host.privilege == 'None'


@pytest.mark.fast
def test_configure_acl_execution(global_state, blue_agent):
    """Verify ConfigureACL adds a firewall rule."""
    port = 445
    # Use a real subnet from global_state
    subnet = list(global_state.subnets.keys())[0]

    action = ConfigureACL(agent_id=blue_agent, target_subnet=subnet, port=port)
    result = action.execute(global_state)
    assert result.success is True

    apply_deltas(global_state, result.state_deltas)
    assert global_state.firewalls['global'].is_blocked(subnet, port) is True
