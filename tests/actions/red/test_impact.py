import pytest
from netforge_rl.actions.red.impact import Impact, KillProcess, ExfiltrateData
from netforge_rl.core.state import GlobalNetworkState, Host


@pytest.fixture
def red_agent():
    return 'red_operator'


@pytest.mark.fast
def test_impact_execution(red_agent):
    """Verify Impact action correctly compromises host integrity."""
    state = GlobalNetworkState()
    target_ip = '192.168.1.5'
    action = Impact(agent_id=red_agent, target_ip=target_ip)

    # Ensure host exists
    state.register_host(
        Host(ip=target_ip, hostname='Target', subnet_cidr='192.168.1.0/24')
    )

    result = action.execute(state)
    assert result.success is True
    assert result.state_deltas[f'hosts/{target_ip}/system_integrity'] == 'compromised'


@pytest.mark.fast
def test_kill_process_execution(red_agent):
    """Verify KillProcess disables EDR active bit."""
    state = GlobalNetworkState()
    target_ip = '192.168.1.10'
    action = KillProcess(agent_id=red_agent, target_ip=target_ip)

    state.register_host(
        Host(ip=target_ip, hostname='TargetEDR', subnet_cidr='192.168.1.0/24')
    )

    result = action.execute(state)
    assert result.success is True
    assert result.state_deltas[f'hosts/{target_ip}/edr_active'] is False


@pytest.mark.fast
def test_exfiltrate_data_validation(red_agent):
    """Verify ExfiltrateData requires privilege and reachability."""
    state = GlobalNetworkState()
    target_ip = '192.168.1.20'
    host = Host(ip=target_ip, hostname='Srv', subnet_cidr='192.168.1.0/24')
    state.register_host(host)

    host.privilege = 'None'

    action = ExfiltrateData(agent_id=red_agent, target_ip=target_ip)
    # Fails because privilege is None
    assert action.validate(state) is False

    host.privilege = 'User'
    assert action.validate(state) is True


@pytest.mark.fast
def test_exfiltrate_data_execution(red_agent):
    """Verify ExfiltrateData generates a ConsumeBandwidthCommand."""
    state = GlobalNetworkState()
    target_ip = '192.168.1.30'
    host = Host(ip=target_ip, hostname='Srv', subnet_cidr='192.168.1.0/24')
    host.privilege = 'Root'
    state.register_host(host)

    action = ExfiltrateData(agent_id=red_agent, target_ip=target_ip)
    result = action.execute(state)

    assert result.success is True
    # Should contain a command object in list
    assert isinstance(result.state_deltas, list)
    from netforge_rl.core.commands import ConsumeBandwidthCommand

    assert any(isinstance(cmd, ConsumeBandwidthCommand) for cmd in result.state_deltas)
