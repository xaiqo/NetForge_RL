import pytest
from netforge_rl.actions.blue.identity import RotateKerberos


@pytest.fixture
def blue_agent():
    return 'blue_commander'


@pytest.mark.fast
def test_rotate_kerberos_execution(global_state, blue_agent):
    """Verify RotateKerberos flushes Red inventories and changes tokens."""
    red_agent = 'red_operator'
    old_token = 'Enterprise_Admin_Token'

    # 1. Seed red agent with existing stolen token
    global_state.agent_inventory[red_agent] = {old_token}

    # 2. Seed host with system token
    target_host = None
    for h in global_state.all_hosts.values():
        if h.subnet_cidr == '10.0.1.0/24':
            target_host = h
            break

    target_host.system_tokens = [old_token]
    target_host.cached_credentials = [old_token]

    # 3. Rotate Kerberos
    action = RotateKerberos(agent_id=blue_agent, target_ip='10.0.1.0/24')
    effect = action.execute(global_state)

    # 4. ActionEffect contains the command
    assert effect.success is True
    command = effect.state_deltas['identity_flush']
    command.execute(global_state)

    # 5. Verify Red inventory is flushed
    assert old_token not in global_state.agent_inventory[red_agent]
    assert len(global_state.agent_inventory[red_agent]) == 0

    # 6. Verify host tokens are updated
    assert old_token not in target_host.system_tokens
    assert len(target_host.system_tokens) == 1
    new_token = target_host.system_tokens[0]
    assert new_token.startswith('Enterprise_Admin_Token_')

    # 7. Verify credentials in memory are also rotated
    assert old_token not in target_host.cached_credentials
    assert new_token in target_host.cached_credentials


@pytest.mark.fast
def test_rotate_kerberos_costs(global_state, blue_agent):
    """Verify that identity rotation is expensive."""
    global_state.agent_funds[blue_agent] = 10000
    initial_downtime = global_state.business_downtime_score

    action = RotateKerberos(agent_id=blue_agent, target_ip='10.0.1.0/24')
    effect = action.execute(global_state)
    command = effect.state_deltas['identity_flush']
    command.execute(global_state)

    assert global_state.agent_funds[blue_agent] == 5000
    assert global_state.business_downtime_score == initial_downtime + 1500
