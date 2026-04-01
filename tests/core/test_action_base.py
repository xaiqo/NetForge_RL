import pytest
from netforge_rl.core.action import BaseAction, ActionEffect
from netforge_rl.core.state import GlobalNetworkState


class SimpleRedAction(BaseAction):
    """A concrete implementation of BaseAction for testing."""

    def __init__(self, agent_id, target_ip):
        # BaseAction(agent_id, target_ip=None, source_ip=None, cost=1, ...)
        super().__init__(agent_id, target_ip=target_ip, duration=2)
        self.team = 'Red'

    def validate(self, global_state: GlobalNetworkState) -> bool:
        """Simple validation: host must exist."""
        return self.target_ip in global_state.all_hosts

    def execute(self, global_state: GlobalNetworkState) -> ActionEffect:
        """Simple execution: host is 'hit'."""
        # Ensure host exists, but we don't need the object
        _ = global_state.all_hosts[self.target_ip]
        # Return an ActionEffect as required by the abstract method
        return ActionEffect(
            success=True,
            state_deltas={'hosts/' + self.target_ip + '/status': 'pwned'},
            observation_data={'effect': 'pwned_host'},
        )


@pytest.mark.fast
def test_base_action_properties():
    """Verify common action properties."""
    action = SimpleRedAction(agent_id='red_0', target_ip='10.0.0.1')
    assert action.agent_id == 'red_0'
    assert action.target_ip == '10.0.0.1'
    assert action.duration == 2
    assert action.cost == 1  # default
    assert action.team == 'Red'


@pytest.mark.fast
def test_base_action_validation(global_state):
    """Verify validation logic with GlobalNetworkState."""
    # Find a valid IP in global_state
    target_ip = list(global_state.all_hosts.keys())[0]
    action = SimpleRedAction(agent_id='red_0', target_ip=target_ip)
    # Validation also checks routing for red agents if subnet is Secure
    # but for a random host it should be fine if it's in DMZ.
    # In seed 0, DMZ is 192.168.1.x
    dmz_ip = None
    for ip, host in global_state.all_hosts.items():
        if host.subnet_cidr == '192.168.1.0/24':
            dmz_ip = ip
            break

    action = SimpleRedAction(agent_id='red_0', target_ip=dmz_ip)
    assert action.validate(global_state) is True

    # Invalid IP should fail validation
    invalid_action = SimpleRedAction(agent_id='red_0', target_ip='999.999.999.999')
    assert invalid_action.validate(global_state) is False


@pytest.mark.fast
def test_base_action_execution(global_state):
    """Verify execution logic returns ActionEffect."""
    target_ip = '192.168.1.5'
    action = SimpleRedAction(agent_id='red_0', target_ip=target_ip)

    # Ensure host exists
    from netforge_rl.core.state import Host

    global_state.register_host(
        Host(ip=target_ip, hostname='Test', subnet_cidr='192.168.1.0/24')
    )

    effect = action.execute(global_state)

    assert isinstance(effect, ActionEffect)
    assert effect.success is True
    assert effect.state_deltas['hosts/' + target_ip + '/status'] == 'pwned'
