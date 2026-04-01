import pytest
from netforge_rl.core.state import Host, Firewall


@pytest.mark.fast
def test_host_initialization():
    """Verify Host object holds correct initial properties."""
    host = Host(ip='10.0.1.5', hostname='TestNode', subnet_cidr='10.0.1.0/24')
    assert host.ip == '10.0.1.5'
    assert host.subnet_cidr == '10.0.1.0/24'
    assert host.privilege == 'None'
    assert host.compromised_by == 'None'
    assert host.status == 'online'
    assert isinstance(host.services, list)
    assert isinstance(host.system_tokens, list)


@pytest.mark.fast
def test_global_state_generation(global_state):
    """Verify GlobalNetworkState generates subnets and hosts."""
    assert len(global_state.subnets) > 0
    assert len(global_state.all_hosts) > 0

    # Check for mandatory subnets (based on NetworkGenerator)
    subnets = [s.cidr for s in global_state.subnets.values()]
    assert '192.168.1.0/24' in subnets  # DMZ
    assert '10.0.0.0/24' in subnets  # Corporate
    assert '10.0.1.0/24' in subnets  # Secure


@pytest.mark.fast
def test_ztna_routing_unauthenticated(global_state):
    """Secure subnet should be unreachable without tokens."""
    secure_host_ip = next(
        ip for ip, h in global_state.all_hosts.items() if h.subnet_cidr == '10.0.1.0/24'
    )
    # Routing should fail for a red agent without tokens
    assert global_state.can_route_to(secure_host_ip, agent_id='red_operator') is False


@pytest.mark.fast
def test_ztna_routing_pivot_requirements(global_state):
    """Verify multi-hop pivot requirements (DMZ -> Corp -> Secure)."""
    corp_ip = next(
        ip for ip, h in global_state.all_hosts.items() if h.subnet_cidr == '10.0.0.0/24'
    )
    secure_ip = next(
        ip for ip, h in global_state.all_hosts.items() if h.subnet_cidr == '10.0.1.0/24'
    )

    # 1. No pivots: cannot reach Corp or Secure
    assert global_state.can_route_to(corp_ip, agent_id='red_operator') is False
    assert global_state.can_route_to(secure_ip, agent_id='red_operator') is False

    # 2. DMZ pivot: can reach Corp, still cannot reach Secure
    dmz_ip = next(
        ip
        for ip, h in global_state.all_hosts.items()
        if h.subnet_cidr == '192.168.1.0/24'
    )
    global_state.all_hosts[dmz_ip].privilege = 'Root'
    assert global_state.can_route_to(corp_ip, agent_id='red_operator') is True
    assert global_state.can_route_to(secure_ip, agent_id='red_operator') is False

    # 3. Corp pivot: can reach Secure (if auth exists)
    global_state.all_hosts[corp_ip].privilege = 'Root'
    global_state.agent_inventory['red_operator'] = {'Enterprise_Admin_Token'}
    assert global_state.can_route_to(secure_ip, agent_id='red_operator') is True


@pytest.mark.fast
def test_firewall_blocking(global_state):
    """Verify firewall rules block traffic even if routing is valid."""
    dmz_ip = next(
        ip
        for ip, h in global_state.all_hosts.items()
        if h.subnet_cidr == '192.168.1.0/24'
    )
    port = 80

    # 1. Open by default (for DMZ)
    assert global_state.can_route_to(dmz_ip, port=port) is True

    # 2. Explicitly block
    global_state.firewalls['global'] = Firewall('global')
    global_state.firewalls['global'].block_port('192.168.1.0/24', port)
    assert global_state.can_route_to(dmz_ip, port=port) is False


@pytest.mark.fast
def test_isolated_host_unreachable(global_state):
    """Verify isolated hosts cannot be reached by anyone."""
    dmz_ip = next(
        ip
        for ip, h in global_state.all_hosts.items()
        if h.subnet_cidr == '192.168.1.0/24'
    )
    global_state.all_hosts[dmz_ip].status = 'isolated'
    assert global_state.can_route_to(dmz_ip, agent_id='red_operator') is False
    assert global_state.can_route_to(dmz_ip, agent_id='blue_operator') is False
