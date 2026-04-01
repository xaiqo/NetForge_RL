import pytest
from netforge_rl.actions.red.exploits import ExploitEternalBlue
from netforge_rl.actions.red.post_exploitation import DumpLSASS, PassTheTicket


@pytest.mark.integration
def test_ztna_end_to_end_breach(env_sim):
    """Verify that Red can breach the secure subnet only via the identity kill chain."""
    env_sim.reset(seed=42)
    state = env_sim.global_state
    red_agent = 'red_operator'

    # 1. Choose a target in the Secure subnet (10.0.1.0/24)
    secure_ip = None
    for ip, host in state.all_hosts.items():
        if host.subnet_cidr == '10.0.1.0/24':
            secure_ip = ip
            break

    # 2. Try to exploit directly - Should fail validation or execution due to ZTNA
    exploit = ExploitEternalBlue(agent_id=red_agent, target_ip=secure_ip)
    assert exploit.validate(state) is False

    # 3. Pivot: Compromise a DMZ host (192.168.1.0/24)
    for h in state.all_hosts.values():
        if h.subnet_cidr == '192.168.1.0/24':
            h.privilege = 'Root'
            h.compromised_by = red_agent
            break

    # 4. Pivot: Compromise a Corporate host (10.0.0.0/24)
    corp_ip = None
    for ip, host in state.all_hosts.items():
        if host.subnet_cidr == '10.0.0.0/24':
            corp_ip = ip
            host.privilege = 'Root'
            host.compromised_by = red_agent
            host.cached_credentials = ['Enterprise_Admin_Token']
            break

    # 5. Dump LSASS to get the token
    dump_action = DumpLSASS(agent_id=red_agent, target_ip=corp_ip)
    effect = dump_action.execute(state)
    assert effect.success is True

    # Manually apply the command delta
    cmd = effect.state_deltas['inventory_update']
    cmd.execute(state)

    assert 'Enterprise_Admin_Token' in state.agent_inventory[red_agent]

    # 6. Now try to validate the exploit against Secure subnet - Should pass routing check
    assert state.can_route_to(secure_ip, agent_id=red_agent) is True

    # 7. Execute PassTheTicket to compromise the Secure host
    state.all_hosts[secure_ip].system_tokens = ['Enterprise_Admin_Token']
    ptt_action = PassTheTicket(agent_id=red_agent, target_ip=secure_ip)
    assert ptt_action.validate(state) is True

    ptt_effect = ptt_action.execute(state)
    assert ptt_effect.success is True

    # Apply deltas manually
    for key, val in ptt_effect.state_deltas.items():
        state.apply_delta(key, val)

    assert state.all_hosts[secure_ip].privilege == 'Root'
    assert state.all_hosts[secure_ip].compromised_by == red_agent
