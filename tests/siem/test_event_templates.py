import pytest
import xml.etree.ElementTree as ET
from netforge_rl.siem.event_templates import (
    evid_4624,
    sysmon_10,
    ACTION_EVENT_MAP,
)


@pytest.mark.fast
def test_evid_4624_template():
    """Verify 4624 template returns valid XML string."""
    log = evid_4624(src_ip='192.168.1.1', target_ip='10.0.0.5', username='Attacker')
    assert '4624' in log
    assert '192.168.1.1' in log
    assert '10.0.0.5' in log
    assert 'Attacker' in log
    # Verify valid XML
    ET.fromstring(log)


@pytest.mark.fast
def test_sysmon_10_template():
    """Verify Sysmon 10 template returns valid XML string."""
    log = sysmon_10(src_ip='192.168.1.1')
    assert '10' in log
    assert 'lsass.exe' in log
    assert '0x1010' in log
    ET.fromstring(log)


@pytest.mark.fast
def test_action_event_map_structure():
    """Verify ACTION_EVENT_MAP has correct structure and keys."""
    assert 'ExploitEternalBlue' in ACTION_EVENT_MAP
    assert '_default' in ACTION_EVENT_MAP

    # Check one entry
    entries = ACTION_EVENT_MAP['ExploitEternalBlue']
    assert isinstance(entries, list)
    for weight, func in entries:
        assert isinstance(weight, float)
        assert callable(func)
