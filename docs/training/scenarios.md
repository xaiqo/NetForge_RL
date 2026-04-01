# Scenarios

## Ransomware (`ransomware`)
Red goal: encrypt Corporate subnet hosts for maximum payout.  
Blue goal: isolate compromised hosts before ransomware deploys.

```python
env = NetForgeRLEnv({'scenario_type': 'ransomware'})
```

## APT Espionage (`apt_espionage`)
Red goal: breach the Secure subnet and exfiltrate PLC data / activate OT impact.  
Blue goal: detect lateral movement via SIEM and rotate Kerberos before tokens are used.

```python
env = NetForgeRLEnv({'scenario_type': 'apt_espionage'})
```

## Scenario Config Reference

| Key | Values | Default | Description |
|-----|--------|---------|-------------|
| `scenario_type` | `ransomware`, `apt_espionage` | `ransomware` | Episode objective |
| `sim2real_mode` | `sim`, `real` | `sim` | Hypervisor mode |
| `nlp_backend` | `tfidf`, `transformer` | `tfidf` | SIEM encoder backend |
