# Architecture Overview

High-level technical architecture of the NetForge RL engine.

## System Diagram

```mermaid
graph TB
    subgraph Agents
        RC[Red Commander]
        RO[Red Operator]
        BC[Blue Commander]
        BO[Blue Operator]
    end

    subgraph Engine["NetForge Engine (parallel_env.py)"]
        TICK[Async Tick Clock]
        REG[Action Registry]
        CRE[Conflict Resolution Engine]
        OBS[BaseObservation Builder]
    end

    subgraph Pillars["Three Research Pillars"]
        P1["Pillar 1:<br/>Zero-Trust Identity<br/>(state.py + identity.py)"]
        P2["Pillar 2:<br/>NLP-SIEM Pipeline<br/>(siem/ + nlp/)"]
        P3["Pillar 3:<br/>Sim2Real Bridge<br/>(sim2real/)"]
    end

    subgraph State["Global Network State"]
        HOSTS[all_hosts: Dict IP→Host]
        SUBNETS[subnets: Dict CIDR→Subnet]
        SIEM_BUF[siem_log_buffer: List]
        TOKENS[agent_inventory: Dict→Set]
    end

    Agents -->|MultiDiscrete actions| REG
    REG --> TICK
    TICK --> CRE
    CRE --> P1
    CRE --> P3
    P3 --> P2
    P2 --> State
    P1 --> State
    State --> OBS
    OBS -->|Dict obs| Agents
```

## Three Research Pillars

### Pillar 1 — Zero-Trust Identity
Hard cryptographic routing constraints. See [Zero-Trust Architecture](zero_trust.md).

### Pillar 2 — NLP-SIEM Pipeline
Stochastic Windows Event XML + 128-dim TF-IDF encoder. See [NLP-SIEM Pipeline](nlp_siem.md).

### Pillar 3 — Sim2Real Bridge
Dual-mode hypervisor (mock/Docker). See [Sim2Real Bridge](sim2real.md).

## Episode Lifecycle

```mermaid
sequenceDiagram
    participant Policy
    participant Env as NetForgeRLEnv
    participant State as GlobalNetworkState
    participant Bridge as Sim2RealBridge

    Policy->>Env: reset(seed)
    Env->>Bridge: teardown_all()
    Env->>State: generate(seed)
    Env-->>Policy: obs {obs, action_mask, siem_embedding=zeros}

    loop Every Tick
        Policy->>Env: step(actions)
        Env->>State: validate + enqueue actions
        Env->>State: advance tick, resolve mature events
        Env->>Bridge: dispatch(exploit, target_ip, target_os)
        Bridge-->>Env: HypervisorResult
        Env->>State: SIEMLogger.log_action(effect)
        Env->>State: SIEMLogger.log_background_noise()
        State->>Env: LogEncoder.encode_buffer(last 8 logs)
        Env-->>Policy: obs {obs, action_mask, siem_embedding}
    end
```
