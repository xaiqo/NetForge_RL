<div align="center">
  <img src="https://img.shields.io/badge/Python-3.12-blue?style=for-the-badge&logo=python" alt="Python 3.12"/>
  <img src="https://img.shields.io/badge/PettingZoo-MARL-purple?style=for-the-badge" alt="PettingZoo"/>
  <img src="https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-red?style=for-the-badge" alt="MITRE ATT&CK"/>
</div>

<h1 align="center">NetForge RL</h1>

<p align="center">
  <b>A research-grade multi-agent cybersecurity environment for Sim2Real reinforcement learning.</b><br><br>
  <a href="https://xaiqo.github.io/NetForge_RL/">📖 Documentation</a>
</p>

---

## What is NetForge RL?

NetForge RL is a **high-fidelity MARL cybersecurity simulator** derived from the CAGE/CybORG challenge environment, evolved into a physically constrained network simulation suitable for Sim2Real transfer research.

Red and Blue agents compete across a three-tier enterprise network (DMZ → Corporate → Secure/OT) under realistic POMDP conditions — partial observability, authentic SIEM telemetry, and multi-dimensional budget constraints.

> **Full documentation:** [https://rfmlab.github.io/NetForge_RL/](https://xaiqo.github.io/NetForge_RL/)

---

## Key Features

| Feature | Description |
|---------|-------------|
| **Zero-Trust Identity** | Cryptographic ZTNA token enforcement — Red physically cannot route to Secure subnet without valid `Enterprise_Admin_Token` |
| **Sim2Real Bridge** | `MockHypervisor` (fast training) ↔ `DockerHypervisor` (live Vulhub containers) — toggled by a single config flag |
| **NLP-SIEM Pipeline** | Authentic Windows Event XML + Sysmon logs encoded into 128-dim TF-IDF vectors injected into Blue's observation space |
| **32 Actions** | 17 Red Team primitives + 15 Blue Team SOC responses, all mapped to MITRE ATT&CK techniques |
| **LSTM-Ready** | PettingZoo `ParallelEnv` with `MultiDiscrete` action space, action masking, and Dict observations |
| **OT/ICS Impact** | PLC kinetic impact vector (Stuxnet-style) with ±10,000 reward — forces Red to plan a full kill chain |

---

## Quick Start

```bash
git clone [https://github.com/xaiqo/NetForge_RL.git](https://github.com/xaiqo/NetForge_RL.git)
cd NetForge_RL/Cyborg
pip install -e .
