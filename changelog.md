# Changelog

All notable changes to the `marl_cyborg` project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [3.0.0] - 2026-02-28
### Added
- **PettingZoo API Core Integration**: Created `marl_cyborg/environment/parallel_env.py` substituting the legacy wrapper paradigm with `pettingzoo.ParallelEnv`, explicitly allowing concurrent multi-agent action steps.
- **Gymnasium Box Compatibility**: All spaces natively map to `gymnasium.spaces` APIs instead of arbitrary nested classes.
- **`BaseAction` / `BaseObservation` Abstract Hierarchy**: Abstracted action mutation. Cyber attacks no longer edit the state directly, but rather return a theoretical JSON impact via `ActionEffect` allowing the environment to resolve simultaneity conflicts natively.
- **Python 3.12 Support (Native)**: Enforced via the new `pyproject.toml` definition.
- **IPFragmentationAction Proof of Concept**: Added a reference action block mimicking deep IP fragmentation exploits to prove structural extensibility.

### Removed
- **OpenAI Gym Legacy Layers**: Deleted `/Agents/Wrappers/` completely. Removed `ChallengeWrapper`, `OpenAIGymWrapper`, and `TrueTableWrapper`.
- **Demo / Unnecessary Dependencies**: Removed legacy `/Evaluation/`, unneeded testing stubs, setup.py files, and legacy `requirements.txt`.
