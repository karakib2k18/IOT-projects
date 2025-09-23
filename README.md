# System 1 – Vulnerable IoT (Baseline)
This baseline intentionally lacks security so you can demonstrate eavesdropping risk:
- No peer-to-peer authentication or encryption
- No physical-layer security
- No gateway key generation
- Traffic forced through the gateway
- Eavesdropper success probability = 1.0

## Setup
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

## Run
python sim/runner_vulnerable.py

## Inspect results
- results/summary_vulnerable.csv (scenario-level metrics)
- results/logs_vulnerable.csv (per-message path, latency, intercepted)

## Quick check
python analysis/compare_single.py


python3 -m venv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
python3 sim/test_attacker.py
python3 sim/runner_vulnerable.py
python3 analysis/compare_single.py
python3 tests/test_vulnerability.py
# IOT-projects
