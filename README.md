# Sentinal

An authorized, non-destructive security-assessment MVP for network-connected CCTV cameras and DVRs.

## Stack

- Python 3.11+
- FastAPI REST API and Jinja2 dashboard
- Nmap for bounded TCP discovery and light service identification
- SQLite by default, using SQLAlchemy
- Pydantic request validation

## Run locally

1. Install the native Nmap binary using your operating system's package manager.
2. Create an environment and install the application:

	```bash
	python -m venv .venv
	source .venv/bin/activate
	python -m pip install -e '.[dev]'
	```

3. Start the dashboard and API:

	```bash
	uvicorn app.main:app --reload
	```

4. Open http://127.0.0.1:8000. API documentation is at http://127.0.0.1:8000/docs.

Set `DATABASE_URL` to use another SQLAlchemy-supported database URL. SQLite is the default.

## Safety and current scope

Only private or loopback IP addresses/networks are accepted, and each scan is limited to 256 addresses. The scan uses TCP connect scanning and Nmap's light service probes; it does not run NSE scripts, attempt credentials, exploit devices, or modify targets. Run scans only where you have explicit authorization. A detected open service is an observation, not proof of a vulnerability. Camera/DVR identification is heuristic, and firmware age, authentication strength, and configuration checks are not implemented yet.

The first version stores scan summaries, probable devices, exposed services, and evidence. It does not yet provide user accounts, scan cancellation, PDF export, or persistent job queuing.

## Tests

```bash
python -m pip install -e '.[dev]'
pytest
```