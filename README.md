# AI-NIDR

An AI-powered network intrusion detection and automated response system.
Final-year project by Felix Ochieng (24/06618), KCA University, School of Technology.

AI-NIDR watches network traffic, uses machine learning to detect and name attacks, scores the risk of
each one from 0 to 100, and blocks the source of the most serious. Analysts follow events and manage
incidents through a dashboard and an API.

## Status

| Part | State |
| --- | --- |
| Feature extraction from Zeek connection records | Working |
| Detection pipeline: models, attack classification, risk scoring | Working, on a placeholder model (see below) |
| Incidents: grouping, states, notes | Working |
| Response engine with safeguards (allowlist, monitored range, limit, expiry, dry run) | Working |
| Firewall driver for nftables over SSH, and the response agent | Written, not yet tried on a real host |
| Sign-in with password and an authenticator code (optional per account until set up), roles, lockout | Working |
| REST API, live events over WebSocket, audit log | Working |
| Sensor collector for Zeek logs | Written, not yet tried against a live Zeek |
| Model trained on CIC-IDS2017 and laboratory traffic | Not done yet |
| Suricata comparison (rule match on alerts) | Not built yet |
| Email notifications, reports | Not built yet |
| React dashboard: overview, incidents, alerts, blocks, administration, live events | Working |

**About the model.** The first model is trained on traffic made by a simulator
(`backend/app/engine/simulate.py`). It lets the whole pipeline run and be tested before the laboratory
exists. Its perfect score on simulated data says nothing about real attacks. The real model comes from
`python -m ml.train` once labelled windows from CIC-IDS2017 and the laboratory are in the database.

## Folder structure

```
backend/
  app/
    main.py            the FastAPI application
    config.py          settings from the environment
    models.py          the eleven database tables
    security.py        passwords, authenticator codes, tokens, roles
    runtime.py         settings an administrator can change while it runs
    engine/
      features.py      connection records to feature windows
      detectors.py     the models, behind one interface
      risk.py          risk score and severity
      pipeline.py      the whole detection path
      simulate.py      simulated traffic for development and tests
    response/
      firewall.py      dry-run and nftables-over-SSH firewalls
      engine.py        when to block, and the safeguards
    services/          incident grouping
    routers/           the API: auth, ingest, incidents, responses, administration, live events
    cli.py             init-db, create-user, create-sensor, bootstrap-model
  ml/                  training: bootstrap (simulated) and train (labelled windows)
  tests/               automated tests
sensor/                Zeek settings, the log collector, the traffic simulator
lab/                   how to build the laboratory, and the response agent for protected hosts
frontend/              the React dashboard
docs/                  proposal, SRS and SDS
models/, data/         generated files (not committed)
```

## Setup on Windows (PowerShell)

Needs Python 3.12 or newer and Git.

```powershell
Copy-Item .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"   # paste the output into .env as SECRET_KEY

cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-dev.txt

pytest                                   # 28 tests should pass
python -m app.cli init-db
python -m app.cli create-user --name "Felix Ochieng" --email you@example.com --role administrator
python -m app.cli create-sensor --name lab-sensor
python -m app.cli bootstrap-model
uvicorn app.main:app --reload
```

`create-user` prints a secret. Add it to an authenticator app (Google Authenticator, Microsoft
Authenticator or similar) straight away: you need its six-digit code every time you sign in.
Add `--no-otp` to create an account that signs in with the password alone; its owner then turns on
two-step sign-in from the dashboard (Account, Sign-in security) by scanning a QR code. Once it is on,
every sign-in asks for the code after the password. `python -m app.cli reset-otp --email <email>`
switches it off for someone who lost their phone.
`create-sensor` prints the sensor key. Copy it; it is not shown again.

Open http://127.0.0.1:8000/docs for the interactive API pages.

Then start the dashboard in a second PowerShell window (needs Node.js 20.19 or newer):

```powershell
cd frontend
npm install        # first time only
npm run dev
```

Open http://localhost:5173 and sign in with the email and password from `create-user` (and the authenticator code, once two-step sign-in is on).

If PowerShell refuses to run `Activate.ps1`, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once.

## Try it without a laboratory

With the backend and dashboard running, open another PowerShell window in the repository folder:

```powershell
backend\.venv\Scripts\Activate.ps1
python sensor\simulate_traffic.py --key <sensor key> --attack normal --seconds 60
python sensor\simulate_traffic.py --key <sensor key> --attack port_scan
python sensor\simulate_traffic.py --key <sensor key> --attack dos
```

The alerts arrive live on the dashboard's Overview screen. The flood appears under Incidents as a
critical incident with a block recorded as `dry_run`.

## Safety

- Automatic response is **off** by default. The system records what it would have blocked. Switch it on
  under Administration on the dashboard (or `PUT /api/v1/settings {"auto_response": true}`) only inside the laboratory.
- The firewall is in dry-run mode until `FIREWALL_MODE=ssh` is set in `.env`.
- The system never blocks an address outside `MONITORED_NETWORK` or on the allowlist.
- Run test attacks only inside the isolated laboratory described in `lab/README.md`.
- Never commit `.env`, anything in `data/`, or packet captures.
