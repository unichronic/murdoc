# UI

React dashboard for local development, gateway route settings, runtime settings,
and attack-lab runs.

## Run

```bash
npm install
npm run dev
```

## Build

```bash
npm run build
```

The production FastAPI gateway lives in `murdoc.gateway.app` at the repo
root. `ui/server.py` is a compatibility shim for old local commands; new code
should import or run `murdoc.gateway.app`.
