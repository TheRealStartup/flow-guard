# Dashboard setup: walkthrough for Inez

Goal: the whole system running on your laptop, filled with realistic data, so you can iterate on the design.
Details for each step are in the README ("Run with Docker Compose").

1. **Docker:** install Docker Desktop and start it (README has the Windows commands). Wait until the engine runs.
2. **Code:** `git clone git@github.com:TheRealStartup/flow-guard.git` and `cd flow-guard`.
3. **Keys (optional for design work):** copy `.env.example` to `.env`. Paul sends the keys privately; paste them there.
   Without keys everything still works offline: scripted model + keyword stand-in for Jev.
   With keys: set `ACL_JUDGE=jev` (real AI check) and optionally `ACL_MODEL=deepseek/deepseek-v4.1-flash`.
   `.env` is never committed.
4. **Start:** `docker compose up --build -d --wait`. Check http://localhost:8000/api/health: `"ok": true`.
5. **Data:** `docker compose exec gateway python /app/demo/seed.py`. It should print 8 ✓ lines and `Audit chain: ok`.
6. **Look around:** API docs at http://localhost:8000/docs; try `/api/metrics`, `/api/events?type=exchange`,
   `/api/sessions`, `/api/policy/history` in the browser.
7. **Design against it:** `docs/api.md` maps each endpoint to a view; `docs/dashboard-demo-panel.md` has the simple
   result card and the honest wording. Minimal set for the pitch: **Audit trail** + **Policies**.
8. **See a policy change appear:** edit `policy/policy.yaml` (e.g. `active_profile: strict`), then reload
   `/api/policy/history`. Judges will do exactly this.
9. **Dashboard code:** `dashboard/` (Next.js + shadcn). The dashboard calls `/api/*`, proxied to the gateway.
   For hot reload, keep the gateway in Docker and run the dashboard on the host on another port (3000 is taken by
   the Docker dashboard): `cd dashboard && npm install && BACKEND_URL=http://127.0.0.1:8000 npm run dev -- -p 3001`,
   then open http://localhost:3001. All read endpoints work this way; only "Try it" (`POST /api/try`) is refused,
   because it accepts calls from inside the gateway's container only. Design that view against the Docker dashboard
   on :3000, or use the data from step 5.

## Windows (PowerShell, not CMD)
- Install WSL 2 + Docker Desktop (README has the commands), then **restart Windows once**. After any install, open a
  **new** PowerShell window; old windows don't see new commands. Docker Desktop must show "Engine running".
- Clone over HTTPS (a browser login to GitHub pops up): `git clone https://github.com/TheRealStartup/flow-guard.git`,
  then `cd flow-guard`. No Git? `winget install --id Git.Git -e`, new window.
- Keys: `Copy-Item .env.example .env`, then `notepad .env`.
- Run the commands one per line (Windows PowerShell 5.1 has no `&&`).
- Hot reload: Node.js via `winget install OpenJS.NodeJS.LTS`, new window, then in `dashboard/`:
  `npm install`, then `$env:BACKEND_URL="http://127.0.0.1:8000"; npm run dev -- -p 3001`.

Problems: `docker compose logs -f gateway`. Reset the audit data: `docker compose down -v`, then steps 4–5.
