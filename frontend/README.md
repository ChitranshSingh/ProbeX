# frontend/

> **Scaffolded in Task S5.**

The React + Vite frontend will live here.  It will:

- Display a scan launcher form (target URL, profile selector, consent checkbox).
- Show a real-time findings feed over the `/ws/{scan_id}` WebSocket.
- Render a findings table with severity badges, CVSS scores, and AI remediation.
- Display a "Demo" banner for scans where `is_example=true`.

## Expected tech stack (Task S5)

- **Vite + React 18** — build tooling and component model.
- **TypeScript** — type safety, with types auto-generated from the FastAPI OpenAPI spec.
- **Vanilla CSS** — utility-first styling, no external CSS framework dependency.
- **WebSocket** — native browser API for real-time progress updates.

## Dev server

Once scaffolded, start with:

```bash
npm install
npm run dev
# → http://localhost:5173
```
