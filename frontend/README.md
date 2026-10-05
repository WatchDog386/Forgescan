# Dashboard

The React dashboard is the fourth increment and is not built yet.

The backend already serves everything it needs:

- `POST /api/v1/auth/login` to sign in, then `Authorization: Bearer <token>` on every request.
- `GET /api/v1/stats/summary`, `/alerts` and `/incidents` for the screens.
- `WebSocket /api/v1/ws/events?token=<token>` for live alerts, incidents and responses.

Until it exists, use the interactive API pages at http://127.0.0.1:8000/docs.
