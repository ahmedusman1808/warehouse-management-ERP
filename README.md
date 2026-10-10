# Warehouse Management ERP

The ERP runs as a same-origin web app and API. PostgreSQL is the shared source of truth, so accounts and records are available on every device that signs in to the deployed URL.

## Local server

Requirements: Node.js 20+ and PostgreSQL 14+.

1. Copy `.env.example` to `.env` and set `DATABASE_URL` for your PostgreSQL instance. If using Docker Compose, also set `POSTGRES_PASSWORD` to a long random value.
2. Install dependencies with `npm install`.
3. Start the app with `npm start`.
4. Open `http://localhost:3000` and create the first administrator account.

The server creates its tables on first startup. It serves both the UI and `/api`; do not open `index.html` directly when using shared accounts.

## Internet deployment

Deploy this repository as a Node/Docker web service and attach a managed PostgreSQL database. Set these environment variables in the hosting dashboard:

- `NODE_ENV=production`
- `DATABASE_URL` to the provider's PostgreSQL connection string
- `PGSSL=true` when the provider requires TLS for database connections
- `PORT` to the port supplied by the host, if required

Put the web service behind the host's HTTPS endpoint. Production cookies are Secure and will not work over plain HTTP. Keep the database private; only the app service should connect to it. Do not publish `.env` or database credentials.

After the public URL is active, open it once to create the first administrator. Add caretaker accounts from **Admin & Access**. Other devices should use that same HTTPS URL. State updates synchronize through PostgreSQL; the UI refreshes shared data every few seconds. If two devices edit the same data at once, the server rejects a stale save instead of silently overwriting the newer version; reload to receive the latest copy.

## Existing browser data

On the first admin setup, the app offers to import existing records from that browser into an empty server database. This is a one-time migration. Keep a downloaded backup before deployment. Records cannot be shared across browsers until the hosted API is configured and the migration is accepted.

## Backups

Use the ERP's **Download data backup** action regularly and configure automated PostgreSQL backups with your hosting provider. The JSON download is a portable copy, not a replacement for database backups.
