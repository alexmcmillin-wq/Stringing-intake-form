# Stringing Intake

Racquet stringing intake form, job queue, printable racquet tags and a searchable client database.
Node + Express + Postgres, built to run on Railway.

- Staff unlock with the **staff PIN**: take in racquets, edit jobs, move the queue, print tags.
- The **owner PIN** can also delete jobs and clients, and import records.
- A device stays unlocked for 30 days, or until someone taps **Lock**. Changing a PIN signs out everyone using it.

## Deploy on Railway

1. **Put the code on GitHub.** Create a new **private** repository, then use *Add file → Upload files* and drop in everything from this folder (`server.js`, `package.json`, `.gitignore`, `README.md` and the `public` folder).
2. **Create the app.** In Railway: *New Project → Deploy from GitHub repo* and pick the repository.
3. **Add the database.** In the same project: *+ New → Database → PostgreSQL*.
4. **Set variables** on the app service (*Variables* tab):

   | Variable | Value |
   |---|---|
   | `DATABASE_URL` | `${{Postgres.DATABASE_URL}}` |
   | `STAFF_PIN` | the PIN staff will use |
   | `OWNER_PIN` | your PIN (must differ from the staff PIN) |
   | `SESSION_SECRET` | any long random string, e.g. 40 random letters and numbers |

5. **Get a link.** App service → *Settings → Networking → Generate Domain*. That's the address for every phone and computer.
6. **Bring in your existing records.** Open the link, unlock with the owner PIN, go to *Clients → Import records* and choose `stringing-records.json`. Keep that file out of the repository; delete it once imported.

The app creates its database tables on first start. Railway redeploys automatically when you change a variable or push to GitHub.

## Run locally

```
npm install
DATABASE_URL=postgresql://localhost/stringing STAFF_PIN=1111 OWNER_PIN=2222 SESSION_SECRET=dev npm start
```
Then open http://localhost:3000.

## Data

Two tables, `clients` and `jobs`, each `(id TEXT PRIMARY KEY, data JSONB, updated_at TIMESTAMPTZ)`.
Back up from Railway's Postgres service (*Backups* tab) or with `pg_dump "$DATABASE_URL"`.
