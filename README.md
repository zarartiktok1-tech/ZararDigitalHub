# Zarar Digital Hub — access-code starter

A mobile-friendly dark/neon hub. Visitors must enter a unique access code. The server checks a SHA-256 hash in MongoDB Atlas; valid codes can have an expiry and use limit. Includes an admin API to create/revoke codes.

## 1. Database
1. Create a free MongoDB Atlas deployment: https://www.mongodb.com/cloud/atlas/register
2. Create a database user and allow your hosting provider's network access (for a beginner setup, Atlas documents `0.0.0.0/0`; use stronger network restrictions where possible).
3. Select **Connect → Drivers → Node.js** and copy the connection URI. Replace the password placeholder and URL-encode special characters in the password.

## 2. Run locally
Requires Node.js 20+.
```sh
npm install
cp .env.example .env
```
Fill `.env` with your Atlas URI, a long random `SESSION_SECRET`, and a separate strong `ADMIN_KEY`. Then run:
```sh
npm start
```
Open http://localhost:3000

## 3. Host on Render
1. Upload this folder to a private GitHub repository (do not commit `.env`).
2. In https://render.com choose **New → Web Service** and connect the repository.
3. Build command: `npm install`
4. Start command: `npm start`
5. Add environment variables in Render's **Environment** settings: `MONGODB_URI`, `DB_NAME` (`zarar_hub`), `SESSION_SECRET` (32+ random characters), `ADMIN_KEY` (another long random secret), and `NODE_ENV` (`production`).
6. Deploy. Render will provide an `https://...onrender.com` URL. Free services may sleep after inactivity.

## 4. Create unique access codes
Use a REST client (such as Postman) to send a POST request to:
`https://YOUR-SERVICE.onrender.com/api/admin/codes`
Headers: `Content-Type: application/json` and `x-admin-key: YOUR_ADMIN_KEY`
Body example:
```json
{"count":5,"label":"Customer","expiresInDays":30,"maxUses":1}
```
The response returns the codes once. Copy them and send one code to each user. `maxUses: 1` means each code can be successfully used once to sign in; if you want each code to be reusable by its assigned user, set a larger `maxUses` (for example 10000) and consider adding a proper account/password system. Expiry is optional: omit `expiresInDays` or set it to 0 for no expiry.

Revoke a code:
POST `/api/admin/revoke`, same headers, body `{"code":"SDH-..."}`.

## Important security notes
- Never put `ADMIN_KEY`, `SESSION_SECRET`, or MongoDB credentials in browser JavaScript or a public repository.
- This starter stores only hashes of access codes. The admin response shows a code once; if lost, create another and revoke the old one.
- Rate limiting is enabled on code attempts. For production/high traffic, use a shared rate-limit store and a persistent session store, and add monitoring/backups.
- The starter demonstrates a gated hub. Replace placeholder module cards with your own legitimate tools, course links, and app links.
