# Setup
1. npm install && npm install @hoodprivate/sdk   (then pin the SDK version; it is beta)
2. cp .env.example .env, fill in the API key (use hc_test_ first), webhook secret and a long APP_PASSWORD
3. npm start -> http://localhost:3000
4. Register https://YOUR-DOMAIN/webhooks/hoodprivate as a webhook in the HoodPrivate dashboard (needs public HTTPS; use a tunnel for local testing)
Set NODE_ENV=production behind HTTPS so the session cookie is Secure.
