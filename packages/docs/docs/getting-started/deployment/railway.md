# Deploy on Railway

The fastest way to get HappyView running is with Railway. This template deploys HappyView and Postgres with a single click:

| SQLite                                                                                                                      | PostgreSQL                                                                                                                    |
| --------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| [![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/deploy/happyview-2-sqlite-1?referralCode=0QOgj_) | [![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/deploy/happyview-2-postgresql?referralCode=0QOgj_) |

## Required configuration

After deploying the template, you'll need to configure a few things before the stack works properly:

1. **Set your session secret.** In the HappyView service variables, set `SESSION_SECRET` to a random string of at least 64 characters. This is used to sign session cookies.

   ```sh
   openssl rand -base64 48
   ```

2. **Assign a public domain.** In the Railway dashboard, add a public domain to the HappyView service. The service needs a publicly accessible URL for OAuth callbacks. Set `PUBLIC_URL` to this domain (e.g. `https://happyview-production.up.railway.app`).
   :::note
   Your instance can use a custom domain or Railway's generated URL with no additional configuration.
   :::

3. Access your HappyView dashboard at the instance's public URL. The first user to log in is automatically bootstrapped as the super user.

## Next steps

- [Configuration](../configuration.md) — full list of environment variables
- [Dashboard](../dashboard.md) — manage lexicons, users, and plugins via the web UI
- [Production deployment](../production-deployment.md) — hardening checklist for production instances
