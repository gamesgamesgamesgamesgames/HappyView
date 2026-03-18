# Deploy on Railway

The fastest way to get HappyView running is with Railway. This template deploys HappyView, [Tap](https://github.com/bluesky-social/indigo/tree/main/cmd/tap) (real-time data and backfill), and Postgres with a single click:

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/deploy/happyview?referralCode=0QOgj_)

## Required configuration

After deploying the template, you'll need to configure a few things before the stack works properly:

1. **Set your session secret.** In the HappyView service variables, set `SESSION_SECRET` to a strong random value. This is used to sign session cookies.

2. **Assign a public domain.** In the Railway dashboard, add a public domain to the HappyView service. The service needs a publicly accessible URL for OAuth callbacks. Set `PUBLIC_URL` to this domain (e.g. `https://happyview-production.up.railway.app`).
   :::note
   Your instance can use a custom domain or Railway's generated URL with no additional configuration.
   :::

3. Access your HappyView dashboard at the instance's public URL. The first user to log in is automatically bootstrapped as the super user.
