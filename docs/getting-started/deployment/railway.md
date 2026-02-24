# Deploy on Railway

The fastest way to get HappyView running is with Railway. This template deploys HappyView, [AIP](https://github.com/graze-social/aip) (OAuth provider), [Tap](https://github.com/bluesky-social/indigo/tree/main/cmd/tap) (real-time data and backfill), and Postgres with a single click:

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/deploy/I1jvZl?referralCode=0QOgj_)

## Required configuration

After deploying the template, you'll need to configure a few things before the stack works properly:

1. **Set your admin DID.** In the AIP service variables, set `ADMIN_DIDS` to your AT Protocol DID (e.g. `did:plc:abc123...`). You can find your DID by looking up your handle on [Internect](https://internect.info/).

2. **Generate AIP signing keys.** The `OAUTH_SIGNING_KEYS` and `ATPROTO_OAUTH_SIGNING_KEYS` variables require multibase-encoded P-256 private keys. See the [AIP Signing Keys documentation](https://github.com/graze-social/aip/blob/main/CONFIGURATION.md#signing-keys) for generation instructions.

3. **Assign public domains.** In the Railway dashboard, add a public domain to both the HappyView and AIP services. The services need publicly accessible URLs to handle OAuth callbacks and XRPC requests.
   :::note
   Your instances can use custom domains or Railway's generated URLs with no additional configuration. The domains are injected automatically to the containers.
   :::

4. Access your HappyView dashboard at the instance's public URL.
