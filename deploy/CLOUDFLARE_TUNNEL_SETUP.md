# BECCA Online - Cloudflare Tunnel Setup

Deploy BECCA to **iam.beccaos.com** using Cloudflare Tunnel.

## Prerequisites

1. Domain `beccaos.com` managed by Cloudflare
2. Cloudflare account (free tier works)
3. `cloudflared` installed on your PC

---

## Step 1: Install cloudflared

### Windows (PowerShell as Admin):
```powershell
winget install Cloudflare.cloudflared
```

Or download from: https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/installation/

---

## Step 2: Authenticate with Cloudflare

```bash
cloudflared tunnel login
```

This opens a browser - select your domain (beccaos.com).

---

## Step 3: Create the Tunnel

```bash
cloudflared tunnel create becca-online
```

This creates a tunnel and outputs a **Tunnel ID** (save it!).

---

## Step 4: Configure the Tunnel

Create config file at `C:\Users\<YOU>\.cloudflared\config.yml`:

```yaml
tunnel: <YOUR-TUNNEL-ID>
credentials-file: C:\Users\<YOU>\.cloudflared\<TUNNEL-ID>.json

ingress:
  - hostname: iam.beccaos.com
    service: http://localhost:5001
  - service: http_status:404
```

---

## Step 5: Create DNS Record

```bash
cloudflared tunnel route dns becca-online iam.beccaos.com
```

This creates a CNAME record pointing iam.beccaos.com to your tunnel.

---

## Step 6: Start the Tunnel

```bash
cloudflared tunnel run becca-online
```

---

## Step 7: Run as Windows Service (Auto-start)

```powershell
# As Administrator
cloudflared service install
cloudflared service start
```

---

## Production Security Checklist

Before going live, update `D:\projects\becca-kernel\.env`:

```env
# Restrict to your domain only
ALLOWED_ORIGINS=https://iam.beccaos.com

# Keys are already auto-generated - check with:
# http://localhost:5001/api/keys
```

---

## Quick Start Commands

```powershell
# Terminal 1: Start BECCA
cd D:\projects\becca-kernel
python becca_online.py

# Terminal 2: Start Tunnel
cloudflared tunnel run becca-online
```

---

## Phone Access

Once running:
1. Open **https://iam.beccaos.com** on your phone
2. Select a project
3. Ask BECCA questions!

---

## Troubleshooting

### Tunnel not connecting?
```bash
cloudflared tunnel info becca-online
```

### Check tunnel logs:
```bash
cloudflared tunnel run becca-online --loglevel debug
```

### Test locally first:
```
http://localhost:5001
```

---

## Security Notes

- Cloudflare provides HTTPS automatically
- Your PC's IP is never exposed
- Rate limiting is built into BECCA (30 req/60s)
- API key required for sensitive operations

