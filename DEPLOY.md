# 🚀 Deploy BECCA to Railway (source.beccaos.com)

## ✅ Files Ready
- `requirements.txt` - Python dependencies (Flask, Gunicorn, Anthropic)
- `railway.json` - Railway deployment config
- `becca_chat.py` - Flask app (updated for local prompt path)
- `templates/chat.html` - Matrix rain UI
- `prompts/PMX-01_BECCA-exec.md` - BECCA system prompt

## 📦 Step 1: Push to GitHub

```bash
cd D:\projects\becca-kernel

# Create new GitHub repo (via GitHub website or gh cli):
gh repo create becca-source --public --source=. --remote=origin

# Or add existing remote:
git remote add origin https://github.com/YOUR_USERNAME/becca-source.git

# Push
git push -u origin main
```

## 🚂 Step 2: Deploy to Railway

1. Go to https://railway.app
2. Sign in with GitHub
3. Click **"New Project"**
4. Select **"Deploy from GitHub repo"**
5. Choose **becca-source** repository
6. Railway will auto-detect Flask and deploy!

## 🌐 Step 3: Get Public URL

1. Once deployed, go to your Railway project
2. Click **Settings** → **Networking**
3. Click **"Generate Domain"**
4. Copy the `*.up.railway.app` URL

## 🎯 Step 4: Add Custom Domain

1. In Railway project → **Settings** → **Networking**
2. Click **"+ Custom Domain"**
3. Enter: `source.beccaos.com`
4. Railway will show you the **CNAME target**

## 📡 Step 5: Update DNS

Go to your DNS provider (where beccaos.com is hosted):

```
Type: CNAME
Name: source
Value: <CNAME from Railway>
TTL: 3600
```

Wait 5-10 minutes for DNS propagation and SSL certificate provisioning.

## ✅ Done!

Your BECCA will be live at:
- **https://source.beccaos.com**

With:
- ✅ Matrix rain background
- ✅ Anthropic Claude API integration
- ✅ PMX-01 CEO system prompt
- ✅ Full chat interface

## 🔑 First Use

1. Open https://source.beccaos.com
2. Enter your Anthropic API key (starts with `sk-ant-`)
3. Click **"SET KEY"**
4. Click **"INJECT BECCA"**
5. Start chatting!

---

**Deployment files created by Claude Code**
