# AEGIS Shield WAF - Vercel Deployment

## 🚀 Deployment Status

Your AEGIS Shield WAF is now configured for Vercel deployment with the following structure:

### File Structure
```
waf-visual-project/
├── api/
│   └── index.js          # Serverless function entry point
├── backend/
│   └── waf-enhanced.js   # Main WAF logic
├── dashboard/            # Static dashboard files
│   ├── index.html
│   ├── app.js
│   └── style.css
├── ml/
│   └── api.py            # Python ML scoring endpoint
├── public/
│   └── index.html        # Landing page (redirects to dashboard)
└── vercel.json           # Vercel configuration
```

### Routes Configuration

- **`/`** → Redirects to `/dashboard`
- **`/dashboard`** → Serves the security dashboard
- **`/api/*`** → WAF API endpoints (stats, logs, config)
- **`/health`** → Health check endpoint
- **`/score`** → ML scoring endpoint (Python)

### Environment Variables Required

Set these in your Vercel project settings:

```env
MONGODB_URI=your_mongodb_connection_string
DISCORD_WEBHOOK=your_discord_webhook_url (optional)
TARGET_URL=http://books.toscrape.com (or your target)
```

### Deployment Steps

1. **Push to GitHub** ✅ (Already done)
2. **Vercel Auto-Deploy** (In progress)
3. **Check Deployment Logs** in Vercel dashboard
4. **Access Your WAF**:
   - Dashboard: `https://your-project.vercel.app/dashboard`
   - API: `https://your-project.vercel.app/api/stats`
   - Health: `https://your-project.vercel.app/health`

### Troubleshooting

If you still see 404 errors:

1. Check Vercel deployment logs for build errors
2. Ensure all dependencies are in `package.json`
3. Verify MongoDB connection string is set
4. Check that `api/index.js` is being recognized as a serverless function

### Local Testing

```bash
# Install dependencies
cd backend && npm install

# Start locally
npm start

# Access dashboard
http://localhost:3000/dashboard
```

## 📊 Expected Vercel Build Output

```
✓ Building...
✓ Serverless Function: api/index.js
✓ Static Files: dashboard/*
✓ Python Function: ml/api.py
✓ Deployment complete
```

---

**Note**: The first deployment may take 2-3 minutes. Subsequent deployments will be faster due to caching.
