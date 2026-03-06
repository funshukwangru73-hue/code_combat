# 🚀 ContestGuard Deployment Guide

## Quick Start - Deploy to Render in 5 Minutes

### Step 1: Prepare Your Files
Replace your old files with these new ones:
- ✅ `requirements.txt` (fixed spelling!)
- ✅ `render.yaml` (added health checks)
- ✅ `server.py` (added SQLite + rate limiting)

Keep these files as-is:
- `student_app.py`
- `admin_app1_1.py`
- `restore.py`

### Step 2: Push to GitHub

```bash
# If you haven't initialized git yet:
git init
git add .
git commit -m "Production-ready ContestGuard with SQLite persistence"

# Create a new repo on GitHub, then:
git remote add origin https://github.com/YOUR_USERNAME/contestguard.git
git branch -M main
git push -u origin main
```

### Step 3: Deploy to Render

1. Go to https://render.com and sign up/login
2. Click "New +" → "Web Service"
3. Connect your GitHub repository
4. Render will auto-detect the `render.yaml` configuration
5. Click "Create Web Service"
6. Wait 2-3 minutes for deployment

### Step 4: Get Your Server URL

After deployment completes, you'll see a URL like:
```
https://contestguard-server.onrender.com
```

### Step 5: Update Client Apps

Open both `student_app.py` and `admin_app1_1.py` and update line 68/60:

```python
DEFAULT_SERVER = "https://YOUR-RENDER-URL.onrender.com"
```

### Step 6: Test It!

```bash
# Test health endpoint
curl https://YOUR-RENDER-URL.onrender.com/health

# Should return:
# {"status":"ok","sessions":0,"uptime_seconds":123,"time":"2025-..."}
```

## 🎯 Testing Before Contest

### Test Session Creation

**Using curl:**
```bash
curl -X POST https://YOUR-RENDER-URL.onrender.com/session/create \
     -H "Content-Type: application/json" \
     -d '{"contest_name":"Test Contest"}'
```

**Expected Response:**
```json
{
  "session_id": "A3F7B2C1",
  "session_code": "1234",
  "admin_token": "abc123...",
  "message": "Session created..."
}
```

### Test with Admin App

1. Run `admin_app1_1.py` (no admin rights needed)
2. Enter your Render URL
3. Click "Create Session"
4. Should show Session ID and QR code

### Test with Student App

1. Run `student_app.py` as Administrator
2. Enter Session ID and 4-digit code from admin app
3. Click "Join Contest"
4. Should lock the machine

### Test Session End

1. In admin app, click "End Session"
2. Student app should unlock automatically
3. Firewall should restore to original state

## 📊 Monitoring Your Deployment

### Render Dashboard
- View logs: Dashboard → Your Service → Logs
- Check metrics: CPU, memory usage
- Restart if needed: Manual Deploy → Clear build cache & deploy

### Health Monitoring (Recommended)

**Set up UptimeRobot (free):**
1. Go to https://uptimerobot.com
2. Add monitor: `https://YOUR-RENDER-URL.onrender.com/health`
3. Check interval: 5 minutes
4. Get alerts via email if server goes down

## ⚠️ Important Notes

### Render Free Tier Limitations
- Server sleeps after 15 minutes of inactivity
- First request after sleep takes ~30 seconds to wake up
- Solution: Have admin ping /health before contest starts

### Database Location
- SQLite database stored at `/tmp/contestguard.db`
- Persists during the same deployment
- **Gets reset when you redeploy** - export data first!

### Rate Limits
The new server has built-in rate limiting:
- Session creation: 10/minute
- Status polling: 120/minute (students poll every 8 seconds)
- Log viewing: 30/minute

## 🔧 Troubleshooting

### "Build failed" on Render
**Issue:** Can't find requirements.txt
**Fix:** Make sure you renamed `requirment.txt` → `requirements.txt`

### "503 Service Unavailable"
**Issue:** App crashed
**Fix:** Check Render logs for Python errors

### "Session not found" errors
**Issue:** Server restarted and lost in-memory data (if you didn't use new server.py)
**Fix:** Use the new `server.py` with SQLite persistence

### Student app can't connect
**Issue:** Wrong server URL
**Fix:** Verify DEFAULT_SERVER matches your Render URL exactly

### Firewall not restoring
**Issue:** restore.py not in same folder as student_app.py
**Fix:** Always distribute both files together

## 🎓 Running a Contest - Checklist

### 1 Hour Before Contest
- [ ] Check Render dashboard - server is running
- [ ] Test /health endpoint responds
- [ ] Wake up the server (visit the URL)
- [ ] Have backup admin credentials ready

### 30 Minutes Before
- [ ] Run admin app, create session
- [ ] Note down Session ID and Code
- [ ] Add allowed IPs for judge/coding platforms
- [ ] Push IPs to students

### 15 Minutes Before
- [ ] Test with one student machine
- [ ] Verify firewall locks correctly
- [ ] Verify firewall unlocks on session end
- [ ] Create the REAL session for contest

### During Contest
- [ ] Keep admin app open
- [ ] Monitor logs tab for student activity
- [ ] Be ready to push IP updates if needed
- [ ] Watch Render dashboard for any errors

### After Contest
- [ ] Click "End Session" in admin app
- [ ] Verify all students unlocked successfully
- [ ] Export/screenshot logs if needed
- [ ] Sessions auto-expire but you can manually clean DB

## 📦 Distribution - Student App

### Create Standalone EXE (Optional)

```bash
# Install PyInstaller
pip install pyinstaller

# Create EXE
pyinstaller --onefile --windowed ^
    --add-data "restore.py;." ^
    --icon=icon.ico ^
    --name ContestGuard_Student ^
    student_app.py
```

**Distribution package should include:**
- ContestGuard_Student.exe
- restore.py (in same folder)
- README with installation instructions

### Installation Instructions for Students

```
ContestGuard Student App - Installation
========================================

1. Download both files:
   - ContestGuard_Student.exe
   - restore.py
   Keep them in the SAME folder!

2. Right-click ContestGuard_Student.exe
   → Run as Administrator (REQUIRED!)

3. Windows Defender may show a warning:
   - Click "More info"
   - Click "Run anyway"

4. Enter the Session ID and 4-digit code
   provided by your contest organizer

5. Click "Join Contest & Lock Machine"

6. Your firewall is now locked to contest IPs only
   DO NOT close the app during the contest!

7. When contest ends, the app will automatically
   unlock your machine and restore your firewall
```

## 🔐 Security Best Practices

### For Production Contests

1. **Use HTTPS only** (Render provides this free)

2. **Change CORS settings** in server.py:
   ```python
   CORS(app, origins=["https://your-admin-domain.com"])
   ```

3. **Keep admin tokens secret**
   - Don't share in public channels
   - Generate new session for each contest

4. **Monitor logs during contest**
   - Watch for suspicious activity
   - Check student connection counts

5. **Backup session data**
   - Export logs after contest
   - Screenshot important info

## 📞 Need Help?

**Common Issues:**
- Server not responding → Check Render logs
- Student can't connect → Verify server URL
- Firewall not working → Must run as Administrator
- Session disappeared → Server restarted (use new server.py with SQLite)

**Render Support:**
- https://render.com/docs
- https://community.render.com

**Test thoroughly before your real contest!**

---

**Your new files are ready! The main improvements:**
✅ SQLite persistence (sessions survive restarts)
✅ Rate limiting (prevents abuse)  
✅ Better error handling
✅ Proper logging for debugging
✅ Health checks for monitoring
✅ Fixed typo in requirements.txt

Deploy and test - you're good to go! 🚀
