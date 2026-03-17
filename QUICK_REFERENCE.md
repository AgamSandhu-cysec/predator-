# 🦅 PREDATOR QUICK REFERENCE CARD

## 🚀 Quick Start (3 Steps)

```bash
# 1. Launch
python3 predator.py

# 2. Connect (in TUI)
Target IP: 192.168.1.10
Username: user
Password: password
OS: Linux
Click "Connect"

# 3. Auto Pwn (after enumeration)
Go to "Auto Exploit" tab
Click "🚀 Auto Pwn"
Get root shell!
```

---

## 📋 Pre-Flight Checklist

- [ ] Set LHOST in `config.yaml` (for reverse shells)
- [ ] Virtual environment activated (`source venv/bin/activate`)
- [ ] Target credentials ready
- [ ] Network connectivity verified

---

## ⚙️ Essential Configuration

### config.yaml Key Settings

```yaml
# Set YOUR attacking machine IP here!
listener:
  lhost: '10.10.14.5'  # ← CHANGE THIS
  lport: 4444

# Performance tuning
execution:
  parallel_exploits: true
  max_parallel: 3
  validate_success: true

# Auto-download
downloader:
  auto_download: true
  cache_dir: ~/.predator/exploits
```

---

## 📊 TUI Navigation

| Tab | Purpose | Action |
|-----|---------|--------|
| Connection | Connect to target | Enter IP, creds, click Connect |
| Enumeration | Live command output | Auto-runs, click Pause if needed |
| Findings | PEAS results | Click "Run LinPEAS/WinPEAS" |
| Exploits | ML recommendations | Select & click "Run Selected" |
| Auto Exploit | Automated pwn | Click "🚀 Auto Pwn" |
| Shell | Interactive root shell | Auto-opens after success |

---

## 🎯 Exploit Confidence Levels

| Color | Confidence | Meaning |
|-------|-----------|---------|
| 🟢 Green | >0.70 | High confidence - try first |
| 🟡 Yellow | 0.40-0.70 | Medium confidence |
| 🔴 Red | <0.40 | Low confidence - fallback |

---

## 💣 Built-In Exploits

### Linux
- **DirtyCow** (CVE-2016-5195) - Kernel 2.6-4.8
- **PwnKit** (CVE-2021-4034) - Polkit privilege escalation
- **Baron Samedit** (CVE-2021-3156) - Sudo heap overflow
- **SUID Python** - Python with SUID bit
- **SUID Bash** - Bash with SUID bit

### Windows
- **Juicy Potato** - SeImpersonatePrivilege
- **PrintSpoofer** - Print Spooler (newer)
- **Unquoted Service Path** - Service misconfiguration
- **AlwaysInstallElevated** - Registry misconfiguration

---

## 🔧 Common Issues & Fixes

### Issue: DirtyCow compilation fails
**Fix:** Tool auto-downloads precompiled binary. If still fails:
```bash
# On target (if you have shell):
apt install build-essential gcc
```

### Issue: "No exploit sources found"
**Fix:** Install searchsploit:
```bash
sudo apt update && sudo apt install exploitdb
```

### Issue: Reverse shells not connecting
**Fix:** Check LHOST in config.yaml:
```yaml
listener:
  lhost: 'YOUR_IP_HERE'  # Not empty!
```

### Issue: All exploits fail
**Fix:** Run PEAS first for better recommendations:
1. Go to Findings tab
2. Click "Run LinPEAS/WinPEAS"
3. Wait for completion
4. Try Auto Pwn again

---

## 🏃 Workflow Strategies

### Strategy 1: Fast & Furious (Parallel Mode)
```
1. Connect → Wait for enum
2. Auto Exploit tab → Auto Pwn
3. Get root in 30 seconds!
```

### Strategy 2: Methodical (Best Accuracy)
```
1. Connect → Wait for enum
2. Findings tab → Run PEAS
3. Review enhanced recommendations
4. Auto Exploit → Auto Pwn
```

### Strategy 3: Manual Selection
```
1. Connect → Wait for enum
2. Exploits tab → Select specific exploit
3. Click "Run Selected Exploit"
4. Enter shell manually
```

---

## 🎨 Log Color Codes

| Color | Meaning |
|-------|---------|
| 🟢 Green | Success, completion |
| 🔴 Red | Error, failure |
| 🟡 Yellow | Warning, needs attention |
| 🔵 Cyan | Info, progress |
| 🟣 Magenta | Headers, stages |

---

## 🐛 Debugging

### Enable Verbose Logging
Check `predator.log`:
```bash
tail -f predator.log
```

### Test Single Module
```python
python3 -c "
from exploits.linux.dirtycow import run
from connector.ssh_connector import SSHConnector

session = SSHConnector('192.168.1.10', 'user', 'password')
session.connect()
result = run(session, lambda x: print(x, end=''))
print(f'Result: {result}')
"
```

### Check Downloads
```bash
ls -la ~/.predator/exploits/
```

---

## 📱 Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| Tab | Next widget/field |
| Shift+Tab | Previous widget |
| Enter | Activate button |
| Ctrl+Q | Quit Predator |
| Ctrl+C | Stop current action (in shell) |

---

## 💡 Pro Tips

### 1. Pre-Cache Exploits
```bash
python3 -c "
from downloader import ensure_exploit
ensure_exploit('dirtycow')
ensure_exploit('pkexec_pwnkit')
ensure_exploit('printspoofer')
"
```

### 2. Batch Testing
Create a targets.txt:
```
192.168.1.10,user,password,linux
192.168.1.11,admin,pass123,windows
```

### 3. Custom Exploits
Add your own:
```python
# exploits/linux/my_exploit.py
from exploits.base import BaseExploit

class MyExploit(BaseExploit):
    def run(self, session, update_callback=None):
        # Your code
        return True

def run(session, update_callback=None):
    return MyExploit().run(session, update_callback)
```

### 4. Parallel Tuning
Adjust for slower/faster targets:
```yaml
execution:
  max_parallel: 2  # For slow targets
  max_parallel: 5  # For fast targets
```

### 5. Offline Mode
Pre-download all exploits, then disconnect internet.

---

## 📊 Success Indicators

### Exploit Succeeded
```
[+] Root confirmed! (uid=0, user=root)
[+] EXPLOIT SUCCESSFUL! Dropping into Interactive Shell...
═══════════════════════════════════
EXPLOIT VALIDATION REPORT
✓ UID: PASS
✓ File Write: PASS
✓ Process Access: PASS
✓ Stability: PASS
Overall: 4/4 checks passed (100% confidence)
═══════════════════════════════════
```

### Exploit Failed
```
[-] Exploit ran but session is NOT root (uid=1000, user=user)
[-] Compilation failed: ...
[-] Could not locate exploit source
```

---

## 🆘 Emergency Commands

### Lost Shell?
Press Ctrl+C multiple times, then type `exit`

### TUI Frozen?
Press Ctrl+Z (background), then:
```bash
killall python3
python3 predator.py  # Restart
```

### Clean Start
```bash
rm -rf ~/.predator/exploits/
rm predator.log
python3 predator.py
```

---

## 📚 Documentation Hierarchy

1. **This file** (QUICK_REFERENCE.md) - Daily usage
2. **README_ENHANCED.md** - Full features & examples
3. **ENHANCEMENTS_SUMMARY.md** - Technical details
4. **Code comments** - Implementation details

---

## ✅ Before Engagement Checklist

- [ ] LHOST configured
- [ ] Virtual environment active
- [ ] searchsploit installed
- [ ] Network connectivity verified
- [ ] Target credentials confirmed
- [ ] Exploits pre-cached (optional)
- [ ] Log file cleared (for OPSEC)
- [ ] Authorization obtained (MANDATORY)

---

## 🎯 Target Selection Tips

### Good Targets (High Success Rate)
- Ubuntu 14.04-18.04 (DirtyCow)
- Ubuntu 20.04-21.04 (PwnKit)
- Windows Server 2016/2019 (PrintSpoofer)
- Machines with SUID binaries
- IIS/SQL Server (SeImpersonate)

### Difficult Targets
- Fully patched systems
- Containers (limited kernel access)
- No compiler on target
- Heavy AV/EDR
- Network restrictions

---

## 🔥 One-Liners

### Quick Test
```bash
python3 predator.py --target 192.168.1.10 --username user --password password --os linux
```
*(Note: CLI mode not implemented, TUI only)*

### Mass Scan
```bash
for ip in 192.168.1.{10..20}; do
    echo "Testing $ip..."
    # Use Predator TUI per target
done
```

---

## 📞 Getting Help

1. **Check logs**: `cat predator.log`
2. **Read error message**: Now includes fixes!
3. **Review validation**: Shows what passed/failed
4. **Test on known-vulnerable**: HTB/THM machines
5. **Check config**: Especially LHOST

---

## 🏆 Success Metrics To Track

- ⏱️ Time to root
- 📊 Exploit success rate
- 🎯 First-try successes
- 🔄 Average retries needed
- 💻 Target types pwned

---

## 🎉 You're Ready!

```
 _____                   _       _              
|  __ \                 | |     | |             
| |__) | __ ___  __   __| | __ _| |_ ___  _ __  
|  ___/ '__/ _ \ \ \ / _` |/ _` | __/ _ \| '__| 
| |   | | |  __/  \ V | | (_| | || (_) | |    
|_|   |_|  \___|   \_/ |_|\__,_|\__\___/|_|    

Enhanced Edition - Ready for Combat 🦅
```

---

**Remember:** Only use on authorized targets. Happy hunting! 🎯
