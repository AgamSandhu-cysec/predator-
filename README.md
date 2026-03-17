# PREDATOR 🐾

<div align="center">
  <p><strong>Automated Privilege Escalation & Red Team Operations Engine</strong></p>
  <p><em>Neuro-inspired AI architecture, exploit chaining, and self-learning capabilities.</em></p>
</div>

---

## 🩸 Overview
**Predator** is a cutting-edge automated privilege escalation tool designed for Red Teamers and penetration testers. It features a complete Textual-based UI (TUI) with a dark, gore-themed aesthetic. 

Under the hood, Predator abandons static exploit lists in favor of a dynamic **Neuro-Inspired AI Architecture**. It parses enumeration data (LinPEAS, WinPEAS, custom enumerators) in real-time, feeds the extracted environment features into an intelligent predictor, and intelligently chains vectors to achieve a `root` or `SYSTEM` interactive shell automatically.

### Key Features
- **Intelligent Exploit Engine**: Evaluates confidence and success probability before launching exploits.
- **Auto Exploit Sequence**: "One-click" parallel or sequential Auto Pwn functionality.
- **Dynamic Enumeration**: Live parsing of PEAS tools and custom cross-platform (Linux/Windows) enumerators.
- **Adaptive ML Brain**: Learns from failed execution attempts and adaptively auto-fixes syntax or missing arguments.
- **Gorgeous TUI**: Built on Python `textual`, featuring live logs, data tables, and a specialized Exploit Planner.

## 🚀 Installation

Ensure you have Python 3.10+ installed on your system (Kali Linux recommended).

1. **Clone the repository:**
   ```bash
   git clone https://github.com/AgamSandhu-cysec/predator-.git
   cd predator-
   ```

2. **Set up a Virtual Environment (Optional but Recommended):**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## 💻 Usage

Start the Predator TUI from your terminal:
```bash
python predator.py
```

### Typical Workflow:
1. **Connection**: Enter the IP, Username, and Password of your lower-privileged initial foothold.
2. **Enumeration & PEAS**: Run the deep scanners to identify kernel versions, SUIDs, misconfigurations, and services.
3. **Exploits Menu**: Review the ML-engine's recommended exploit vectors, ranked by confidence.
4. **Auto-Pwn**: Hit the Auto-Exploit tab and watch the engine automatically select, upload, compile, and execute the best vulnerability chains until a root shell is established!

## 🤝 Credits
**Created and crafted by [AgamSandhu-cysec](https://github.com/AgamSandhu-cysec)**

*Thank you for using Predator.*
