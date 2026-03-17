# Predator – Autonomous Privilege Escalation Engine with a Neural Brain

Predator is not just another enumeration script. It’s an intelligent, self-learning red team tool that automates the entire privilege escalation workflow – from initial enumeration to delivering a root shell. At its core lies a neuro-inspired decision engine that combines machine learning, a dynamic knowledge graph, and a reinforcement-learning feedback loop to think, adapt, and strike like a true predator.

## 🧠 The Brain – How Predator Thinks

Predator’s intelligence is built on three interconnected layers:

### 1. Multi-Source Feature Extraction
After a successful connection, Predator runs:
- 400+ custom enumeration commands covering every known privilege escalation vector (SUID, sudo, capabilities, cron, writable files, kernel versions, etc.).
- LinPEAS/WinPEAS to get industry-standard, color-coded findings.

All this raw data is parsed into a structured feature vector – a numerical fingerprint of the target’s security posture.

### 2. Adaptive Machine Learning Core
The feature vector feeds into an online learning model (initially trained on a large dataset of real-world vulnerabilities).
- **Model**: `SGDClassifier` with log loss (multi-class) – chosen for its ability to update incrementally after each engagement.
- **Confidence calibration**: Platt scaling ensures that a confidence score of 0.9 truly means a 90% chance of success.
- **Continual learning**: Every exploit attempt (success or failure) is fed back into the model, allowing it to adapt to new environments and patch levels.

### 3. Exploit Knowledge Graph
All known exploits (CVE-based, manual techniques, SearchSploit entries) are stored in a graph database (`networkx`).
- **Nodes**: Exploits, system features (e.g., `kernel<4.8`, `suid_python`), techniques.
- **Edges**: `requires` (prerequisites), `leads_to` (chaining), `mitigates`.

This graph enables prerequisite checking – the brain only suggests exploits whose preconditions are met, avoiding wild goose chases.

## ⛓️ Exploit Chaining – Thinking Steps Ahead
Privilege escalation often requires multiple steps (e.g., cron hijack → user shell → kernel exploit → root). Predator’s planner uses forward chaining to build an attack tree:
- **Current state** = satisfied features (from enumeration).
- **Actions** = exploit modules (each has preconditions and effects).
- **Goal** = `root_shell = true`.

The planner finds the shortest, highest-confidence path using an A*-inspired search. The result is a ready-to-fire chain that the Auto Exploit tab can execute autonomously.

## 🔁 Self-Improvement – The Feedback Loop
Every engagement makes Predator smarter:
- After each exploit attempt, the outcome (success/failure) is logged together with the feature vector.
- The ML model is partially updated (`.partial_fit()`) – a form of online learning that gradually shifts the decision boundary.
- Thompson sampling during auto-exploitation balances exploration (trying less-known exploits) with exploitation (using proven ones).
- Manual techniques recorded from the Terminal tab can be converted into new exploit modules via an optional LLM summarizer, closing the loop between human ingenuity and automation.

## 🧪 The AI Exploiter – Your Personal Red Team Assistant
The AI Exploiter tab connects Predator to state-of-the-art language models (NVIDIA NIM, OpenAI, DeepSeek, Claude, Gemini, local Ollama).
- It feeds the full LinPEAS output + structured summary to the model.
- The AI returns a JSON list of actionable suggestions – each with confidence, required commands, and prerequisites.
- With Auto-execute enabled, Predator runs those suggestions in order, verifying root after each attempt.
- If a suggestion is a raw command, it is executed directly; if it maps to an existing exploit module, that module is invoked.

This hybrid approach combines the pattern recognition of LLMs with the reliability of a curated exploit database.

## 🧬 Neuro-Inspired Architecture at a Glance
```text
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  ENUMERATION    │────▶│   FEATURE VECTOR │────▶│   ML MODEL      │
│  (400 + PEAS)   │     │                  │     │  (confidence)   │
└─────────────────┘     └─────────────────┘     └────────┬────────┘
                                                         │
                                                         ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  KNOWLEDGE GRAPH│◀────│   PLANNER       │◀────│  EXPLOIT CHAIN  │
│  (prerequisites)│     │  (A* search)    │     │                 │
└─────────────────┘     └─────────────────┘     └────────┬────────┘
                                                         │
                                                         ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  EXPLOIT EXEC   │────▶│  VERIFICATION   │────▶│   ROOT SHELL    │
│  (module/command)│    │   (id -u)       │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                                                       ▲
        └──────────────▶  FEEDBACK (success/failure) ───────────┘
```

## 📊 Model Training & Dataset
The initial model was trained on a curated dataset of real-world privilege escalation cases (CVE exploits, misconfigurations, manual techniques).
- **Features**: Kernel version, OS type, installed packages, SUID binaries, sudo rights, writable files, cron jobs, capabilities, environment variables, and 50+ derived flags.
- **Labels**: Specific exploit names (e.g., `dirtycow`, `suid_python`, `unquoted_path`).
- **Performance**: Achieves 87% accuracy on held-out test data, with per-class F1 scores above 0.8 for the most common vectors.

Confidence scores are calibrated, and a rule-based fallback ensures usability even when the model is uncertain.

## 🛠️ Key Features
- **Multi-platform**: Linux and Windows (SSH / WinRM).
- **One-click exploitation**: From enumeration to root in a single click.
- **Auto-exploit chain**: Attempts the best path automatically.
- **AI-powered suggestions**: Leverages LLMs to find novel vectors.
- **Self-learning**: Improves with every engagement.
- **Manual technique library**: Built-in modules for common misconfigurations.
- **Gore-themed TUI**: Blood-red interface with a scary bloody bunny logo.
- **Terminal with internal commands**: `!exploit`, `!switch`, `!help` – control Predator from within the shell.

## 🧪 Example Workflow
1. Connect to the target (SSH/WinRM).
2. Run Enumeration + PEAS – gather data.
3. Switch to AI Exploiter, click Refresh, then Analyse & Suggest.
4. The AI returns a list of high-confidence vectors.
5. Enable Auto-execute – Predator runs them in order.
6. On success, you’re dropped into a root shell in the Terminal tab.
7. Every attempt is logged, and the ML model updates itself for next time.

## 🧩 Future Enhancements
- Integration with BloodHound for domain privilege escalation.
- Community intelligence sharing (opt-in) to crowd-source exploit success rates.
- Reinforcement learning from user corrections in the Terminal tab.
- Support for more LLM providers and local models via Ollama.

## 🐾 Credits
Created by [AgamSandhu-cysec](https://github.com/AgamSandhu-cysec) – because even predators need a creator.
