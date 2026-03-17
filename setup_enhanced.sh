#!/usr/bin/env bash
#
# Predator Enhanced Edition - Setup & Verification Script
# Run this after enhancements to verify everything is working
#

set -e

echo "╔══════════════════════════════════════════════════════╗"
echo "║   PREDATOR ENHANCED EDITION - Setup Script          ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Check Python version
echo -e "${CYAN}[*] Checking Python version...${NC}"
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 8 ]); then
    echo -e "${RED}[-] Python 3.8+ required. Found: $PYTHON_VERSION${NC}"
    exit 1
else
    echo -e "${GREEN}[+] Python $PYTHON_VERSION detected${NC}"
fi

# Check if we're in the right directory
if [ ! -f "predator.py" ]; then
    echo -e "${RED}[-] Error: predator.py not found. Run this script from the Predator root directory.${NC}"
    exit 1
fi

# Install/upgrade dependencies
echo ""
echo -e "${CYAN}[*] Checking Python dependencies...${NC}"
if [ -f "requirements.txt" ]; then
    # Check if venv exists
    if [ -d "venv" ]; then
        echo -e "${GREEN}[+] Using existing virtual environment${NC}"
        source venv/bin/activate
    else
        echo -e "${YELLOW}[!] No virtual environment found. Skipping pip install.${NC}"
        echo -e "${YELLOW}    Run manually: python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt${NC}"
    fi
else
    echo -e "${YELLOW}[!] Warning: requirements.txt not found${NC}"
fi

# Create necessary directories
echo ""
echo -e "${CYAN}[*] Creating directory structure...${NC}"
mkdir -p exploits/linux/bin
mkdir -p exploits/windows/bin
mkdir -p ml/models
mkdir -p ~/.predator/exploits
echo -e "${GREEN}[+] Directories created${NC}"

# Verify new files exist
echo ""
echo -e "${CYAN}[*] Verifying enhanced files...${NC}"

check_file() {
    if [ -f "$1" ]; then
        echo -e "${GREEN}  [+] $1${NC}"
        return 0
    else
        echo -e "${RED}  [-] MISSING: $1${NC}"
        return 1
    fi
}

MISSING=0

# Check new exploit modules
check_file "exploits/linux/pkexec_pwnkit.py" || MISSING=$((MISSING+1))
check_file "exploits/linux/sudo_baron_samedit.py" || MISSING=$((MISSING+1))
check_file "exploits/linux/suid_bash.py" || MISSING=$((MISSING+1))
check_file "exploits/windows/printspoofer.py" || MISSING=$((MISSING+1))

# Check enhancement modules
check_file "ml/enhanced_predictor.py" || MISSING=$((MISSING+1))
check_file "exploit_validator.py" || MISSING=$((MISSING+1))
check_file "parallel_executor.py" || MISSING=$((MISSING+1))

# Check documentation
check_file "README_ENHANCED.md" || MISSING=$((MISSING+1))
check_file "ENHANCEMENTS_SUMMARY.md" || MISSING=$((MISSING+1))

if [ $MISSING -gt 0 ]; then
    echo ""
    echo -e "${RED}[!] $MISSING file(s) missing. Enhancement may be incomplete.${NC}"
    echo -e "${YELLOW}[!] Please ensure all files were created properly.${NC}"
fi

# Check config.yaml has enhanced settings
echo ""
echo -e "${CYAN}[*] Checking config.yaml enhancements...${NC}"
if grep -q "parallel_exploits" config.yaml; then
    echo -e "${GREEN}  [+] Enhanced execution settings found${NC}"
else
    echo -e "${YELLOW}  [!] Warning: config.yaml may not have enhanced settings${NC}"
fi

if grep -q "auto_download" config.yaml; then
    echo -e "${GREEN}  [+] Auto-download configuration found${NC}"
else
    echo -e "${YELLOW}  [!] Warning: Auto-download settings missing${NC}"
fi

# Check LHOST configuration
echo ""
echo -e "${CYAN}[*] Checking LHOST configuration...${NC}"
LHOST=$(grep "lhost:" config.yaml | awk '{print $2}' | tr -d "'\"")
if [ -z "$LHOST" ] || [ "$LHOST" == "''" ]; then
    echo -e "${YELLOW}  [!] WARNING: LHOST not configured in config.yaml${NC}"
    echo -e "${YELLOW}      Reverse shell exploits will fail!${NC}"
    echo -e "${YELLOW}      Edit config.yaml and set: listener.lhost: 'YOUR_IP'${NC}"
else
    echo -e "${GREEN}  [+] LHOST configured: $LHOST${NC}"
fi

# Test import of new modules
echo ""
echo -e "${CYAN}[*] Testing Python module imports...${NC}"

python3 << 'EOF'
import sys
failed = []

try:
    from ml.enhanced_predictor import EnhancedExploitPredictor
    print("  [+] ml.enhanced_predictor")
except Exception as e:
    print(f"  [-] ml.enhanced_predictor: {e}")
    failed.append("enhanced_predictor")

try:
    from exploit_validator import ExploitValidator
    print("  [+] exploit_validator")
except Exception as e:
    print(f"  [-] exploit_validator: {e}")
    failed.append("exploit_validator")

try:
    from parallel_executor import ParallelExploitExecutor
    print("  [+] parallel_executor")
except Exception as e:
    print(f"  [-] parallel_executor: {e}")
    failed.append("parallel_executor")

try:
    from exploits.linux import pkexec_pwnkit, sudo_baron_samedit, suid_bash
    print("  [+] New Linux exploits")
except Exception as e:
    print(f"  [-] New Linux exploits: {e}")
    failed.append("linux_exploits")

try:
    from exploits.windows import printspoofer
    print("  [+] New Windows exploits")
except Exception as e:
    print(f"  [-] New Windows exploits: {e}")
    failed.append("windows_exploits")

if failed:
    print(f"\n[-] {len(failed)} module(s) failed to import!")
    sys.exit(1)
EOF

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+] All Python modules imported successfully${NC}"
else
    echo -e "${RED}[-] Some Python modules failed to import${NC}"
    echo -e "${YELLOW}[!] Check error messages above${NC}"
fi

# Summary
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║              SETUP VERIFICATION COMPLETE             ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

if [ $MISSING -eq 0 ]; then
    echo -e "${GREEN}✅ All enhancement files present${NC}"
    echo -e "${GREEN}✅ Python modules working${NC}"
    echo -e "${GREEN}✅ Configuration enhanced${NC}"
    echo ""
    echo -e "${CYAN}🚀 Predator Enhanced Edition is ready!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Configure LHOST in config.yaml (if not already done)"
    echo "  2. Run: python3 predator.py"
    echo "  3. Review README_ENHANCED.md for usage guide"
    echo ""
    echo -e "${YELLOW}Optional: Install searchsploit for more exploits${NC}"
    echo "  sudo apt update && sudo apt install exploitdb"
else
    echo -e "${YELLOW}⚠️  Setup complete with warnings${NC}"
    echo "  Please review messages above and fix any missing files."
fi

echo ""
echo -e "${CYAN}═════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}         'In the jungle, only Predator survives.'${NC}"
echo -e "${CYAN}═════════════════════════════════════════════════════${NC}"
echo ""
