# 🤝 Contributing to PhishLens

Welcome to the **PhishLens** project! This repository is configured as an official **VS Code Project Workspace** (`phishlens.code-workspace`) so anyone on the team can clone, open, edit, and run the code immediately.

---

## 🚀 1. Opening the Project in VS Code

### Option A: Double-Click the Workspace File
1. Clone or download the repository to your computer.
2. Double-click the file named **`phishlens.code-workspace`**.
3. VS Code will immediately open the project with all pre-configured settings, recommended extensions, launch debuggers, and test suites ready to go.

### Option B: From within VS Code
1. Open VS Code.
2. Go to **File ➔ Open Workspace from File...**
3. Select **`phishlens.code-workspace`**.

---

## 📦 2. Environment Setup (1-Click)

### On Windows:
Double-click `setup.bat` (or run it in terminal):
```powershell
.\setup.bat
```

### On macOS / Linux:
```bash
chmod +x setup.sh
./setup.sh
```

This will automatically create a virtual environment (`.venv`), install all requirements, and run the test suite to verify your setup.

---

## 🛠️ 3. How to Edit & Extend the Project

The code is strictly modular across 4 engineering roles. Here is where to make edits:

### A. Adding or Modifying Detection Rules
- **File**: `phishlens/scoring/rules.py`
- To add a new heuristic rule (e.g., checking for specific suspicious headers or keywords):
  1. Inherit from `ForensicRule`.
  2. Implement the `evaluate(parsed_email, intel_results)` method.
  3. Add the rule instance to the `DEFAULT_RULES` array.

### B. Adding Threat Intelligence Feeds
- **Directory**: `phishlens/intel/`
- To integrate a new API (e.g., PhishTank, Shodan, GreyNoise):
  1. Create a new client class inheriting from `BaseIntelClient` in `phishlens/intel/base.py` (which provides automatic SQLite caching and rate-limiting).
  2. Implement your lookup query and call `self.normalize_verdict()`.
  3. Hook the client into `IntelManager.enrich()` in `phishlens/intel/intel_manager.py`.

### C. Modifying the Web Dashboard UI
- **Directory**: `phishlens/web/static/`
  - `index.html`: Layout, metric cards, and tab panes.
  - `style.css`: Theme colors, typography, and card designs.
  - `app.js`: Client-side JavaScript handling API calls, drag-and-drop, and dynamic rendering.

### D. Adding Sample Emails for Testing
- **Directory**: `samples/`
  - Put malicious test `.eml` files in `samples/phishing/`
  - Put clean test `.eml` files in `samples/legitimate/`
  - Run `python evaluate.py` to see how your changes impact overall precision and recall.

---

## 🧪 4. Testing Your Changes

Before committing your code, run the unit test suite:
```bash
python -m pytest
```
All tests must pass. You can add new unit tests in `tests/`.

---

## 🌿 5. Git Collaboration Workflow

1. Create a new feature branch for your edits:
   ```bash
   git checkout -b feature/my-new-rule
   ```
2. Make your edits and test them.
3. Commit your changes:
   ```bash
   git add .
   git commit -m "Add new heuristic rule for urgent wire transfer requests"
   ```
4. Push to your branch and open a Pull Request on GitHub:
   ```bash
   git push origin feature/my-new-rule
   ```
