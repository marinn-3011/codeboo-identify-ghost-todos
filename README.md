# CodeBoo

> A local code debt and TODO analyzer powered by open-weight AI models.

CodeBoo scans your source code files to surface forgotten `TODO` comments, potential memory leaks, unhandled exceptions, and security risks. Issues are categorized and ranked by severity (from routine refactors to critical memory bugs) and presented visually on a lightweight local dashboard.

---

## Features

- **Automated Technical Debt Analysis:** Recursively parses local directories or cloned GitHub repositories to extract TODO items, missing error handlers, and resource leaks.
- **Severity Classification:** Rates issues on a 1–5 urgency scale:
  - **Level 1–2 (Harmless):** Cosmetic fixes, routine TODOs, and styling tasks.
  - **Level 3–4 (Specter):** Unhandled exceptions, dead code, and inefficient loops.
  - **Level 5 (Phantom):** Critical memory leaks, unclosed resources, and security vulnerabilities.
- **Privacy-First Inference:** Runs entirely locally via Ollama. No code is transmitted to cloud APIs or external servers.
- **Low-RAM Footprint:** Engineered to run smoothly on machines with 4–6 GB of free system memory.

---

## Tech Stack

- **Inference Engine:** Ollama (`qwen2.5-coder:7b`, `gemma2:9b`, or `gemma4:2b`)
- **Backend:** Python 3.10+ (Standard Library / FastAPI)
- **Frontend:** Single-page HTML/CSS/JS with custom CSS issue visualization

---

## Quick Start

### 1. Prerequisites

Ensure [Ollama](https://ollama.ai/) is installed and running. Pull your preferred code analysis model:

```bash
ollama pull qwen2.5-coder:7b
```

### 2. Installation

Clone the repository and navigate into the project directory:

```bash
git clone https://github.com/your-username/codeboo.git
cd codeboo
```

### 3. Usage

Run the server:

```bash
python main.py
```

Open your browser and navigate to `http://localhost:8000`. Enter a local file path or repository URL to run a scan.

---

## Configuration

You can customize the model used for scanning in `config.py`:

```python
# config.py
OLLAMA_MODEL = "qwen2.5-coder:7b"  # Or "gemma2:9b", "gemma4:2b"
OLLAMA_HOST = "http://localhost:11434"
MAX_FILE_SIZE_KB = 100
```

---

## Limitations

- **Large Codebases:** Repositories with thousands of files are scanned module-by-module to keep context sizes within local memory limits.
- **Static Analysis Scope:** CodeBoo performs semantic static inspection; deep execution profiling still requires runtime profiling tools.

---

## License

Distributed under the MIT License. See `LICENSE` for details.