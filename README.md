# CodeBoo

Paste a public GitHub link or a folder on your computer. CodeBoo looks through the code for forgotten promises, risky spots and quiet failures, ranks them by urgency, and shows each one as a ghost. Small problems are cute little wisps. Serious ones are tall, glowing and a bit scary. A model running on your own machine explains the most urgent ones in everyday words.

Built for the DEV Hacktoberfest 2026 "Ghost in the Machine" challenge, with open-weight models doing the explaining.

## What it finds

| Ghost | What it means | Examples |
| --- | --- | --- |
| Leaked secret | Keys or passwords typed into the code | Private keys, cloud and GitHub tokens, hard-coded passwords |
| Risky code | Code that could be tricked into doing something harmful | Running text as code, shell commands, unsafe loading of saved data, database questions built by gluing text |
| Weak spot | Settings that make an app easier to attack | Switched-off certificate checks, old hash methods, debug mode, open permissions |
| Possible leak | Resources that may never be released | Files never closed, timers never stopped, memory never freed |
| Quiet failure | Errors that are caught and hidden | Empty catch blocks, bare `except:` |
| Forgotten promise | Notes-to-self nobody came back to | `TODO`, `FIXME`, `HACK`, `XXX`, `BUG` comments |

Each ghost has one of five levels: Wisp, Little ghost, Haunting, Specter and Phantom, from "tidy up whenever" to "fix today".

## How it works

1. **Fetch.** For a GitHub link, the app downloads the repository's zip archive (no git needed) into a temporary folder and deletes it afterwards. For a folder path, it reads the folder in place.
2. **Scan.** About 20 plain, readable rules (see `hunt.py`) look through the code files. Test, example and documentation folders get a lower urgency, and obvious placeholders such as `changeme` are ignored.
3. **Rank.** Findings are ranked by urgency, and the ghosts appear right away.
4. **Explain.** The most urgent 24 ghosts are sent, a few at a time, to a local model through Ollama. The model sees only a short code excerpt (secret values hidden) and writes a plain-English explanation and a fix. It can also say a finding looks harmless, which lowers its urgency. The model can move a ghost's urgency only a little, so one bad answer can't bury a real problem. When all explanations are in, the list is ranked again.

If Ollama isn't running, you still get every ghost with a built-in explanation. Only the model-written wording is missing.

## Requirements

- Python 3.8 or newer. There is nothing to install with pip.
- [Ollama](https://ollama.com) with a model pulled, for the plain-English explanations (optional but recommended).
- An internet connection, only when fetching from GitHub.

## Run it

1. Pull a model with its full tag: `ollama pull gemma4:e4b`
2. From this folder: `python3 hunt.py` (on Windows, `python hunt.py`)
3. Open http://127.0.0.1:8766

To use a different model, set `HUNT_MODEL`:
- macOS or Linux: `HUNT_MODEL=qwen3.5:4b python3 hunt.py`
- Windows (PowerShell): `$env:HUNT_MODEL="qwen3.5:4b"; python hunt.py`

## Settings

All are optional environment variables.

| Variable | Default | What it does |
| --- | --- | --- |
| `HUNT_MODEL` | `gemma4:e4b` | The Ollama model that writes the explanations |
| `OLLAMA_URL` | `http://localhost:11434` | Where Ollama is running |
| `PORT` | `8766` | Port for the page |
| `ARCHIVE_URL` | GitHub's archive address | Advanced: where repository zips are fetched from |

## Limits

- This is a quick look with simple rules, not a security audit. Some ghosts are false alarms, and real problems can hide from a scan like this.
- Leak detection is a rough guess based on patterns, for example a file opened with no close anywhere in the same file.
- The model judges a short excerpt, not the whole project, so it often says "hard to tell".
- Only public GitHub repositories work. Private repositories need a folder on your computer instead.
- Use the repository link, or a branch link such as `https://github.com/owner/repo/tree/main`. Links to a sub-folder of a repository aren't supported.
- Limits keep a hunt quick: up to 800 files of 300 KB or less, 60 ghosts shown, and the 24 most urgent explained.
- It does not show how old a note-to-self is, because a downloaded archive has no history.

## Privacy

- The server listens on localhost only and never logs paths or code.
- Code is scanned on your computer, and the model runs on your computer. The only network use is downloading a GitHub archive when you ask for one.
- Secret values are hidden in everything shown on the page and everything sent to the model.
