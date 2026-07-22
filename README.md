# RepoGuardian

RepoGuardian is a lightweight secret-scanning tool for Python, JavaScript, environment files, and related config files. It helps detect common API keys, tokens, and credential-like strings before they are committed or shared.

## Project files

- scanner.py — main scanner entry point
- activate.sh — enables or disables the detector in commit/save mode
- .repoguardian.yml — optional scanner configuration
- vscode-extension/ — VS Code integration
- evidence/ — generated evidence bundles and JSON reports

## Reconstruct the virtual environment

The repository already includes a virtual environment folder named venv. If it is missing or you want to recreate it from scratch, use the steps below.

### Option 1: Reuse the existing environment

If the venv folder already exists, activate it:

```bash
source venv/bin/activate
```

### Option 2: Recreate the environment

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
python -m pip install GitPython PyYAML colorama
```

### Verified dependencies

The current environment includes:

- GitPython
- PyYAML
- colorama

## How to use the project

### 1. Run the scanner on files

```bash
source venv/bin/activate
python scanner.py <file1> <file2>
```

Example:

```bash
python scanner.py hello.js demo.py
```

### 2. Scan tracked files in the repository

```bash
python scanner.py
```

### 3. Scan staged changes before committing

```bash
python scanner.py --staged
```

### 4. Enable the commit hook

Run the helper script:

```bash
bash activate.sh
```

When prompted:

- choose y to enable detection
- choose 2 to activate it for Git commits

This creates a Git pre-commit hook so the scanner runs automatically before a commit.

## Configuration

You can customize scanning behavior with .repoguardian.yml. Common options include:

- allowlist_patterns
- scan_file_extensions
- block_file_extensions
- min_entropy
- ignore_paths

## Evidence output

When findings are detected, the scanner writes evidence files into the evidence/ directory. These contain metadata and a digest for review.

## Notes

- The detector ignores common folders such as venv, .git, node_modules, build, and dist.
- The scanner is intended as a guardrail for detecting likely secrets, not as a perfect security scanner.
