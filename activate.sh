#!/bin/bash

# activate.sh - Toggle script for RepoGuardian API key detector

echo "Do you need to use the API key detector? (y/n)"
read use_detector

# Helper function to remove python hook and update config
cleanup_existing() {
    if [ -f .git/hooks/pre-commit ]; then
        rm .git/hooks/pre-commit
    fi
    # Remove existing detector_mode lines
    sed -i '/^detector_mode:/d' .repoguardian.yml
}

if [ "$use_detector" != "y" ] && [ "$use_detector" != "Y" ]; then
    echo "Deactivating API key detector..."
    cleanup_existing
    # Ensure newline before appending
    sed -i -e '$a\' .repoguardian.yml
    echo "detector_mode: off" >> .repoguardian.yml
    echo "Done."
    exit 0
fi

echo "Should it work during saving files (1) or Git commits (2)?"
read mode

cleanup_existing

if [ "$mode" == "1" ]; then
    echo "Activating for saving files (VS Code Extension)..."
    # Ensure newline before appending
    sed -i -e '$a\' .repoguardian.yml
    echo "detector_mode: save" >> .repoguardian.yml
    echo "Done."
elif [ "$mode" == "2" ]; then
    echo "Activating for Git commits (Pre-commit Hook)..."
    # Ensure newline before appending
    sed -i -e '$a\' .repoguardian.yml
    echo "detector_mode: commit" >> .repoguardian.yml
    
    # Create the pre-commit hook
    cat << 'EOF' > .git/hooks/pre-commit
#!/bin/bash
# Pre-commit hook for RepoGuardian API Key Detector
echo "[RepoGuardian] Running API Key Detector on staged files..."

# Find python executable
if [ -f "venv/bin/python" ]; then
    PYTHON="venv/bin/python"
else
    PYTHON="python3"
fi

$PYTHON scanner.py --staged
if [ $? -ne 0 ]; then
    echo "[RepoGuardian] Commit blocked due to detected secrets!"
    exit 1
fi
EOF
    chmod +x .git/hooks/pre-commit
    echo "Done."
else
    echo "Invalid option. Exiting."
    exit 1
fi
