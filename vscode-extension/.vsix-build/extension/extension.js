const vscode = require('vscode');
const child_process = require('child_process');
const path = require('path');
const fs = require('fs');

const diagnosticCollection = vscode.languages.createDiagnosticCollection('repoguardian');

/**
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
    console.log('RepoGuardian extension activated.');

    // Create a decoration type with a prominent background color (e.g., bright red with some transparency)
    const secretDecorationType = vscode.window.createTextEditorDecorationType({
        backgroundColor: 'rgba(255, 0, 0, 0.4)',
        isWholeLine: false,
        border: '1px solid rgba(255, 0, 0, 0.8)',
        borderRadius: '2px'
    });

    // Scan on save
    let saveDisposable = vscode.workspace.onDidSaveTextDocument((document) => {
        scanFile(document, secretDecorationType);
    });

    // Command for manual scan
    let commandDisposable = vscode.commands.registerCommand('repoguardian.scan', () => {
        const editor = vscode.window.activeTextEditor;
        if (editor) {
            scanFile(editor.document, secretDecorationType);
        }
    });

    context.subscriptions.push(saveDisposable);
    context.subscriptions.push(commandDisposable);
    context.subscriptions.push(diagnosticCollection);
}

function scanFile(document, decorationType) {
    if (document.uri.scheme !== 'file') {
        return;
    }

    const filePath = document.uri.fsPath;
    const workspaceFolder = vscode.workspace.getWorkspaceFolder(document.uri);

    // We assume the scanner.py is in the workspace root
    let cwd = process.cwd();
    if (workspaceFolder) {
        cwd = workspaceFolder.uri.fsPath;
    }

    const scannerScript = path.join(cwd, 'scanner.py');
    if (!fs.existsSync(scannerScript)) {
        return; // No scanner configured in this repo
    }

    const configPath = path.join(cwd, '.repoguardian.yml');
    let detectorMode = 'save'; // default to save if not specified
    if (fs.existsSync(configPath)) {
        const content = fs.readFileSync(configPath, 'utf8');
        const match = content.match(/^detector_mode:\s*(.+)$/m);
        if (match) {
            detectorMode = match[1].trim();
        }
    }

    // Normalize config value so both textual and numeric mode selections work.
    const normalizedMode = detectorMode
        .replace(/\s+#.*$/, '')
        .replace(/^["']|["']$/g, '')
        .trim()
        .toLowerCase();
    const saveModeValues = new Set(['1', 'save']);

    // Only run on save if detector mode maps to save behavior.
    if (!saveModeValues.has(normalizedMode)) {
        return;
    }

    // Path to the python executable in the venv if exists, else global python
    const venvPythonPathLinux = path.join(cwd, 'venv', 'bin', 'python');
    let pythonExec = 'python3';

    if (fs.existsSync(venvPythonPathLinux)) {
        pythonExec = venvPythonPathLinux;
    }

    child_process.exec(`"${pythonExec}" "${scannerScript}" "${filePath}"`, { cwd }, (error, stdout, stderr) => {
        diagnosticCollection.delete(document.uri); // clear previous diagnostics
        const editor = vscode.window.activeTextEditor;
        if (editor && editor.document.uri.toString() === document.uri.toString() && decorationType) {
            editor.setDecorations(decorationType, []); // clear previous highlights
        }

        // exit code 1 means secrets found, based on scanner.py module design
        if (error && error.code === 1) {
            const diagnostics = [];
            const decorationRanges = [];
            const output = stdout.toString() + stderr.toString();
            const lines = output.split('\n');

            for (const rawLine of lines) {
                // Strip ANSI escape codes that scanner.py might output via colorama
                const line = rawLine.replace(/\x1b\[[0-9;]*m/g, '');

                // Example format from scanner.py:
                //   - bad.py:3 [regex] -> secret_key = 'AKIA...'
                const match = line.match(/^\s*-\s*(.*?):(\d+|\?)\s*\[(.*?)\]\s*->\s*(.*)$/);
                if (match) {
                    const lineStr = match[2];
                    const lineNumber = lineStr === '?' ? 0 : Math.max(0, parseInt(lineStr, 10) - 1);
                    const type = match[3];
                    const snippet = match[4];

                    let range;
                    if (lineNumber < document.lineCount) {
                        range = new vscode.Range(lineNumber, 0, lineNumber, document.lineAt(lineNumber).text.length);
                    } else {
                        range = new vscode.Range(0, 0, 0, 0);
                    }

                    const message = `[RepoGuardian] Secret detected (${type}): ${snippet}`;

                    const diagnostic = new vscode.Diagnostic(
                        range,
                        message,
                        vscode.DiagnosticSeverity.Error
                    );
                    diagnostic.source = 'RepoGuardian';
                    diagnostics.push(diagnostic);
                    decorationRanges.push(range);
                }
            }
            if (diagnostics.length > 0) {
                diagnosticCollection.set(document.uri, diagnostics);
                if (editor && editor.document.uri.toString() === document.uri.toString() && decorationType) {
                    editor.setDecorations(decorationType, decorationRanges);
                }
                vscode.window.showErrorMessage(`RepoGuardian: ${diagnostics.length} secret(s) detected!`);
            } else {
                vscode.window.showErrorMessage(`RepoGuardian detected secrets, but couldn't parse the locations. Please check the terminal or scanner.py manually.`);
            }
        }
    });
}

function deactivate() {
    diagnosticCollection.clear();
}

module.exports = {
    activate,
    deactivate
};
