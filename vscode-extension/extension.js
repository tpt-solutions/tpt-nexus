// Minimal activation for the tpt-nexus VS Code extension. Wires the
// "nexus: Verify current .telos file" command to the `nexus verify` CLI.
const { commands, window } = require("vscode");

function activate(context) {
  const verify = commands.registerCommand("nexus.verify", async () => {
    const editor = window.activeTextEditor;
    if (!editor) {
      window.showErrorMessage("nexus: no open editor");
      return;
    }
    const doc = editor.document;
    if (!doc.fileName.endsWith(".telos")) {
      window.showErrorMessage("nexus: open a .telos file first");
      return;
    }
    await doc.save();
    const { exec } = require("child_process");
    exec(`nexus verify "${doc.fileName}"`, (err, stdout, stderr) => {
      const out = stdout + stderr;
      if (err) {
        window.showErrorMessage(`nexus verify failed:\n${out}`);
      } else {
        window.showInformationMessage(`nexus verify ok:\n${out}`);
      }
    });
  });
  context.subscriptions.push(verify);
}

function deactivate() {}

module.exports = { activate, deactivate };
