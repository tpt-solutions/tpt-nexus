# tpt-nexus VS Code extension

Syntax highlighting for `.telos` intent files plus a `nexus: Verify current
.telos file` command that runs `nexus verify` on the active file.

## Layout

- `package.json` — language + grammar + command contributions.
- `syntaxes/telos.tmLanguage.json` — a small TextMate grammar.
- `language-configuration.json` — bracket/comment config.
- `extension.js` — activates the verify command (requires `nexus` on `PATH`).

## Install (from source)

```text
cd vscode-extension
npm install
code --install-extension .
```

Or open this folder in VS Code and press F5 to launch an Extension Development
Host. The verify command appears in the editor title bar when a `.telos` file is
open, and also via the Command Palette (`nexus: Verify current .telos file`).

> Requires the `nexus` CLI on your `PATH` (build it with
> `cargo build -p tpt-nexus-cli` and add `target/debug` to `PATH`).
