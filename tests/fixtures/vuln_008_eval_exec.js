// GR-BFSI-008 fixture — Dangerous eval Usage (JavaScript)
// Intentionally vulnerable. DO NOT deploy.

// Direct eval of user input — arbitrary code execution
function executeExpression(userInput) {
    return eval(userInput);
}

// Function constructor — equivalent to eval
function runDynamic(code) {
    const fn = new Function(code);
    return fn();
}

// Child process with shell=true equivalent in JS
const { exec } = require('child_process');

function runCommand(filename) {
    // shell injection via exec (shell=true by default in child_process.exec)
    exec(`convert ${filename} output.pdf`, (err, stdout) => {
        return stdout;
    });
}

module.exports = { executeExpression, runDynamic, runCommand };
