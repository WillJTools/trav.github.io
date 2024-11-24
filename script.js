const fileInput = document.getElementById('fileInput');
const fileName = document.getElementById('fileName');
const vulnerabilitiesOutput = document.getElementById('vulnerabilitiesOutput');
const codeDisplay = document.getElementById('codeDisplay');
const removeScriptButton = document.getElementById('removeScript');

// Comprehensive regex patterns
const vulnerabilityPatterns = [
    { regex: /eval\(/g, message: 'Use of eval detected. This can lead to code injection.' },
    { regex: /innerHTML\s*=/g, message: 'Direct assignment to innerHTML detected. This can lead to XSS vulnerabilities.' },
    { regex: /password|secret|key|token/gi, message: 'Hardcoded sensitive information detected.' },
    { regex: /document\.write\(/g, message: 'Use of document.write detected. Avoid for security reasons.' },
    { regex: /new Function\(/g, message: 'Use of dynamically constructed functions detected. Potential code execution risk.' },
    { regex: /require\(.+\)/g, message: 'Dynamic require statements detected. Could be a security risk.' },
    { regex: /os\.system\(/g, message: 'Use of os.system detected in Python. Can lead to command injection.' },
    { regex: /subprocess\.Popen\(/g, message: 'Subprocess Popen used in Python. Ensure input is sanitized.' },
    { regex: /base64\.b64decode\(/g, message: 'Use of base64 decoding. Check for malicious payloads.' },
    { regex: /exec\(/g, message: 'Use of exec detected. Can lead to code injection.' },
    { regex: /importlib\.import_module\(/g, message: 'Dynamic import detected. Validate input carefully.' },
    { regex: /pickle\.load\(/g, message: 'Use of pickle.load detected. This can lead to deserialization attacks.' },
    { regex: /yaml\.load\(/g, message: 'Use of yaml.load detected. This can lead to code execution.' },
    { regex: /input\(.+\)/g, message: 'Use of input() without sanitization can be risky.' },
    { regex: /open\(.+w\)/g, message: 'Potential file overwrite risk detected with open() in write mode.' },
    { regex: /strcpy\(/g, message: 'Use of strcpy detected in C. Risk of buffer overflow.' },
    { regex: /gets\(/g, message: 'Use of gets detected in C. Risk of buffer overflow.' },
    { regex: /system\(/g, message: 'Use of system() in C/C++ detected. Validate input carefully.' },
    { regex: /rand\(\)/g, message: 'Use of rand() detected. Consider using a secure random function.' },
    { regex: /Math\.random\(\)/g, message: 'Math.random() detected. Ensure it is used securely.' },
    { regex: /console\.log\(/g, message: 'Console.log detected. Remove debug statements before production.' },
    { regex: /window\.location\s*=/g, message: 'Direct assignment to window.location detected. Risk of open redirects.' },
    { regex: /fetch\(.+\)/g, message: 'Ensure fetch() calls handle errors and validate responses.' },
    { regex: /axios\.get\(.+\)/g, message: 'Ensure axios GET requests handle responses securely.' },
    { regex: /res\.sendFile\(.+\)/g, message: 'Ensure res.sendFile in Node.js does not expose sensitive files.' },
    { regex: /child_process\.exec\(/g, message: 'Use of child_process.exec detected in Node.js. Risk of command injection.' },
    { regex: /child_process\.spawn\(/g, message: 'Ensure input to child_process.spawn is sanitized.' },
    { regex: /fs\.readFile\(/g, message: 'Ensure fs.readFile in Node.js does not read unauthorized files.' },
    { regex: /app\.get\(.+\)/g, message: 'Check Express app.get routes for input validation.' },
    { regex: /app\.post\(.+\)/g, message: 'Check Express app.post routes for input sanitization.' },
    { regex: /django\.db\.models\.F\(/g, message: 'Check Django F expressions for safe usage.' },
    { regex: /jQuery\.(get|post|ajax)\(/g, message: 'Ensure jQuery AJAX calls validate and sanitize input.' },
    { regex: /unescape\(/g, message: 'Use of unescape detected. Avoid for security reasons.' },
    { regex: /process\.env/g, message: 'Check for leaked environment variables in Node.js.' },
    { regex: /threading\.Thread\(/g, message: 'Ensure threading in Python is handled securely.' },
    { regex: /asyncio\.run\(/g, message: 'Check asyncio usage for potential deadlocks or vulnerabilities.' },
    { regex: /re\.search\(.+\)/g, message: 'Ensure regex patterns are not vulnerable to ReDoS attacks.' },
    { regex: /java\.sql\.Statement\(/g, message: 'Use of SQL Statements detected in Java. Risk of SQL injection.' },
    { regex: /PreparedStatement\.execute\(/g, message: 'Ensure prepared statements in Java are parameterized properly.' },
    { regex: /http\.get\(/g, message: 'Use of HTTP GET in Node.js. Ensure secure implementation.' },
    { regex: /http\.post\(/g, message: 'Use of HTTP POST in Node.js. Validate inputs carefully.' },
    { regex: /contenteditable/g, message: 'Contenteditable detected. Ensure user input is sanitized.' },
    { regex: /navigator\.geolocation/g, message: 'Geolocation API detected. Ensure user permissions are handled securely.' },
    { regex: /window\.opener/g, message: 'Use of window.opener detected. Risk of phishing attacks.' },
    { regex: /localStorage\./g, message: 'LocalStorage detected. Avoid storing sensitive information in LocalStorage.' },
    { regex: /sessionStorage\./g, message: 'SessionStorage detected. Ensure data is sanitized.' },
    { regex: /crypto\.randomBytes\(/g, message: 'Ensure crypto.randomBytes usage is secure.' },
    { regex: /navigator\.clipboard/g, message: 'Clipboard API detected. Handle clipboard data securely.' }
];

// Escape HTML to prevent rendering of uploaded code
function escapeHTML(html) {
    return html
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// Map severity levels to CSS classes
const severityColors = {
    high: 'high-severity',
    medium: 'medium-severity',
    low: 'low-severity',
};

// Format vulnerabilities for the vulnerabilities section
function formatVulnerabilityOutput(vulnerabilities) {
    return vulnerabilities
        .map((vuln) => {
            const severityClass = severityColors[vuln.severity]; // Map severity to CSS class
            return `
                <div class="vulnerability-item">
                    <span class="severity-indicator ${severityClass}"></span>
                    ${vuln.message} 
                    (Vulnerable code: "<code>${escapeHTML(vuln.matchText)}</code>", Line: ${vuln.line})
                </div>
            `;
        })
        .join('');
}

// Process code and return vulnerabilities and formatted lines
function processCode(content, patterns) {
    const lines = content.split('\n'); // Split the code into lines
    const vulnerabilities = []; // Capture details of all vulnerabilities
    const formattedLines = lines.map((line, lineNumber) => {
        let processedLine = escapeHTML(line); // Start with escaped content
        patterns.forEach((pattern) => {
            const matches = [...line.matchAll(pattern.regex)];
            matches.forEach((match) => {
                const matchText = match[0];
                const escapedMatchText = escapeHTML(matchText);
                const highlightSpan = `<span class="highlight-${pattern.severity}">${escapedMatchText}</span>`;

                // Replace the match in the line with the highlighted span
                processedLine = processedLine.replace(escapedMatchText, highlightSpan);

                // Store vulnerability details
                vulnerabilities.push({
                    matchText,
                    message: pattern.message,
                    severity: pattern.severity,
                    line: lineNumber + 1,
                });
            });
        });
        return processedLine; // Return the highlighted line
    });

    return { vulnerabilities, formattedLines };
}

// Reset the analyzer to its default state
function resetAnalyzer() {
    fileName.textContent = 'No file chosen';
    vulnerabilitiesOutput.textContent = 'No vulnerabilities detected.';
    codeDisplay.innerHTML = '<p>Code will appear here.</p>'; // Reset display
    removeScriptButton.hidden = true;
    fileInput.value = '';
}

// Handle file uploads
fileInput.addEventListener('change', async (event) => {
    const file = event.target.files[0];
    if (file) {
        fileName.textContent = file.name;
        removeScriptButton.hidden = false;

        // Read the file content
        const content = await file.text();

        // Process the code for vulnerabilities
        const { vulnerabilities, formattedLines } = processCode(content, vulnerabilityPatterns);

        // Render vulnerabilities with severity indicators
        if (vulnerabilities.length > 0) {
            vulnerabilitiesOutput.innerHTML = formatVulnerabilityOutput(vulnerabilities);
        } else {
            vulnerabilitiesOutput.textContent = 'No vulnerabilities detected.';
        }

        // Render the formatted code in the Code Display section
        codeDisplay.innerHTML = formattedLines
            .map((line, index) => `<div class="code-line"><span class="line-number">${index + 1}</span> ${line}</div>`)
            .join('');
    } else {
        resetAnalyzer();
    }
});

// Handle script removal
removeScriptButton.addEventListener('click', () => resetAnalyzer());
