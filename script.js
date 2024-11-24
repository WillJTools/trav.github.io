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
    { regex: /\bdebugger\b/g, message: 'Debugger statement detected. Remove for production code.' },
    { regex: /catch\s*\(\s*\)\s*\{/g, message: 'Empty catch block detected. Log or handle errors properly.' },
    { regex: /jwt\.sign\(.*\{\s*expiresIn:\s*['"]?\d+['"]?\s*\}/g, message: 'JWT without a secure expiration time detected.' },
    { regex: /Object\.assign\(\s*\{\},\s*\.\.\./g, message: 'Improper use of Object.assign spreading detected. Check immutability.' },
    { regex: /crypto\.createHash\(['"](md5|sha1)['"]\)/g, message: 'Use of weak hash algorithm (MD5/SHA1) detected. Use stronger alternatives like SHA256.' },
    { regex: /<iframe.*srcdoc=.*>/gi, message: 'Use of srcdoc in iframe detected. Risk of XSS.' },
    { regex: /let\s*\w+\s*=\s*undefined;/g, message: 'Explicit assignment to undefined detected. Avoid unnecessary assignments.' },
    { regex: /[^_a-zA-Z0-9]\$http\.(get|post|put|delete)/g, message: 'AngularJS $http detected. Validate input and ensure proper sanitization.' },
    { regex: /[^a-zA-Z]\$\(/g, message: 'Potential jQuery injection point detected. Avoid dynamic selectors.' },
    { regex: /java\.util\.regex\.Pattern/g, message: 'Ensure Java regex patterns are not vulnerable to ReDoS attacks.' },
    { regex: /\bselect\s+\*\s+from\s+/gi, message: 'Use of SELECT * in SQL queries detected. Retrieve only necessary fields.' },
    { regex: /exec\(.*\)/gi, message: 'Dynamic exec usage detected. Validate or sanitize inputs.' },
    { regex: /\.\.\.args/g, message: 'Improper use of spread operator detected. Ensure arguments are sanitized.' },
    { regex: /\bres\.redirect\(.*\)/g, message: 'Unvalidated redirects detected in Express.js. Validate all user input.' },
    { regex: /java\.util\.Random/g, message: 'Use of insecure random generator in Java detected. Use SecureRandom instead.' },
    { regex: /<script\b[^>]*>[^]*<\/script>/gi, message: 'Inline script detected. Consider using external scripts for better security.' },
    { regex: /xhr\.open\(['"](GET|POST)['"],/g, message: 'XMLHttpRequest detected. Validate and sanitize all user input.' },
    { regex: /JSON\.parse\(/g, message: 'Ensure JSON.parse inputs are validated.' },
    { regex: /\bPromise\.all\(/g, message: 'Improper handling of Promise.all detected. Ensure errors are caught.' },
    { regex: /password_verify\(/g, message: 'Ensure password_verify is used with properly hashed passwords in PHP.' },
    { regex: /\bDate\.now\(\)/g, message: 'Use of Date.now detected. Ensure proper synchronization for time-sensitive operations.' },
    { regex: /\bnull\s*==\s*\w+/g, message: 'Null comparison detected. Use strict equality checks (===).' },
    { regex: /\btry\s*\{\s*\}/g, message: 'Empty try block detected. Ensure exceptions are properly handled.' },
    { regex: /\sdelete\s\w+\[.+\]/g, message: 'Dynamic property deletion detected. Ensure objects are immutable where possible.' },
    { regex: /user\s*=\s*request\.GET/g, message: 'Use of raw GET parameter assignment detected. Ensure data is sanitized in Python Django.' },
    { regex: /document\.cookie/g, message: 'Direct access to document.cookie detected. Use HTTPOnly flags for sensitive cookies.' },
    { regex: /window\.name/g, message: 'Use of window.name detected. Avoid for sensitive data storage.' },
    { regex: /window\.history\.pushState/g, message: 'Improper use of pushState detected. Validate all URL changes.' },
    { regex: /<style\b[^>]*>[^]*<\/style>/gi, message: 'Inline CSS detected. Use external stylesheets for maintainability and security.' },
    { regex: /hmac\s*=\s*hashlib\.md5/g, message: 'Use of HMAC with MD5 detected in Python. Use SHA256 or stronger.' },
    { regex: /import\s+\*+.+/g, message: 'Wildcard imports detected in Python. Import specific modules for better clarity.' },
    { regex: /[^a-zA-Z]System\.exit\(/g, message: 'Direct use of System.exit detected in Java. Ensure proper shutdown handling.' },
    { regex: /\/\*.+\*\//g, message: 'Overly complex comments detected. Simplify inline documentation.' },
    { regex: /\blog4j:.*Log4j2\b/g, message: 'Log4j usage detected. Check for Log4Shell vulnerability patches.' },
    { regex: /#[a-fA-F0-9]{6}/g, message: 'Hardcoded hex colors detected. Use CSS variables for theming.' },
    { regex: /input\[type=['"]password['"]\]/g, message: 'Unprotected password fields detected. Ensure secure transmission.' },
    { regex: /process\.on\(['"]uncaughtException['"],/g, message: 'Uncaught exceptions handler detected. Ensure proper error logging.' },
    { regex: /bcrypt\.hashSync\(.+\)/g, message: 'Ensure bcrypt is properly salted for password hashing.' },
    { regex: /async function\s+\w+\s*\([^)]*\)\s*\{\}/g, message: 'Empty async function detected. Ensure implementation is completed.' },
    { regex: /XMLHttpRequest\(/g, message: 'Use of XMLHttpRequest detected. Prefer modern Fetch API.' },
    { regex: /const\s+\w+\s*=\s*require\(.+\)/g, message: 'Dynamic require detected. Validate dependencies in Node.js.' },
    { regex: /console\.error\(/g, message: 'Console.error detected. Ensure error details are not exposed to users.' },
    { regex: /\bThrowable\b/g, message: 'Generic throwable handling detected in Java. Use specific exceptions.' },
    { regex: /java\.nio\.file\.(Paths|Files)/g, message: 'Ensure Java NIO files are accessed securely to avoid traversal attacks.' },
    { regex: /\bhttp:\/\/\S+/g, message: 'Unencrypted HTTP URL detected. Prefer HTTPS.' },
    { regex: /\bSELECT\s+\w+\s+FROM\s+\w+\s+WHERE\s+1\s+=\s+1\b/gi, message: 'SQL tautology detected. Ensure input is parameterized.' },
    { regex: /<meta\s+http-equiv=['"]refresh['"]/g, message: 'Meta refresh tag detected. Avoid automatic redirects.' },
    { regex: /\bprintf\(/g, message: 'Improper printf usage detected. Ensure format strings are validated in C/C++.' },
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

// Escape HTML
function escapeHTML(content) {
  return content
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Analyze Code
function analyzeCode(content) {
  const lines = content.split('\n');
  const vulnerabilities = [];
  const highlightedLines = lines.map((line, lineNumber) => {
    let processedLine = escapeHTML(line);
    vulnerabilityPatterns.forEach((pattern) => {
      const matches = [...line.matchAll(pattern.regex)];
      matches.forEach((match) => {
        vulnerabilities.push({
          message: pattern.message,
          severity: pattern.severity,
          line: lineNumber + 1,
          match: match[0],
        });
        processedLine = processedLine.replace(
          match[0],
          `<span class="highlight-${pattern.severity}">${match[0]}</span>`
        );
      });
    });
    return `<span class="line-number">${lineNumber + 1}</span>${processedLine}`;
  });
  return { vulnerabilities, highlightedLines };
}

// Render Vulnerabilities
function renderVulnerabilities(vulnerabilities) {
  vulnerabilitiesOutput.innerHTML = vulnerabilities
    .map(
      (vuln) =>
        `<p><span class="severity-indicator ${vuln.severity}"></span> ${vuln.message} (Line: ${vuln.line})</p>`
    )
    .join('');
}

// Render Code
function renderCode(lines) {
  codeDisplay.innerHTML = lines.join('<br>');
}

// Reset UI
function resetUI() {
  fileName.textContent = 'No file chosen';
  vulnerabilitiesOutput.innerHTML = '<p>No vulnerabilities detected.</p>';
  codeDisplay.innerHTML = '<p>Code will appear here.</p>';
  removeScriptButton.hidden = true;
}

// Handle File Upload
fileInput.addEventListener('change', async (event) => {
  const file = event.target.files[0];
  if (file) {
    fileName.textContent = file.name;
    const content = await file.text();
    const { vulnerabilities, highlightedLines } = analyzeCode(content);
    renderVulnerabilities(vulnerabilities);
    renderCode(highlightedLines);
    removeScriptButton.hidden = false;
  }
});

// Handle Reset
removeScriptButton.addEventListener('click', resetUI);
