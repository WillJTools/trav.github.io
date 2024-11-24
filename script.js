const fileInput = document.getElementById('fileInput');
const fileName = document.getElementById('fileName');
const vulnerabilitiesOutput = document.getElementById('vulnerabilitiesOutput');
const codeDisplay = document.getElementById('codeDisplay');
const removeScriptButton = document.getElementById('removeScript');

const vulnerabilityPatterns = [
    // Previously provided patterns...

    { regex: /navigator\.permissions/g, message: 'Exploit browser permissions to gain unauthorized access to user data.' },
    { regex: /deepClone/g, message: 'Exploit deep cloning to introduce prototype pollution.' },
    { regex: /parse\(\s*window\.location\.search/g, message: 'Inject malicious payloads into URL query parameters for XSS or injections.' },
    { regex: /res\.setHeader\(.+['"]Set-Cookie['"]/g, message: 'Manipulate cookie headers to bypass secure flags or inject scripts.' },
    { regex: /DOMParser\(\)/g, message: 'Inject malicious HTML or XML into DOMParser to execute scripts or access data.' },
    { regex: /new Worker\(.+\)/g, message: 'Abuse Web Workers to execute untrusted scripts or exfiltrate sensitive data.' },
    { regex: /window\.frames\[\d+\]/g, message: 'Inject scripts or steal data by manipulating window frames.' },
    { regex: /:hover\s*\{.*cursor\s*:\s*pointer.*}/g, message: 'Craft clickable elements to spoof UI and trick users into unintended actions.' },
    { regex: /if\s*\(\s*window\s*\.\s*top\s*!=\s*window\s*\)/g, message: 'Bypass frame-busting logic to execute malicious scripts in iframes.' },
    { regex: /headers\.append/g, message: 'Inject malicious headers into requests for unauthorized actions or data leakage.' },
    { regex: /res\.status\(\d+\)\.end/g, message: 'Exploit poorly handled HTTP responses to reveal server-side information.' },
    { regex: /context\.drawImage/g, message: 'Steal sensitive information by manipulating canvas rendering.' },
    { regex: /navigator\.maxTouchPoints/g, message: 'Fingerprint users by exploiting touch point enumeration.' },
    { regex: /process\.exit\(\)/g, message: 'Exploit unhandled termination logic to disrupt application flow.' },
    { regex: /sessionStorage\.setItem/g, message: 'Abuse sessionStorage to store and retrieve sensitive data insecurely.' },
    { regex: /Object\.hasOwnProperty/g, message: 'Inject payloads into prototype chains to bypass security checks.' },
    { regex: /unhandledRejection/g, message: 'Exploit unhandled promise rejections to crash applications or leak data.' },
    { regex: /catch\s*\(err\)\s*{\s*}/g, message: 'Exploit empty catch blocks to mask critical errors or bypass logging.' },
    { regex: /fetch\s*\(.+,\s*{\s*method:\s*['"](DELETE|PUT)['"]/gi, message: 'Abuse insecure HTTP methods to delete or modify resources.' },
    { regex: /crossorigin\s*=\s*"anonymous"/gi, message: 'Exploit anonymous cross-origin requests to exfiltrate data.' },
    { regex: /formData\.append\s*\(.+\)/g, message: 'Inject malicious data into FormData objects to manipulate form submissions.' },
    { regex: /JSON\.stringify\s*\(.+\)/g, message: 'Craft payloads to leak sensitive data serialized in JSON responses.' },
    { regex: /document\.referrer/g, message: 'Exploit referrer data to gain insights into user navigation paths.' },
    { regex: /document\.write\s*\(.+\)/g, message: 'Inject scripts or malicious content directly into the DOM using document.write.' },
    { regex: /window\.addEventListener\s*\(\s*"error",/g, message: 'Hijack global error handlers to suppress logs or redirect flow.' },
    { regex: /element\.src\s*=\s*".*"/g, message: 'Inject malicious URLs into element.src to trigger unauthorized network requests.' },
    { regex: /navigator\.clipboard\.writeText/g, message: 'Exploit clipboard access to overwrite user clipboard data with malicious content.' },
    { regex: /appendChild\s*\(.*\)/g, message: 'Insert malicious nodes into the DOM using appendChild.' },
    { regex: /replaceChild\s*\(.*\)/g, message: 'Replace legitimate nodes with malicious ones using replaceChild.' },
    { regex: /console\.log\(/g, message: 'Exploit exposed debug information to gather sensitive data.' },
    { regex: /os\.path\.join\s*\(.+\)/g, message: 'Abuse unsanitized paths in os.path.join to access restricted files.' },
    { regex: /eval\(/g, message: 'Exploit by injecting malicious JavaScript into eval.' },
    { regex: /innerHTML\s*=/g, message: 'Attack by injecting unescaped HTML to execute XSS.' },
    { regex: /password|secret|key|token/gi, message: 'Exploit by retrieving hardcoded sensitive information.' },
    { regex: /document\.write\(/g, message: 'Inject scripts directly into the document to execute XSS.' },
    { regex: /new Function\(/g, message: 'Exploit by passing malicious arguments to dynamically created functions.' },
    { regex: /require\(.+\)/g, message: 'Exploit by loading malicious modules through dynamic require paths.' },
    { regex: /os\.system\(/g, message: 'Attack by executing arbitrary OS commands through os.system.' },
    { regex: /subprocess\.Popen\(/g, message: 'Inject unsanitized input into subprocess commands for arbitrary command execution.' },
    { regex: /base64\.b64decode\(/g, message: 'Exploit by hiding malicious payloads in base64-encoded data.' },
    { regex: /exec\(/g, message: 'Inject commands through unsanitized input to exec for code execution.' },
    { regex: /importlib\.import_module\(/g, message: 'Load untrusted modules dynamically to execute arbitrary code.' },
    { regex: /pickle\.load\(/g, message: 'Exploit deserialization vulnerabilities by injecting malicious payloads into pickle data.' },
    { regex: /unescaped\s*user\s*input/g, message: 'Inject unescaped user input to exploit XSS or injection vulnerabilities.' },
    { regex: /crypto\.createCipheriv\(.+['"]ecb['"]/g, message: 'Exploit weak encryption modes (ECB) to decrypt sensitive data.' },
    { regex: /\.env\s*=\s*.+/g, message: 'Extract environment variables to reveal sensitive information.' },
    { regex: /res\.send\(\s*JSON\.stringify\(.+\)/g, message: 'Exploit by injecting malicious data into JSON responses.' },
    { regex: /jwt\.sign\(.+,\s*['"].{0,16}['"]/g, message: 'Exploit weak JWT secret keys to forge tokens.' },
    { regex: /navigator\.permissions/g, message: 'Abuse navigator permissions to access sensitive user data.' },
    { regex: /execSync\(.+\)/g, message: 'Inject commands into execSync to execute malicious code synchronously.' },
    { regex: /deepClone/g, message: 'Exploit by crafting objects to achieve prototype pollution.' },
    { regex: /JSON\.parse\(.+\)/g, message: 'Inject unsanitized data into JSON.parse to exploit prototype pollution.' },
    { regex: /parse\(\s*window\.location\.search/g, message: 'Inject malicious query parameters to achieve XSS or injection attacks.' },
    { regex: /http\.Agent\({\s*keepAlive:\s*true/g, message: 'Abuse persistent connections to maintain unauthorized access.' },
    { regex: /res\.setHeader\(.+['"]Set-Cookie['"]/g, message: 'Manipulate Set-Cookie headers to bypass security policies.' },
    { regex: /api\.fetch\(.+\)/g, message: 'Exploit insecure API fetch calls to exfiltrate sensitive data.' },
    { regex: /context\.strokeText/g, message: 'Craft payloads to leak sensitive data through canvas rendering.' },
    { regex: /\.filter\(\s*.+=>.+\.length\s*[><]=?\s*1/g, message: 'Abuse array length filtering to manipulate results for unauthorized access.' },
    { regex: /Content-Security-Policy/g, message: 'Bypass weak Content-Security-Policy headers to execute XSS.' },
    { regex: /res\.json\(\s*require\(/g, message: 'Exploit dynamic JSON responses to inject malicious file paths.' },
    { regex: /path\.basename\(/g, message: 'Abuse dynamic file paths to perform directory traversal.' },
    { regex: /session_start\(/gi, message: 'Hijack insecure PHP sessions to impersonate users.' },
    { regex: /sqlite3_exec\(.+\)/g, message: 'Inject unsanitized SQL commands into sqlite3_exec to achieve SQL injection.' },
    { regex: /cluster\.fork\(\)/g, message: 'Exploit Node.js worker clusters to hijack inter-worker communication.' },
    { regex: /password_verify\(.+\)/g, message: 'Bypass password_verify using weakly hashed passwords.' },
    { regex: /document\.domain/g, message: 'Exploit domain assignments to bypass same-origin policies.' },
    { regex: /Vite\./g, message: 'Abuse Vite configurations to leak sensitive build variables.' },
    { regex: /navigator\.deviceMemory/g, message: 'Fingerprint users by exploiting device memory exposure.' },
    { regex: /setTimeout\s*\(\s*".*"\)/g, message: 'Inject dynamic strings into setTimeout to execute arbitrary code.' },
    { regex: /unescape\(.+\)/g, message: 'Exploit deprecated unescape functions to execute malicious scripts.' },
    { regex: /fetch\(\s*document\.location\s*\)/g, message: 'Trigger SSRF by redirecting fetch requests to malicious URLs.' },
    { regex: /localStorage\.setItem\(.+\)/g, message: 'Abuse LocalStorage to store and retrieve sensitive user data.' },
    { regex: /window\.location\s*=/g, message: 'Inject malicious URLs into window.location for open redirects.' },
    { regex: /res\.redirect\s*\(.+\)/g, message: 'Exploit unvalidated redirects to direct users to malicious sites.' },
    { regex: /document\.cookie/g, message: 'Access and steal cookies to hijack user sessions.' },
    { regex: /window\.name/g, message: 'Exploit window.name to pass sensitive data across origins.' },
    { regex: /os\.path\.join\s*\(.+\)/g, message: 'Inject path traversal payloads into os.path.join for unauthorized file access.' },
    { regex: /sqlalchemy\.text/g, message: 'Exploit dynamic SQL in SQLAlchemy to achieve SQL injection.' },
    { regex: /crypto\.createHash\(['"](md5|sha1)['"]\)/g, message: 'Exploit weak hash algorithms (MD5/SHA1) to crack sensitive hashes.' },
    { regex: /child_process\.exec\(/g, message: 'Inject commands into child_process.exec to execute arbitrary commands.' },
    { regex: /axios\.post/g, message: 'Exploit insecure payloads in Axios POST requests to manipulate data.' },
    { regex: /navigator\.geolocation/g, message: 'Hijack user location by abusing the Geolocation API.' },
    { regex: /dangerouslySetInnerHTML/g, message: 'Inject malicious HTML into React’s dangerouslySetInnerHTML for XSS.' },
    { regex: /Buffer\.allocUnsafe/g, message: 'Exploit unsafe buffer allocation to leak memory content.' },
    { regex: /mongoClient\s*\.\s*db\(/g, message: 'Inject payloads into MongoDB client methods to manipulate or extract database contents.' },
    { regex: /res\.render\s*\(.+\)/g, message: 'Inject payloads into template rendering to exploit XSS or SSR vulnerabilities.' },
    { regex: /res\.download\s*\(.+\)/g, message: 'Exploit file download endpoints to retrieve unauthorized files.' },
    { regex: /axios\.create\(/g, message: 'Exploit custom Axios instances by injecting malicious headers or base URLs.' },
    { regex: /innerHTML\s*=/g, message: 'Attacker can inject arbitrary HTML/JavaScript via innerHTML, leading to XSS.' },
    { regex: /password|secret|key|token/gi, message: 'Hardcoded sensitive information may be stolen or misused by attackers.' },
    { regex: /document\.write\(/g, message: 'Attackers can exploit document.write to inject malicious scripts, leading to XSS.' },
    { regex: /new Function\(/g, message: 'Dynamic code execution allows attackers to run arbitrary JavaScript.' },
    { regex: /require\(.+\)/g, message: 'Dynamic require enables attackers to load malicious modules or dependencies.' },
    { regex: /os\.system\(/g, message: 'Command injection is possible, allowing attackers to execute arbitrary OS commands.' },
    { regex: /subprocess\.Popen\(/g, message: 'Unsanitized input can lead to arbitrary command execution by attackers.' },
    { regex: /base64\.b64decode\(/g, message: 'Attackers may use Base64 encoding to deliver and execute hidden payloads.' },
    { regex: /exec\(/g, message: 'Arbitrary command execution is possible via unsanitized inputs in exec.' },
    { regex: /importlib\.import_module\(/g, message: 'Dynamic import can allow attackers to load unauthorized modules.' },
    { regex: /pickle\.load\(/g, message: 'Attackers can exploit deserialization to execute arbitrary code.' },
    { regex: /unescaped\s*user\s*input/g, message: 'Unescaped user input can lead to XSS or injection vulnerabilities.' },
    { regex: /crypto\.createCipheriv\(.+['"]ecb['"]/g, message: 'Weak ECB mode allows attackers to manipulate ciphertexts.' },
    { regex: /\.env\s*=\s*.+/g, message: 'Environment variables exposed can lead to credential or data leaks.' },
    { regex: /res\.send\(\s*JSON\.stringify\(.+\)/g, message: 'Attackers can exploit raw JSON responses to deliver malicious payloads.' },
    { regex: /jwt\.sign\(.+,\s*['"].{0,16}['"]/g, message: 'Short JWT secrets are vulnerable to brute-force attacks by attackers.' },
    { regex: /navigator\.permissions/g, message: 'Abuse of permissions API can give attackers access to sensitive user data.' },
    { regex: /execSync\(.+\)/g, message: 'Synchronous command execution allows attackers to run arbitrary commands.' },
    { regex: /deepClone/g, message: 'Improper object cloning can lead to prototype pollution attacks.' },
    { regex: /JSON\.parse\(.+\)/g, message: 'Attackers can exploit JSON parsing to deliver prototype pollution payloads.' },
    { regex: /parse\(\s*window\.location\.search/g, message: 'Attackers can craft malicious query strings to exploit this parser.' },
    { regex: /http\.Agent\({\s*keepAlive:\s*true/g, message: 'Mismanaged connections may allow attackers to hijack sessions.' },
    { regex: /res\.setHeader\(.+['"]Set-Cookie['"]/g, message: 'Improperly configured cookies may be vulnerable to theft or tampering.' },
    { regex: /api\.fetch\(.+\)/g, message: 'Unvalidated API fetch calls may expose sensitive data to attackers.' },
    { regex: /context\.strokeText/g, message: 'Malicious inputs in canvas text rendering may lead to data leakage.' },
    { regex: /\.filter\(\s*.+=>.+\.length\s*[><]=?\s*1/g, message: 'Improper array filtering can lead to logic bypass or boundary exploits.' },
    { regex: /Content-Security-Policy/g, message: 'Weak CSP policies allow attackers to execute inline scripts or unsafe eval.' },
    { regex: /res\.json\(\s*require\(/g, message: 'Dynamic JSON file serving allows attackers to inject malicious responses.' },
    { regex: /path\.basename\(/g, message: 'Improper validation of paths can lead to directory traversal by attackers.' },
    { regex: /session_start\(/gi, message: 'Improper session handling in PHP can lead to session fixation attacks.' },
    { regex: /sqlite3_exec\(.+\)/g, message: 'Dynamic SQL queries allow attackers to execute SQL injection attacks.' },
    { regex: /cluster\.fork\(\)/g, message: 'Improper worker validation allows attackers to compromise inter-process communication.' },
    { regex: /password_verify\(.+\)/g, message: 'Improper password verification may allow attackers to bypass authentication.' },
    { regex: /re\.match\(.+\)/g, message: 'Improper regex patterns are vulnerable to ReDoS (Regex DoS) attacks.' },
    { regex: /document\.domain/g, message: 'Changing document.domain enables attackers to exploit cross-origin policies.' },
    { regex: /Vite\./g, message: 'Improperly configured Vite builds may expose sensitive environment variables.' },
    { regex: /process\.stdout\.write/g, message: 'Direct logging of sensitive data can be exploited for information disclosure.' },
    { regex: /secure_compare/g, message: 'Improper secure comparisons can leak timing information to attackers.' },
    { regex: /.*\$.*/g, message: 'Improper sanitization of template literals allows attackers to inject arbitrary data.' },
    { regex: /TLSv1_1_method/g, message: 'Weak TLS version allows attackers to compromise secure communications.' },
    { regex: /java\.security\.MessageDigest/g, message: 'Improper hash algorithms like MD5 or SHA1 are vulnerable to collision attacks.' },
    { regex: /.*toLocaleString\(/g, message: 'Improper locale formatting may lead to data manipulation or leakage.' },
    { regex: /useEffect\(.+\[\]\)/g, message: 'Unoptimized useEffect logic may enable attackers to abuse race conditions.' },
    { regex: /apolloClient\.mutate/g, message: 'Improper input sanitization in GraphQL mutations may allow injection attacks.' },
    { regex: /axios\.create\(/g, message: 'Attackers can abuse default headers or base URLs for sensitive data leakage.' },
    { regex: /mongoose\.Schema/g, message: 'Improperly defined schemas may lead to data tampering or injection.' },
    { regex: /localStorage\.setItem\(.+\)/g, message: 'Storing sensitive data in localStorage enables attackers to steal it via XSS.' },
    { regex: /document\.querySelector/g, message: 'Unvalidated selectors can be exploited for DOM-based XSS.' },
    { regex: /DOMParser\(\)/g, message: 'Improperly sanitized XML or HTML parsing can lead to injection attacks.' },
    { regex: /Headers\.append/g, message: 'Improper header values allow attackers to manipulate HTTP requests.' },
    { regex: /eval\(.*\)/g, message: 'Dynamic code execution allows attackers to inject and run arbitrary scripts.' },
    { regex: /this\.state\.\w+\s*=\s*.+/g, message: 'Direct state assignment may enable attackers to overwrite application state.' },
    { regex: /Content-Disposition/g, message: 'Improperly configured Content-Disposition headers may lead to data leakage.' },
    { regex: /CSP\.sandbox/g, message: 'Weak CSP sandbox policies allow attackers to bypass iframe restrictions.' },
    { regex: /@babel\/polyfill/g, message: 'Improper use of polyfills may introduce outdated or insecure dependencies.' },
    { regex: /crypto\.createHash\(['"]sha256['"]\)\.update\(['"].*['"]\)\.digest/g, message: 'Hardcoded inputs in hash functions enable attackers to infer secrets.' },
    { regex: /Object\.create\(\s*null\s*\)/g, message: 'Improper object creation may allow prototype pollution attacks.' },
    { regex: /\/\*\s*@ts-ignore/g, message: 'Improper TypeScript ignore comments may allow vulnerabilities to go unnoticed.' },
    { regex: /requestAnimationFrame\(.+\)/g, message: 'Unoptimized frame rendering may be exploited for timing attacks.' },
    { regex: /access-Control-Allow-Origin:\s*\*/gi, message: 'CORS wildcard headers allow attackers to access sensitive data cross-origin.' },
    { regex: /app\.get\(['"]\*\//g, message: 'Wildcard routes can allow unauthorized access to sensitive endpoints.' },
    { regex: /sessionStorage\s*\.\s*setItem/g, message: 'Storing sensitive data in sessionStorage can be stolen via XSS.' },
    { regex: /function\s+.+\s*\(.*,\s*arguments/g, message: 'Improper use of arguments may leak sensitive data or cause logic errors.' },
    { regex: /content-Security-Policy:\s*default-src\s*['"]self['"]/gi, message: 'Weak CSP allows attackers to inject malicious scripts from trusted origins.' },
    { regex: /window\.crypto\.getRandomValues/g, message: 'Improper use of random values may allow attackers to predict sensitive data.' },
    { regex: /fs\.chmodSync/g, message: 'Improper file permissions may allow attackers to access or modify files.' },
    { regex: /import\(.+\.wasm['"]\)/g, message: 'Improperly validated WebAssembly modules allow attackers to execute malicious code.' },
    { regex: /new\s+Intl\.DateTimeFormat/g, message: 'Improperly validated locale inputs can expose sensitive user data.' },
    { regex: /fetch\(\s*document\.location\s*\)/g, message: 'Exposing sensitive URLs via fetch can lead to SSRF or data leakage.' },
    { regex: /console\.table/g, message: 'Improper logging of sensitive data may expose it to attackers.' },
    { regex: /unescape\(.+\)/g, message: 'Using deprecated unescape functions may enable code injection attacks.' },
    { regex: /window\.frames\[\d+\]/g, message: 'Improper frame access can lead to phishing or clickjacking attacks.' },
    { regex: /:hover\s*\{.*cursor\s*:\s*pointer.*}/g, message: 'Improper styling can mislead users or enable UI redressing attacks.' },
    { regex: /if\s*\(\s*window\s*\.\s*top\s*!=\s*window\s*\)/g, message: 'Improper frame-busting code can lead to clickjacking bypasses.' },
    { regex: /ws\.onmessage/g, message: 'Improper WebSocket message handling may lead to injection or data leakage.' },
    { regex: /@angular\/platform-server/g, message: 'Improper Angular server rendering can lead to template injection attacks.' },
    { regex: /Deno\.run\(/g, message: 'Improperly sanitized commands can lead to arbitrary command execution.' },
    { regex: /<meta\s+http-equiv=['"]X-UA-Compatible['"]/g, message: 'Legacy compatibility headers can enable attackers to exploit outdated browsers.' },
    { regex: /const\s+\w+\s*=\s*require\(['"].+json['"]\)/g, message: 'Improper JSON imports may expose sensitive data or configurations.' },
    { regex: /let\s+\w+\s*=\s*await\s+Promise\.any\(/g, message: 'Improper promise handling may leak sensitive data or cause race conditions.' },
    { regex: /(?<!http(s)?:\/\/)(\.\.|\/\.\.)/g, message: 'Improper path validation enables directory traversal attacks.' },
    { regex: /navigator\.deviceMemory/g, message: 'Exposing device memory allows attackers to infer hardware details for exploitation.' },
    { regex: /<base\s+href=['"]http:/gi, message: 'Insecure base href exposes the app to man-in-the-middle attacks.' },
    { regex: /ng-template/g, message: 'Improper template binding in Angular can lead to injection vulnerabilities.' },
    { regex: /fetch\s*\(\s*['"].*jsonplaceholder.*['"]\)/g, message: 'Exposing placeholder API usage may allow attackers to abuse endpoints.' },
    { regex: /google\.(apis|maps|analytics)/g, message: 'Improperly secured Google APIs can expose keys or sensitive data.' },
    { regex: /html\(\s*\{\s*.+\s*}/g, message: 'Inject untrusted HTML through jQuery to execute malicious scripts.' },
    { regex: /res\.sendFile\(.+\)/g, message: 'Exploit unsanitized paths in res.sendFile to access sensitive files.' },
    { regex: /new\s*RegExp\(.+\)/g, message: 'Inject crafted patterns into dynamic regexes to achieve ReDoS attacks.' },
    { regex: /dangerouslySetInnerHTML/g, message: 'Inject malicious HTML using React’s dangerouslySetInnerHTML to execute XSS.' },
    { regex: /request\.param\s*\(.+\)/g, message: 'Exploit unsanitized parameters to achieve injection attacks.' },
    { regex: /sqlite3\.connect\(.+\)/g, message: 'Inject malicious database paths or commands into sqlite3.connect.' },
    { regex: /fs\.readFile\(/g, message: 'Read unauthorized files by injecting paths into fs.readFile.' },
    { regex: /window\.history\.pushState/g, message: 'Inject malicious URLs into pushState for phishing or session hijacking.' },
    { regex: /navigator\.geolocation/g, message: 'Exploit geolocation API to track or spoof user locations.' },
    { regex: /child_process\.fork\(/g, message: 'Exploit inter-process communication to execute malicious commands in forked processes.' },
    { regex: /cookie-parser/g, message: 'Hijack or manipulate cookies through insecure cookie parsing.' }
];



// Escape HTML to prevent rendering of the uploaded code
function escapeHTML(html) {
    return html
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// Determine file type from extension
function getFileType(fileName) {
    const extension = fileName.split('.').pop().toLowerCase();
    return extension;
}

// Process code and return vulnerabilities
function processCode(content, fileType, patterns) {
    const lines = content.split('\n'); // Split the code into lines
    const vulnerabilities = []; // Capture details of all vulnerabilities
    const formattedLines = lines.map((line, lineNumber) => {
        let processedLine = escapeHTML(line); // Start with escaped content

        patterns.forEach((pattern) => {
            let matches = line.match(pattern.regex);

            if (matches) {
                matches.forEach((match) => {
                    const escapedMatchText = escapeHTML(match);
                    const highlightSpan = `<span class="highlight">${escapedMatchText}</span>`;
                    
                    // Replace the match in the line with the highlighted span
                    processedLine = processedLine.replace(escapedMatchText, highlightSpan);

                    // Add to vulnerabilities if not a duplicate
                    if (!vulnerabilities.some(v => v.message === pattern.message && v.line === lineNumber + 1)) {
                        vulnerabilities.push({
                            message: pattern.message,
                            matchText: match,
                            line: lineNumber + 1,
                        });
                    }
                });
            }
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
        const fileType = getFileType(file.name);
        fileName.textContent = file.name;
        removeScriptButton.hidden = false;

        // Read the file content
        const content = await file.text();

        // Process the code for vulnerabilities
        const { vulnerabilities, formattedLines } = processCode(content, fileType, vulnerabilityPatterns);

        // Display vulnerabilities
        if (vulnerabilities.length > 0) {
            vulnerabilitiesOutput.innerHTML = vulnerabilities
                .map(
                    (vuln) =>
                        `&#8226; ${vuln.message} (Vulnerable code: "<code>${escapeHTML(
                            vuln.matchText
                        )}</code>", Line: ${vuln.line})`
                )
                .join('<br>');
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
