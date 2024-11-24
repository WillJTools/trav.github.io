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
    { regex: /unescaped\s*user\s*input/g, message: 'Unescaped user input detected. Risk of XSS or injection vulnerabilities.' },
    { regex: /document\.write\s*\(/g, message: 'document.write detected. Avoid using this as it can lead to XSS vulnerabilities.' },
    { regex: /password\s*=\s*[^\s;]+/gi, message: 'Hardcoded password detected. Avoid storing passwords in plaintext.' },
    { regex: /location\.hash\s*\=\s*\w+/gi, message: 'Direct manipulation of location.hash detected. Validate input to prevent attacks.' },
    { regex: /onclick\s*=\s*".*"/gi, message: 'Inline onclick JavaScript detected. Move the logic to external scripts.' },
    { regex: /window\.name\s*\=\s*".*"/gi, message: 'Window name manipulation detected. Avoid using window.name for sensitive data.' },
    { regex: /Object\.defineProperty\s*\(\s*globalThis/g, message: 'Global object modification detected. Risk of global namespace pollution.' },
    { regex: /<svg[^>]+onload=["'].*?["']/g, message: 'SVG with onload event detected. Potential for XSS.' },
    { regex: /import\s+.+\s+from\s+['"](\.\.|\/\.\.)/g, message: 'Relative path imports detected. Risk of directory traversal or supply chain attacks.' },
    { regex: /Object\.assign\s*\(\s*globalThis/g, message: 'Direct assignment to globalThis detected. Avoid polluting the global namespace.' },
    { regex: /class\s+.+\s+extends\s+Error/g, message: 'Custom error class detected. Ensure error messages do not expose sensitive details.' },
    { regex: /\*\s+@param\s+\{.*?\}\s+.*default.*=.*null/gi, message: 'Parameters with default null values detected. Validate optional parameters.' },
    { regex: /new\s+Proxy\s*\(.+\)/g, message: 'Proxy object detected. Ensure the handler properly restricts unwanted access or mutation.' },
    { regex: /new\s+WeakMap\s*\(.+\)/g, message: 'WeakMap usage detected. Ensure sensitive data is not weakly referenced inappropriately.' },
    { regex: /res\.redirect\s*\(.+\)/g, message: 'Redirect response detected. Ensure URL redirection is validated to prevent open redirects.' },
    { regex: /\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/.+/g, message: 'Excessive directory traversal detected. Validate file paths thoroughly.' },
    { regex: /const\s+.+\s+=\s+.+\.querySelectorAll\(/g, message: 'Bulk DOM selectors detected. Ensure proper input sanitization for mass DOM updates.' },
    { regex: /navigator\.sendBeacon/g, message: 'sendBeacon detected. Validate destination URLs and transmitted data.' },
    { regex: /element\.getAttribute\(["']on.*?["']\)/g, message: 'Dynamic access to event handler attributes detected. Potential for XSS.' },
    { regex: /process\.chdir\(/g, message: 'Changing working directory detected in Node.js. Ensure paths are validated.' },
    { regex: /os\.path\.join\s*\(.+\)/g, message: 'Path joining detected in Python. Ensure input paths are sanitized.' },
    { regex: /sqlalchemy\.text/g, message: 'Dynamic SQL in SQLAlchemy detected. Ensure input is sanitized to prevent injection.' },
    { regex: /sqlite3\.connect\(.+\)/g, message: 'SQLite connection detected. Validate database paths and permissions.' },
    { regex: /import\s+\* as/g, message: 'Wildcard imports detected. Avoid importing unnecessary modules.' },
    { regex: /new\s+Intl\.ListFormat\(/g, message: 'Intl ListFormat API detected. Validate inputs for list formatting to prevent data leakage.' },
    { regex: /Math\.round\(.+\)/g, message: 'Math rounding detected. Ensure floating-point precision issues are handled.' },
    { regex: /Buffer\.allocUnsafe/g, message: 'Unsafe buffer allocation detected in Node.js. Use alloc instead.' },
    { regex: /requestAnimationFrame/g, message: 'requestAnimationFrame usage detected. Validate frame rendering logic to avoid race conditions.' },
    { regex: /eval\(.+\)\s*\/\/\s*safe/gi, message: 'Unsafe eval marked as safe detected. Avoid evaluating code dynamically.' },
    { regex: /child_process\.fork\(/g, message: 'Child process forking detected. Ensure inter-process communication is secure.' },
    { regex: /<template[^>]*>\s*<script>/g, message: 'Inline script in template tag detected. Avoid inline JavaScript for security reasons.' },
    { regex: /document\.forms\[\w+\]\.submit\(\)/g, message: 'Direct form submission detected. Validate all form data before submission.' },
    { regex: /html5shiv/g, message: 'Legacy HTML5 shiv detected. Remove legacy code for modern browser compatibility.' },
    { regex: /import\s+.+\s+from\s+['"]data:/g, message: 'Data URI import detected. Validate data to avoid malicious payloads.' },
    { regex: /CSSStyleSheet/g, message: 'CSSStyleSheet API detected. Ensure stylesheets are properly sanitized before injection.' },
    { regex: /new\s+SharedArrayBuffer/g, message: 'SharedArrayBuffer usage detected. Validate memory sharing between threads securely.' },
    { regex: /Reflect\.construct\(/g, message: 'Dynamic class instantiation detected using Reflect. Validate constructor arguments.' },
    { regex: /app\.use\(\s*['"]\/api/g, message: 'Generic API endpoint detected in Express. Validate all API inputs thoroughly.' },
    { regex: /cookie-parser/g, message: 'Cookie-parser usage detected. Ensure cookies are encrypted and validated.' },
    { regex: /expectException/g, message: 'Expected exception handling in tests detected. Ensure all exceptions are tested.' },
    { regex: /const\s+.+\s+=\s+\[\]\.concat\(/g, message: 'Array concatenation detected. Ensure input arrays are sanitized.' },
    { regex: /context\.drawImage/g, message: 'Canvas image rendering detected. Validate sources to avoid data exfiltration.' },
    { regex: /await\s*setTimeout/g, message: 'Timeout inside async function detected. Ensure timeout delays are appropriate.' },
    { regex: /Object\.freeze\s*\(.+\)/g, message: 'Freezing objects detected. Avoid freezing sensitive objects.' },
    { regex: /String\.prototype\.replace/g, message: 'String replace detected. Validate replacement logic for potential bypasses.' },
    { regex: /getElementsByTagName/g, message: 'DOM tag selector detected. Avoid inefficient selectors.' },
    { regex: /parentNode\.removeChild/g, message: 'Direct node removal detected. Validate node removal logic.' },
    { regex: /outerHTML\s*=\s*.+/g, message: 'Direct outerHTML modification detected. Ensure content is sanitized.' },
    { regex: /window\.frames/g, message: 'Frame access detected. Validate cross-frame interactions.' },
    { regex: /input\s+type=["']password["']/gi, message: 'Password input detected. Ensure inputs are not auto-filled insecurely.' },
    { regex: /Object\.hasOwnProperty/g, message: 'Direct property checks detected. Avoid prototype pollution risks.' },
    { regex: /unhandledRejection/g, message: 'Unhandled promise rejections detected. Add appropriate error handling.' },
    { regex: /aggregate\(\s*\[.+?\]/g, message: 'MongoDB aggregation pipeline detected. Validate pipeline stages.' },
    { regex: /binarySearch/g, message: 'Custom binary search detected. Ensure algorithm handles edge cases correctly.' },
    { regex: /let\s+\w+\s*=\s*location\.hash/g, message: 'Accessing location.hash detected. Validate fragment identifiers.' },
    { regex: /BigInt\(.+\)/g, message: 'BigInt usage detected. Validate for numerical overflow or improper use.' },
    { regex: /new\s+Intl\.DisplayNames/g, message: 'Intl DisplayNames detected. Ensure locale is set explicitly.' },
    { regex: /FS\.mkdirSync/g, message: 'Synchronous directory creation detected in Node.js. Validate paths properly.' },
    { regex: /fetch\s*\(.+,\s*{\s*method:\s*['"](DELETE|PUT)['"]/gi, message: 'Sensitive HTTP methods detected in fetch API. Validate input and permissions.' },
    { regex: /await\s+eval\(/g, message: 'Asynchronous eval usage detected. Avoid dynamic code execution.' },
    { regex: /\.setHeader\(["']X-Powered-By['"],/gi, message: 'Setting X-Powered-By header detected. Avoid exposing framework information.' },
    { regex: /crypto\.subtle\.generateKey/g, message: 'Web Crypto API key generation detected. Ensure strong algorithm configurations.' },
    { regex: /websocket\s*=\s*new\s*WebSocket\(.+\)/g, message: 'WebSocket connection detected. Validate origin and sanitize input.' },
    { regex: /atob\(/g, message: 'atob detected. Check for potential Base64 injection vulnerabilities.' },
    { regex: /btoa\(/g, message: 'btoa detected. Ensure data encoding does not expose sensitive information.' },
    { regex: /JSON\.parse\(.+\)/g, message: 'JSON.parse detected. Ensure parsed data is validated to avoid prototype pollution.' },
    { regex: /JSON\.stringify\s*\(.*\)/g, message: 'Ensure sensitive data is excluded when stringifying objects.' },
    { regex: /while\s*\(true\)/g, message: 'Infinite loop detected. Risk of Denial-of-Service (DoS).' },
    { regex: /setTimeout\s*\(\s*".*"\)/g, message: 'Dynamic string in setTimeout detected. Avoid for security reasons.' },
    { regex: /navigator\.hardwareConcurrency/g, message: 'Hardware concurrency API detected. Avoid exposing hardware details.' },
    { regex: /document\.referrer/g, message: 'Accessing document.referrer detected. Ensure referrer data is handled securely.' },
    { regex: /document\.cookie\s*\=\s*".*Secure.*"/gi, message: 'Cookies without the Secure flag detected. Ensure cookies are secure.' },
    { regex: /<script[^>]+src=["']http:/gi, message: 'Insecure HTTP script source detected. Use HTTPS for scripts.' },
    { regex: /style\s*=\s*['"].*expression\(.*\)/gi, message: 'CSS expression detected. Risk of CSS-based XSS.' },
    { regex: /animation\s*:\s*['"]none['"]/g, message: 'CSS animation properties detected. Ensure animations are secure.' },
    { regex: /file_get_contents\(.+\)/g, message: 'Use of file_get_contents in PHP detected. Validate file paths to prevent LFI.' },
    { regex: /preg_replace\s*\(.+['"]e['"]/gi, message: 'Use of preg_replace with /e modifier in PHP detected. Risk of code execution.' },
    { regex: /htmlspecialchars\s*\(.+,.*ENT_NOQUOTES.*/g, message: 'HTML escaping without quotes detected in PHP. Use ENT_QUOTES instead.' },
    { regex: /sprintf\s*\(.*%x.*\)/g, message: 'Hexadecimal formatting detected in sprintf. Ensure data is sanitized.' },
    { regex: /java\.net\.URLConnection/g, message: 'URLConnection in Java detected. Check for insecure configurations.' },
    { regex: /java\.nio\.file\.Files\.readAllBytes/g, message: 'Reading files directly in Java detected. Ensure file paths are secure.' },
    { regex: /executor\.submit\(/g, message: 'Executor.submit detected in Java. Handle thread pools carefully to prevent exhaustion.' },
    { regex: /__proto__\s*:/g, message: 'Prototype pollution vulnerability detected. Avoid unsafe object assignments.' },
    { regex: /eval\s*\(.+\)/g, message: 'Use of eval detected. Avoid evaluating dynamic JavaScript code.' },
    { regex: /fs\.unlink/g, message: 'File deletion detected in Node.js. Validate paths to prevent file-based attacks.' },
    { regex: /fs\.mkdir/g, message: 'Directory creation detected. Ensure proper sanitization to avoid directory traversal.' },
    { regex: /child_process\.execFile/g, message: 'Execution of external commands detected in Node.js. Validate inputs.' },
    { regex: /axios\.post/g, message: 'POST request detected in Axios. Ensure payloads are sanitized and validated.' },
    { regex: /react-scripts/g, message: 'React development scripts detected. Ensure scripts are not exposed in production.' },
    { regex: /element\.dataset\./g, message: 'Dynamic dataset property access detected. Validate data attributes.' },
    { regex: /\$\(/g, message: 'Use of jQuery selectors detected. Ensure input is sanitized before using jQuery.' },
    { regex: /res\.sendFile/g, message: 'Sending files directly in Express.js detected. Validate file paths.' },
    { regex: /crypto\.createCipheriv/g, message: 'Custom encryption detected in Node.js. Ensure strong algorithms are used.' },
    { regex: /crypto\.randomUUID\(/g, message: 'Random UUID generation detected. Validate UUID usage to prevent predictable IDs.' },
    { regex: /socket\.broadcast\.emit/g, message: 'Broadcasting events via WebSocket detected. Validate event data.' },
    { regex: /window\.alert/g, message: 'Use of alert detected. Avoid alert dialogs in production code.' },
    { regex: /new\s*RegExp\(.+\)/g, message: 'Dynamic regular expression detected. Validate patterns to avoid ReDoS attacks.' },
    { regex: /navigator\.clipboard\.writeText/g, message: 'Clipboard API detected. Ensure user input is sanitized before copying.' },
    { regex: /canvas\.toDataURL/g, message: 'Canvas toDataURL detected. Check for potential data leakage.' },
    { regex: /@font-face/g, message: 'Custom font-face usage detected. Ensure fonts are loaded securely.' },
    { regex: /app\.put\(/g, message: 'PUT route in Express.js detected. Validate and sanitize payloads.' },
    { regex: /WebAssembly/g, message: 'WebAssembly detected. Validate imported modules for security risks.' },
    { regex: /setImmediate/g, message: 'setImmediate detected. Use cautiously to avoid untrusted code execution.' },
    { regex: /crypto\.pbkdf2/g, message: 'Password-based key derivation detected. Ensure secure salt and iterations.' },
    { regex: /crossorigin\s*=\s*"anonymous"/gi, message: 'Cross-origin resource detected. Ensure CORS is configured securely.' },
    { regex: /await\s*Promise\.all\(.+\)/g, message: 'Promise.all detected. Ensure error handling for all promises.' },
    { regex: /cssText\s*=\s*".*"/gi, message: 'Direct manipulation of style.cssText detected. Ensure styles are safe.' },
    { regex: /dangerouslySetInnerHTML/g, message: 'React dangerouslySetInnerHTML detected. Ensure the content is sanitized.' },
    { regex: /http-equiv\s*=\s*"refresh"/gi, message: 'Meta refresh detected. Avoid automatic redirections for better usability and security.' },
    { regex: /localStorage\.setItem\s*\(.*\)/g, message: 'Sensitive data storage in localStorage detected. Consider alternatives like cookies with HttpOnly.' },
    { regex: /navigator\.geolocation\.getCurrentPosition\s*\(/g, message: 'Geolocation API detected. Ensure user consent and secure handling of location data.' },
    { regex: /innerHTML\s*=\s*request\.params/g, message: 'Assignment of request parameters to innerHTML detected. Risk of XSS.' },
    { regex: /event\.returnValue\s*=\s*false;/g, message: 'Direct event returnValue manipulation detected. Use preventDefault instead.' },
    { regex: /console\.trace/g, message: 'Console.trace detected. Remove debug code before production.' },
    { regex: /catch\s*\(err\)\s*{\s*}/g, message: 'Empty catch block detected. Properly handle exceptions.' },
    { regex: /setInterval\s*\(\s*".*"\s*,/g, message: 'Dynamic string in setInterval detected. Avoid for security and performance.' },
    { regex: /serialize\s*\(.*\)/g, message: 'Improper serialization detected. Ensure objects are serialized securely.' },
    { regex: /decodeURIComponent\s*\(.*\)/g, message: 'Use of decodeURIComponent detected. Ensure input is sanitized before decoding.' },
    { regex: /srcdoc\s*=\s*".*"/g, message: 'Iframe srcdoc attribute detected. Avoid injecting untrusted HTML.' },
    { regex: /javascript:\s*void/g, message: 'javascript:void detected in links. Consider alternatives for better usability.' },
    { regex: /res\.jsonp/g, message: 'Use of JSONP in responses detected. Risk of XSS.' },
    { regex: /res\.send\(.+\)/g, message: 'Sending raw response detected. Ensure proper encoding and sanitization.' },
    { regex: /document\.cookie\s*=\s*".*HttpOnly.*"/gi, message: 'HttpOnly flag missing in cookie settings. Ensure sensitive cookies are protected.' },
    { regex: /catch\s*\(e\)\s*{\s*throw\s*e;\s*}/g, message: 'Rethrowing caught exceptions detected. Handle exceptions more gracefully.' },
    { regex: /appendChild\s*\(.*\)/g, message: 'Direct use of appendChild detected. Sanitize all inserted DOM nodes.' },
    { regex: /replaceChild\s*\(.*\)/g, message: 'Direct use of replaceChild detected. Validate and sanitize all replacements.' },
    { regex: /response\.redirect\s*\(.+\)/g, message: 'Unvalidated redirect detected. Validate destination URLs.' },
    { regex: /window\.addEventListener\s*\(\s*"error",/g, message: 'Global error handler detected. Avoid exposing sensitive error details.' },
    { regex: /fetch\s*\(\s*".*"/g, message: 'Fetch with hardcoded URLs detected. Validate and sanitize input data.' },
    { regex: /decodeURI\s*\(.+\)/g, message: 'Decode URI usage detected. Ensure sanitized input before decoding.' },
    { regex: /document\.write\s*\(.+\)/g, message: 'Direct use of document.write detected. Risk of XSS.' },
    { regex: /eval\s*\(.+\)/g, message: 'Use of eval detected. Avoid eval for executing dynamic code.' },
    { regex: /element\.src\s*=\s*".*"/g, message: 'Dynamic assignment to element.src detected. Validate and sanitize URLs.' },
    { regex: /prototype\s*=\s*{.*}/g, message: 'Direct prototype modification detected. Use Object.create for better safety.' },
    { regex: /setAttribute\s*\(\s*"href",\s*.*\)/g, message: 'Dynamic href attribute assignment detected. Validate URLs to prevent open redirects.' },
    { regex: /new\s*XMLHttpRequest/g, message: 'Direct use of XMLHttpRequest detected. Prefer Fetch API for better security.' },
    { regex: /Promise\.resolve\s*\(.+\)/g, message: 'Promise.resolve detected. Ensure data passed is sanitized.' },
    { regex: /style\.backgroundImage\s*=\s*".*"/g, message: 'Dynamic assignment to style.backgroundImage detected. Validate URLs.' },
    { regex: /document\.body\s*\.\s*innerHTML/g, message: 'Direct assignment to body.innerHTML detected. Risk of XSS.' },
    { regex: /console\.warn/g, message: 'Console.warn detected. Ensure debugging messages are removed in production.' },
    { regex: /JSON\.stringify\s*\(.+\)/g, message: 'JSON.stringify detected. Ensure sensitive data is not exposed in logs.' },
    { regex: /Promise\.allSettled/g, message: 'Promise.allSettled detected. Ensure proper handling of all settled promises.' },
    { regex: /formData\.append\s*\(.+\)/g, message: 'FormData.append detected. Validate and sanitize data before appending.' },
    { regex: /addEventListener\s*\(\s*"message"/g, message: 'Listening to message events detected. Ensure origin validation.' },
    { regex: /navigator\.appVersion/g, message: 'Use of navigator.appVersion detected. Avoid browser-specific logic.' },
    { regex: /res\.render\s*\(.+\)/g, message: 'Rendering templates detected. Ensure proper escaping to prevent XSS.' },
    { regex: /res\.download\s*\(.+\)/g, message: 'File download detected. Ensure file paths are validated.' },
    { regex: /request\.param\s*\(.+\)/g, message: 'Direct use of request.param detected. Risk of injection vulnerabilities.' },
    { regex: /html\(\s*\{\s*.+\s*}/g, message: 'Dynamic HTML injection detected in jQuery. Ensure content is sanitized.' },
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
