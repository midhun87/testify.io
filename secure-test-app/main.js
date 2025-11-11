// main.js
const { app, BrowserWindow, ipcMain, screen, dialog, systemPreferences } = require('electron');
const path = require('path');
const fetch = require('node-fetch'); // Use require for node-fetch v2
const { exec } = require('child_process'); // For system checks

// --- MOVED isDev TO THE TOP ---
const isDev = !app.isPackaged;

let mainWindow;
let systemCheckWindow; // Window for the new pre-check
let validatedTestData = null;
let currentToken = null;
let isTestSubmitted = false;


// --- MODIFIED BACKEND_URL for Local Testing ---
// Set to localhost based on your error logs.
// Change this back to 'https://www.testify-lac.com' for production.
const BACKEND_URL = 'https://www.testify-lac.com';
console.log(`[Startup] Using Local Test backend URL: ${BACKEND_URL}`);

// --- FORBIDDEN APPS LIST ---
const FORBIDDEN_APPS_WINDOWS = [
    'obs', 'obs64', 'obs32', 'ScreenFlow', 'QuickTime Player', 'vlc', // Common recording/media players
    'zoom.us', 'ms-teams', 'teams.exe', 'slack', 'discord', // Communication apps
    'chrome.exe', 'firefox.exe', 'msedge.exe', // Block other browsers (consider adding more if needed)
    'SnippingTool.exe', 'Snip & Sketch.exe', 'ScreenRec.exe', // Screenshot tools
    'anydesk.exe', 'teamviewer.exe' // Remote desktop tools
];
const FORBIDDEN_APPS_MACOS = [
    'OBS', 'ScreenFlow', 'QuickTime Player', 'VLC',
    'Zoom.us', 'Microsoft Teams', 'Slack', 'Discord',
    'Google Chrome', 'Firefox', 'Microsoft Edge', // Block other browsers
    'Screenshot', 'Screenshot.app', 'Grab', 'Grab.app', // Screenshot tools
    'AnyDesk', 'TeamViewer' // Remote desktop tools
];
// --- END FORBIDDEN APPS ---


// --- 1. NEW System Check Window ---
function createSystemCheckWindow() {
    console.log('[Startup] Creating system check window.');
    // Matched window style to token-entry window
    systemCheckWindow = new BrowserWindow({
        width: 600, // Increased width
        height: 550, // Increased height
        center: true,
        frame: true, // Show the frame (title bar, close buttons)
        resizable: isDev, // Allow resize in dev mode
        movable: true,
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            nodeIntegration: false,
            contextIsolation: true,
            devTools: isDev,
        }
    });

    if (isDev) {
        systemCheckWindow.webContents.openDevTools();
    }

    systemCheckWindow.loadFile('system-check.html');
    systemCheckWindow.setMenu(null); // No app menu
}

// --- 2. Initial Token Window Creation ---
function createTokenWindow() {
    console.log('[Startup] Creating initial token entry window.');
    mainWindow = new BrowserWindow({
        width: 800,
        height: 600,
        center: true,
        frame: true,
        resizable: isDev,
        movable: true,
        minimizable: true,
        closable: true,
        alwaysOnTop: false,
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            nodeIntegration: false,
            contextIsolation: true,
            devTools: isDev,
            sandbox: !isDev,
            webSecurity: true,
        }
    });

    if (isDev) {
        mainWindow.webContents.openDevTools();
    }

    mainWindow.loadFile('token-entry.html');
    mainWindow.setMenu(null);
}


// --- 3. Create Secure Lockdown Window ---
function createLockdownWindow() {
    const primaryDisplay = screen.getPrimaryDisplay();
    const { width, height } = primaryDisplay.workAreaSize;

    console.log('[Lockdown] Creating secure lockdown window.');

    const lockdownWindow = new BrowserWindow({
        width: width,
        height: height,
        fullscreen: true,
        kiosk: !isDev, // Enable kiosk mode only in production
        frame: false,
        resizable: false,
        movable: false,
        minimizable: false,
        closable: true,     // We handle closing via the 'close' event
        alwaysOnTop: !isDev,  // Only force on top in production
        show: false,          // Show after settings are applied
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            nodeIntegration: false,
            contextIsolation: true,
            devTools: isDev,
            sandbox: !isDev,
            webSecurity: true,
        }
    });

    // --- Aggressive Lockdown Settings ---
    if (process.platform === 'win32') {
         const appUserModelId = 'com.testify.securetest';
         app.setAppUserModelId(appUserModelId);
         lockdownWindow.setAppDetails({appId: appUserModelId});
         console.log(`[Lockdown Win32] Set AppUserModelId: ${appUserModelId}`);

         // Add Content Protection to block screen capture on Windows
         if (!isDev) {
            lockdownWindow.setContentProtection(true);
            console.log('[Lockdown Win32] Content protection enabled.');
         }
    }

    if (!isDev) {
        lockdownWindow.setAlwaysOnTop(true, 'screen-saver'); // Strongest level
        lockdownWindow.setKiosk(true); // Re-affirm kiosk
        lockdownWindow.setFullScreen(true); // Re-affirm fullscreen
        console.log("[Lockdown Production] Applied: kiosk, fullscreen, alwaysOnTop('screen-saver')");
    } else {
        console.log("[Dev Mode] Applying partial relaxation.");
        lockdownWindow.setAlwaysOnTop(false);
        lockdownWindow.setClosable(true);
        lockdownWindow.webContents.openDevTools();
    }

    lockdownWindow.show();
    lockdownWindow.setMenu(null); // Remove menu

    // --- Event Handlers ---
    lockdownWindow.on('close', (e) => {
        // Allow closing if in dev mode or if the test was successfully submitted
        if (isDev || isTestSubmitted) {
            console.log('[Lockdown] Window close allowed (Dev/Submitted).');
            return;
        }
        // Prevent closing otherwise and notify the renderer process
        console.log('[Lockdown] Window close attempt prevented.');
        e.preventDefault();
        dialog.showErrorBox('Action Denied', 'Closing the test window is not allowed during the test.');
        lockdownWindow.webContents.send('proctoring-violation', 'Attempted to close the test window.');
    });

    lockdownWindow.on('blur', () => {
        // Don't interfere in development mode
        if (isDev) return;
        console.log('[Lockdown Prod] Window lost focus. Reasserting focus.');
        lockdownWindow.flashFrame(true); // Flash taskbar icon on Windows
        // Notify the renderer process about the violation
        lockdownWindow.webContents.send('proctoring-violation', 'Window lost focus. Attempts to switch applications are monitored.');

        // Forcefully regain focus and re-apply lockdown settings
        lockdownWindow.focus();
        lockdownWindow.setKiosk(true);
        lockdownWindow.setFullScreen(true);
        lockdownWindow.setAlwaysOnTop(true, 'screen-saver');
    });

    lockdownWindow.on('leave-full-screen', () => {
        // Prevent leaving fullscreen/kiosk in production
        if (isDev) return;
        console.log('[Lockdown Prod] Attempted to leave full-screen. Re-entering.');
        // Re-apply settings
        lockdownWindow.setKiosk(true);
        lockdownWindow.setFullScreen(true);
        lockdownWindow.setAlwaysOnTop(true, 'screen-saver');
        // Notify renderer
        lockdownWindow.webContents.send('proctoring-violation', 'Exiting full-screen mode is not allowed.');
    });

    lockdownWindow.webContents.on('before-input-event', (event, input) => {
        // Escape hatch for development (Ctrl+Shift+Alt+Q)
        if (isDev && input.control && input.shift && input.alt && input.key.toLowerCase() === 'q') {
            console.log('!!! DEV ESCAPE HATCH. QUITTING. !!!'); app.quit(); return;
        }

        // Don't block shortcuts in dev mode
        if (isDev) return;

        // Block common clipboard shortcuts (Ctrl/Cmd + C/V/X)
        const isClipboardShortcut = (input.control || input.meta) && !input.alt && !input.shift;
        const key = input.key.toLowerCase();
        if (isClipboardShortcut && (key === 'c' || key === 'v' || key === 'x')) {
            console.log(`[Lockdown Prod] Blocked clipboard shortcut: ${input.meta ? 'Cmd' : 'Ctrl'}+${key}`);
            event.preventDefault(); // Prevent the default action
            lockdownWindow.webContents.send('proctoring-violation', 'Copy/paste/cut actions are disabled.');
            return;
        }

        // Block system shortcuts like Alt+Tab, Windows Key, Task Manager, etc.
        if (input.alt || input.meta || (input.control && input.shift && key === 'escape')) {
             if (input.meta && (input.type === 'keyDown' || input.type === 'keyUp')) {
                 console.log(`[Lockdown Prod] Blocked Windows Key (Meta).`);
                 event.preventDefault();
                 lockdownWindow.webContents.send('proctoring-violation', 'System shortcuts (Windows key) are disabled.');
                 return;
             }
             if(input.alt) {
                 console.log(`[Lockdown Prod] Blocked Alt-based shortcut (Key: ${key}).`);
                 event.preventDefault();
                 lockdownWindow.webContents.send('proctoring-violation', 'System shortcuts (Alt key combinations) are disabled.');
                 return;
             }
             if (input.control && input.shift && key === 'escape') {
                  console.log(`[Lockdown Prod] Blocked Task Manager shortcut.`);
                 event.preventDefault();
                 lockdownWindow.webContents.send('proctoring-violation', 'System shortcuts (Task Manager) are disabled.');
                 return;
             }
        }
    });

    return lockdownWindow; // Return the created window
}
// --- End Create Secure Window ---


// --- App Lifecycle ---
// Start with the system check window when the app is ready
app.whenReady().then(createSystemCheckWindow);

// Quit when all windows are closed (except on macOS)
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });

app.on('activate', () => {
    // On macOS, re-create the window if the dock icon is clicked and no windows are open
    if (BrowserWindow.getAllWindows().length === 0) {
        // Determine which window to create based on the current state (e.g., if a token was validated)
        if (!currentToken) {
            createSystemCheckWindow(); // Start flow from the beginning if no token is active
        }
        // Add more complex logic here if you need to resume a test (currently restarts)
    }
});
// --- End App Lifecycle ---

// --- NEW IPC Handlers for System Check ---

// Fired from system-check.html when all checks pass
ipcMain.on('system-check-passed', () => {
    console.log('[IPC] System check passed.');
    // Close the check window if it exists
    if (systemCheckWindow) {
        systemCheckWindow.close();
        systemCheckWindow = null;
    }
    // Proceed to the token entry window
    createTokenWindow();
});

// Fired from system-check.html if the user clicks Quit
ipcMain.on('quit-app', () => {
    console.log('[IPC] Quit app requested from system check.');
    app.quit();
});

// Handles the request from system-check.js to check running apps
ipcMain.handle('check-running-apps', () => {
    console.log('[IPC check-running-apps] Checking for forbidden applications...');
    return new Promise((resolve) => {
        const platform = process.platform;
        let cmd = '';
        let forbiddenList = [];
        const appName = app.getName(); // Get the name of *this* Electron app
        console.log(`[check-running-apps] Current app name: "${appName}"`);

        // Determine the command and forbidden list based on the OS
        if (platform === 'win32') {
            // Use full path to tasklist.exe to avoid PATH issues
            cmd = '"%WINDIR%\\System32\\tasklist.exe" /FO CSV /NH';
            forbiddenList = FORBIDDEN_APPS_WINDOWS;
        } else if (platform === 'darwin') {
            cmd = 'ps -ax -o comm'; // Get running process commands on macOS
            forbiddenList = FORBIDDEN_APPS_MACOS;
        } else {
            console.warn('[check-running-apps] Unsupported platform for app check.');
            return resolve({ forbiddenApps: [] }); // Assume pass on unsupported OS
        }

        // Execute the command
        exec(cmd, (err, stdout, stderr) => {
            if (err) {
                console.error('[check-running-apps] Error executing task list:', err);
                // Return an error object if the command fails
                return resolve({ error: `Could not check running apps. OS Error: ${err.message}` });
            }

            const runningApps = stdout.toLowerCase(); // Convert output to lowercase for comparison
            const foundApps = [];

            // Check if any forbidden app names are present in the output
            forbiddenList.forEach(appNameForbidden => {
                if (runningApps.includes(appNameForbidden.toLowerCase())) {
                    // CRITICAL: Ensure the forbidden app isn't this Electron app itself
                    if (appName.toLowerCase() !== appNameForbidden.toLowerCase()) {
                         foundApps.push(appNameForbidden);
                    }
                }
            });

            if (foundApps.length > 0) {
                console.warn(`[check-running-apps] Found forbidden apps: ${foundApps.join(', ')}`);
                resolve({ forbiddenApps: foundApps });
            } else {
                console.log('[check-running-apps] No forbidden apps found.');
                resolve({ forbiddenApps: [] });
            }
        });
    });
});

// Handles the request from system-check.js to check screen recording status (macOS only)
ipcMain.handle('check-screen-recording', () => {
    console.log('[IPC check-screen-recording] Checking media access...');
    let isRecording = false;
    let reason = 'No active screen recording detected.';

    if (process.platform === 'darwin') {
        // On macOS, check the system preference for screen recording permission
        const status = systemPreferences.getMediaAccessStatus('screen');
        console.log(`[check-screen-recording] macOS screen capture status: ${status}`);
        // 'granted' only means permission exists, not active recording. App check is primary.
        // We flag 'granted' as a potential risk for the user to double-check.
        if (status === 'granted') {
            isRecording = true; // Flag as potential issue
            reason = 'An application has screen recording permissions. Please disable it in System Settings > Security & Privacy.';
        } else if (status === 'denied' || status === 'not-determined') {
            isRecording = false;
        }
    } else if (process.platform === 'win32') {
        // No direct API on Windows. Rely on app check and content protection.
        console.log('[check-screen-recording] Windows: Relying on app check and content protection.');
        isRecording = false;
    }

    return { isRecording, reason };
});

// --- End NEW System Check IPC ---


// --- Existing IPC Handlers ---

// Provides environment info (isDev, BACKEND_URL) to renderer processes
ipcMain.handle('get-env', () => {
    console.log(`[IPC get-env] Providing environment. isDev: ${isDev}, BACKEND_URL: ${BACKEND_URL}`);
    return { isDev: isDev, BACKEND_URL: BACKEND_URL };
});

// Handles token validation requested from token-entry.js
ipcMain.handle('validate-token', async (event, token) => {
    console.log(`[IPC validate-token] Received token: ${token ? '******' : '<empty>'}`);
    if (!token) return { isValid: false, error: 'Token cannot be empty.' };

    try {
        // Call the backend API to validate the token and get test details
        const response = await fetch(`${BACKEND_URL}/api/public/test-details`, { headers: { 'x-auth-token': token } });
        const data = await response.json();

        // Check if the backend response indicates success
        if (!response.ok) {
            throw new Error(data?.message || `Validation failed (Status: ${response.status})`);
        }

        console.log(`[IPC validate-token] SUCCESS. Token valid for test: ${data?.title}. Is Mock: ${data.isMockTest}`);
        validatedTestData = data; // Store fetched test data globally in main process
        currentToken = token;     // Store the validated token globally

        // Close the current token entry window
        const currentWin = BrowserWindow.fromWebContents(event.sender);
        if (currentWin) {
            currentWin.close();
            mainWindow = null; // Clear the reference
        } else {
            console.warn('[IPC validate-token] Could not find token window to close.');
        }

        // Create the secure lockdown window for the next step
        mainWindow = createLockdownWindow();

        // --- THIS IS THE CHANGE ---
        // ALWAYS load the verification page, for both real and mock tests.
        console.log('[IPC validate-token] Loading candidate verification page for all users (mock or real)...');
        await mainWindow.loadFile('candidate-verification.html');
        // --- END OF CHANGE ---

        // Return success to the original (now closed) token entry window's JS
        return { isValid: true, error: null };

    } catch (error) {
        // Handle validation errors (network, invalid token, etc.)
        console.error('[IPC validate-token] Error:', error);
        validatedTestData = null; // Clear stored data on error
        currentToken = null;
        // Return failure details
        return { isValid: false, error: error.message || 'Network error or invalid response during validation.' };
    }
});


// Provides the stored token and test data to candidate-verification.html
ipcMain.handle('get-initial-verification-data', (event) => {
    console.log('[IPC get-initial-verification-data] Providing token and test details.');
    // Security check: Ensure the request comes from the current main window
    if (!mainWindow || event.sender !== mainWindow.webContents) {
        console.warn('[IPC get-initial-verification-data] Unauthorized request origin.');
        return null;
    }
    // Return the data fetched during token validation
    return { token: currentToken, testDetails: validatedTestData };
});

// Handles photo upload request from candidate-verification.js
ipcMain.handle('upload-photo', async (event, imageDataUrl) => {
    console.log('[IPC upload-photo] Received photo upload request...');
    if (!mainWindow || event.sender !== mainWindow.webContents) { console.warn('[IPC upload-photo] Unauthorized request origin.'); return { success: false, error: "Unauthorized request origin." }; }
    if (!imageDataUrl || !imageDataUrl.startsWith('data:image/jpeg;base64,')) return { success: false, error: "Invalid image data format." };

    try {
        // Proxy the upload request to the backend API
        const response = await fetch(`${BACKEND_URL}/api/public/upload-image`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ imageData: imageDataUrl })
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.message || `Backend upload failed (Status: ${response.status})`);
        console.log('[IPC upload-photo] Backend upload successful. URL:', result.imageUrl);
        return { success: true, imageUrl: result.imageUrl }; // Return Cloudinary URL
    } catch (error) {
        console.error('[IPC upload-photo] Error during upload:', error);
        return { success: false, error: error.message || "Server error during upload." };
    }
});

// Handles college list fetch request from candidate-verification.js
ipcMain.handle('fetch-colleges', async (event, testId) => {
    console.log(`[IPC fetch-colleges] Request for testId: ${testId}`);
    if (!mainWindow || event.sender !== mainWindow.webContents) { console.warn('[IPC fetch-colleges] Unauthorized request origin.'); return { success: false, error: "Unauthorized request." }; }
    if (!testId) return { success: false, error: "Test ID is required." };

    try {
        // Proxy the request to the backend API
        const response = await fetch(`${BACKEND_URL}/api/public/colleges/${testId}`);
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || `Failed to fetch colleges (Status: ${response.status})`);
        console.log(`[IPC fetch-colleges] Fetched ${data.length} colleges.`);
        return { success: true, colleges: data };
    } catch (error) {
        console.error('[IPC fetch-colleges] Error:', error);
        return { success: false, error: error.message || 'Server error fetching colleges.' };
    }
});


//
// --- *** THIS IS THE CRITICAL FIX *** ---
//
// Handles submission of verification details from candidate-verification.js
ipcMain.handle('submit-verification-details', async (event, receivedToken, details) => {
    console.log('[IPC submit-verification-details] Received details:', details);
    if (!mainWindow || event.sender !== mainWindow.webContents) { console.warn('[IPC submit-verification-details] Unauthorized request origin.'); return { success: false, error: "Unauthorized request." }; }
    if (receivedToken !== currentToken) { console.error('[IPC submit-verification-details] Token mismatch!'); return { success: false, error: "Token mismatch error." }; }
    if (!details || !validatedTestData) { console.error('[IPC submit-verification-details] Missing details or original test data.'); return { success: false, error: "Internal error: Missing data." }; }

    
    // --- NEW MOCK TEST LOGIC ---
    if (validatedTestData.isMockTest === true) {
        console.log('[IPC submit-verification-details] Mock test. Skipping backend save for verification details.');
        
        // Store details for the test page to fetch
        // (This is a simplified way to pass details without DB)
        validatedTestData.candidateDetails = details; 
        console.log(`[IPC submit-verification-details] Mock User Details: ${JSON.stringify(details)}`);

        // --- Phase 2: Load the Correct Test Page ---
        try {
            const isCodingTest = validatedTestData?.testType === 'coding';
            console.log(`[IPC submit-verification-details] isCodingTest evaluated to: ${isCodingTest} (testType: ${validatedTestData?.testType})`);
            const testPage = isCodingTest ? 'hiring-coding-test.html' : 'hiring-test.html';
            
            console.log(`[IPC submit-verification-details] Loading page: ${testPage}`);
            await mainWindow.loadFile(testPage);
            console.log(`[IPC submit-verification-details] Test page ${testPage} loaded.`);
            
            return { success: true }; // <<< IT RETURNS SUCCESS
        
        } catch (loadError) {
            // Handle errors loading the HTML file
            console.error(`[IPC submit-verification-details] Error loading test page:`, loadError);
            dialog.showErrorBox('Loading Error', `Failed to load the test page: ${loadError.message}. Please restart the application.`);
            return { success: false, error: `Load failed: ${loadError.message}` };
        }
    }
    // --- END MOCK TEST LOGIC ---


    // --- STANDARD HIRING FLOW ---
    // (This code will only run if isMockTest is false)
    console.log('[IPC submit-verification-details] Standard test. Saving details to backend...');
    try {
        const assignmentId = validatedTestData?.assignmentId;
        if (!assignmentId) throw new Error("Missing assignment ID in validated test data.");

        // Call the backend API to save the initial verification record
        const saveResponse = await fetch(`${BACKEND_URL}/api/save-initial-details`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'x-auth-token': currentToken },
            body: JSON.stringify({ details }) // Send details object directly
        });
        const saveResult = await saveResponse.json();
        if (!saveResponse.ok) throw new Error(saveResult.message || `Backend save failed (Status: ${saveResponse.status})`);
        console.log('[IPC submit-verification-details] Backend saved initial details successfully.');
    } catch (saveError) {
        // Handle errors during the save process
        console.error('[IPC submit-verification-details] Error saving initial details:', saveError);
        // dialog.showErrorBox('Initialization Error', `Failed to save verification details: ${saveError.message}. Please restart the application.`);
        return { success: false, error: `Save failed: ${saveError.message}` }; // <<< THIS IS THE SOURCE OF YOUR ERROR
    }

    // Phase 2: Load the Correct Test Page (for standard flow)
    try {
        const isCodingTest = validatedTestData?.testType === 'coding';
        console.log(`[IPC submit-verification-details] isCodingTest evaluated to: ${isCodingTest} (testType: ${validatedTestData?.testType})`);

        const testPage = isCodingTest ? 'hiring-coding-test.html' : 'hiring-test.html';

        console.log(`[IPC submit-verification-details] Loading page: ${testPage}`);
        await mainWindow.loadFile(testPage);
        console.log(`[IPC submit-verification-details] Test page ${testPage} loaded.`);
        return { success: true }; // Indicate success

    } catch (loadError) {
        // Handle errors loading the HTML file
        console.error(`[IPC submit-verification-details] Error loading test page:`, loadError);
        dialog.showErrorBox('Loading Error', `Failed to load the test page: ${loadError.message}. Please restart the application.`);
        return { success: false, error: `Load failed: ${loadError.message}` };
    }
});


//
// --- *** MODIFIED 'get-validated-token' HANDLER *** ---
//
// Provides the validated token AND mock status to the test pages
ipcMain.handle('get-validated-token', (event) => {
    // Security check
    if (!mainWindow || event.sender !== mainWindow.webContents) {
        console.warn('[IPC get-validated-token] Unauthorized request origin.');
        return null; // Return null on failure
    }
    
    // Check if we have the necessary data
    if (!currentToken || !validatedTestData) {
         console.error('[IPC get-validated-token] Error: currentToken or validatedTestData is missing.');
         return null; // Return null on failure
    }

    console.log(`[IPC get-validated-token] Providing token and mock status (isMockTest: ${validatedTestData.isMockTest}).`);
    
    // Return an OBJECT, not just the token string
    return { 
        token: currentToken, 
        isMockTest: validatedTestData.isMockTest || false 
    };
});

// Fired from the test page upon successful submission to the backend
ipcMain.on('test-submitted-successfully', (event) => {
    // Security check
    if (!mainWindow || event.sender !== mainWindow.webContents) {
        console.warn('[IPC test-submitted-successfully] Unauthorized signal origin.');
        return;
    }
    console.log('[IPC test-submitted-successfully] Signal received. Quitting application.');
    isTestSubmitted = true; // Set flag to allow clean closing
    app.quit(); // Quit the Electron application
});
// --- End IPC Handlers ---
