// main.js
// ... other requires ...
const fetch = require('node-fetch');
const { exec } = require('child_process');

// --- MOVED isDev TO THE TOP ---
const isDev = !app.isPackaged; // Keep isDev for other conditional logic (devtools, etc.)

let mainWindow;
// ... other state variables ...

// --- HARDCODED BACKEND_URL for Production ---
const BACKEND_URL = 'https://www.testify-lac.com';
console.log(`[Startup] Using fixed PRODUCTION backend URL: ${BACKEND_URL}`);

// --- FORBIDDEN APPS LIST ---
const FORBIDDEN_APPS_WINDOWS = [
// --- Window Creation Functions ---
    'zoom.us', 'ms-teams', 'teams.exe', 'slack', 'discord',
    'chrome.exe', 'firefox.exe', 'msedge.exe', // Block other browsers
    'SnippingTool.exe', 'Snip & Sketch.exe', 'ScreenRec.exe',
    'anydesk.exe', 'teamviewer.exe'
];
const FORBIDDEN_APPS_MACOS = [
    'OBS', 'ScreenFlow', 'QuickTime Player', 'VLC',
    'Zoom.us', 'Microsoft Teams', 'Slack', 'Discord',
    'Google Chrome', 'Firefox', 'Microsoft Edge', // Block other browsers
    'Screenshot', 'Screenshot.app', 'Grab', 'Grab.app',
    'AnyDesk', 'TeamViewer'
];
// --- END FORBIDDEN APPS ---


// --- 1. NEW System Check Window ---
function createSystemCheckWindow() {
    console.log('[Startup] Creating system check window.');
    // ** MODIFICATION: Matched window style to token-entry window **
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
// This function is mostly from your original file, with enhancements
function createLockdownWindow() {
    const primaryDisplay = screen.getPrimaryDisplay();
    const { width, height } = primaryDisplay.workAreaSize;

    console.log('[Lockdown] Creating secure lockdown window.');

    const lockdownWindow = new BrowserWindow({
        width: width,
        height: height,
        fullscreen: true,
        kiosk: true,
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

         // ** NEW: Add Content Protection to block screen capture on Windows **
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

    // --- Event Handlers (From your original file, all correct) ---
    lockdownWindow.on('close', (e) => {
        if (isDev || isTestSubmitted) {
            console.log('[Lockdown] Window close allowed (Dev/Submitted).');
            return;
        }
        console.log('[Lockdown] Window close attempt prevented.');
        e.preventDefault();
        lockdownWindow.webContents.send('proctoring-violation', 'Attempted to close the test window.');
    });

    lockdownWindow.on('blur', () => {
        if (isDev) return;
        console.log('[Lockdown Prod] Window lost focus. Reasserting focus.');
        lockdownWindow.flashFrame(true);
        lockdownWindow.webContents.send('proctoring-violation', 'Window lost focus. Attempts to switch applications are monitored.');

        // Re-assertion
        lockdownWindow.focus();
        lockdownWindow.setKiosk(true);
        lockdownWindow.setFullScreen(true);
        lockdownWindow.setAlwaysOnTop(true, 'screen-saver');
    });

    lockdownWindow.on('leave-full-screen', () => {
        if (isDev) return;
        console.log('[Lockdown Prod] Attempted to leave full-screen. Re-entering.');
        lockdownWindow.setKiosk(true);
        lockdownWindow.setFullScreen(true);
        lockdownWindow.setAlwaysOnTop(true, 'screen-saver');
        lockdownWindow.webContents.send('proctoring-violation', 'Exiting full-screen mode is not allowed.');
    });

    lockdownWindow.webContents.on('before-input-event', (event, input) => {
        // Escape hatch for dev
        if (isDev && input.control && input.shift && input.alt && input.key.toLowerCase() === 'q') {
            console.log('!!! DEV ESCAPE HATCH. QUITTING. !!!'); app.quit(); return;
        }

        if (isDev) return; // Don't block shortcuts in dev mode

        // Block Ctrl+C, Ctrl+V, Ctrl+X
        const isShortcut = (input.control || input.meta) && !input.alt && !input.shift;
        const key = input.key.toLowerCase();
        if (isShortcut && (key === 'c' || key === 'v' || key === 'x')) {
            console.log(`[Lockdown Prod] Blocked clipboard shortcut: ${input.meta ? 'Cmd' : 'Ctrl'}+${key}`);
            event.preventDefault();
            lockdownWindow.webContents.send('proctoring-violation', 'Copy/paste/cut actions are disabled.');
            return;
        }

        // Block Alt+Tab, Alt+F4, Ctrl+Shift+Esc, Windows Key (Meta), etc.
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
// ** MODIFIED: Start with system check window **
app.whenReady().then(createSystemCheckWindow);

app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });

app.on('activate', () => {
    // On macOS, re-create the right window if none exist
    if (BrowserWindow.getAllWindows().length === 0) {
        if (!currentToken) {
            createSystemCheckWindow(); // Start from scratch
        }
        // If test was in progress, this logic would need to be more complex
        // For now, we just restart the flow.
    }
});
// --- End App Lifecycle ---

// --- NEW IPC Handlers for System Check ---

ipcMain.on('system-check-passed', () => {
    console.log('[IPC] System check passed.');
    if (systemCheckWindow) {
        systemCheckWindow.close();
        systemCheckWindow = null;
    }
    createTokenWindow(); // Proceed to token entry
});

ipcMain.on('quit-app', () => {
    console.log('[IPC] Quit app requested from system check.');
    app.quit();
});

ipcMain.handle('check-running-apps', () => {
    console.log('[IPC check-running-apps] Checking for forbidden applications...');
    return new Promise((resolve) => {
        const platform = process.platform;
        let cmd = '';
        let forbiddenList = [];
        const appName = app.getName(); // Get the name of *this* app
        console.log(`[check-running-apps] Current app name: "${appName}"`); // Log the app name for debugging

        if (platform === 'win32') {
            // ** MODIFICATION: Use full path to bypass PATH issues **
            // %WINDIR% is an environment variable (e.g., C:\Windows)
            cmd = '"%WINDIR%\\System32\\tasklist.exe" /FO CSV /NH';
            forbiddenList = FORBIDDEN_APPS_WINDOWS;
        } else if (platform === 'darwin') {
            cmd = 'ps -ax -o comm';
            forbiddenList = FORBIDDEN_APPS_MACOS;
        } else {
            console.warn('[check-running-apps] Unsupported platform for app check.');
            return resolve({ forbiddenApps: [] }); // Unsupported, so pass
        }

        exec(cmd, (err, stdout, stderr) => {
            if (err) {
                console.error('[check-running-apps] Error executing task list:', err);
                // ** MODIFICATION: Pass the actual error message back **
                return resolve({ error: `Could not check running apps. OS Error: ${err.message}` });
            }

            const runningApps = stdout.toLowerCase();
            const foundApps = [];

            forbiddenList.forEach(appNameForbidden => {
                // Check if the forbidden app is in the task list
                if (runningApps.includes(appNameForbidden.toLowerCase())) {
                    // CRITICAL: Make sure it's not *this* app
                    // (e.g., if appName is 'ms-teams' and forbidden is 'ms-teams')
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

ipcMain.handle('check-screen-recording', () => {
    console.log('[IPC check-screen-recording] Checking media access...');
    let isRecording = false;
    let reason = 'No active screen recording detected.';

    if (process.platform === 'darwin') {
        const status = systemPreferences.getMediaAccessStatus('screen');
        console.log(`[check-screen-recording] macOS screen capture status: ${status}`);
        if (status === 'granted') {
            // This just means an app *has* permission, not that it *is* recording.
            // A running app check is more effective.
            // For the demo, we'll flag 'granted' as a potential issue.
            isRecording = true;
            reason = 'An application has screen recording permissions. Please disable it in System Settings > Security & Privacy.';
        } else if (status === 'denied' || status === 'not-determined') {
            isRecording = false;
        }
    } else if (process.platform === 'win32') {
        // No direct API on Windows.
        // This check relies on the forbidden app list.
        // setContentProtection() is the real security here.
        console.log('[check-screen-recording] Windows: Relying on app check and content protection.');
        isRecording = false;
    }

    return { isRecording, reason };
});

// --- End NEW System Check IPC ---


// --- Existing IPC Handlers (Modified `validate-token` and `submit-verification-details`) ---
ipcMain.handle('get-env', () => {
    console.log(`[IPC get-env] Providing environment. isDev: ${isDev}, BACKEND_URL: ${BACKEND_URL}`);
    return { isDev: isDev, BACKEND_URL: BACKEND_URL };
});

ipcMain.handle('validate-token', async (event, token) => {
    console.log(`[IPC validate-token] Received token: ${token ? '******' : '<empty>'}`);
    if (!token) return { isValid: false, error: 'Token cannot be empty.' };
    try {
        const response = await fetch(`${BACKEND_URL}/api/public/test-details`, { headers: { 'x-auth-token': token } });
        const data = await response.json();
        if (!response.ok) throw new Error(data?.message || `Validation failed (Status: ${response.status})`);

        console.log(`[IPC validate-token] SUCCESS. Token valid for test: ${data?.title}`);
        validatedTestData = data; // Store the fetched test data
        currentToken = token;

        // Close token window, create lockdown window
        const currentWin = BrowserWindow.fromWebContents(event.sender);
        if (currentWin) {
            currentWin.close();
            mainWindow = null; // Clear reference
        } else {
            console.warn('[IPC validate-token] Could not find token window to close.');
        }

        // Create the NEW secure window
        mainWindow = createLockdownWindow();

        console.log('[IPC validate-token] Loading candidate verification page...');
        await mainWindow.loadFile('candidate-verification.html');

        return { isValid: true, error: null };

    } catch (error) {
        console.error('[IPC validate-token] Error:', error);
        validatedTestData = null; currentToken = null;
        return { isValid: false, error: error.message || 'Network error or invalid response during validation.' };
    }
});


ipcMain.handle('get-initial-verification-data', (event) => {
    console.log('[IPC get-initial-verification-data] Providing token and test details.');
    if (!mainWindow || event.sender !== mainWindow.webContents) { console.warn('[IPC get-initial-verification-data] Unauthorized request origin.'); return null; }
    // Send the test data fetched during token validation
    return { token: currentToken, testDetails: validatedTestData };
});

ipcMain.handle('upload-photo', async (event, imageDataUrl) => {
    console.log('[IPC upload-photo] Received photo upload request...');
    if (!mainWindow || event.sender !== mainWindow.webContents) { console.warn('[IPC upload-photo] Unauthorized request origin.'); return { success: false, error: "Unauthorized request origin." }; }
    if (!imageDataUrl || !imageDataUrl.startsWith('data:image/jpeg;base64,')) return { success: false, error: "Invalid image data format." };
    try {
        const response = await fetch(`${BACKEND_URL}/api/public/upload-image`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ imageData: imageDataUrl }) });
        const result = await response.json(); if (!response.ok) throw new Error(result.message || `Backend upload failed (Status: ${response.status})`);
        console.log('[IPC upload-photo] Backend upload successful. URL:', result.imageUrl);
        return { success: true, imageUrl: result.imageUrl };
    } catch (error) { console.error('[IPC upload-photo] Error during upload:', error); return { success: false, error: error.message || "Server error during upload." }; }
});

ipcMain.handle('fetch-colleges', async (event, testId) => {
    console.log(`[IPC fetch-colleges] Request for testId: ${testId}`);
    if (!mainWindow || event.sender !== mainWindow.webContents) { console.warn('[IPC fetch-colleges] Unauthorized request origin.'); return { success: false, error: "Unauthorized request." }; }
    if (!testId) return { success: false, error: "Test ID is required." };
    try {
        const response = await fetch(`${BACKEND_URL}/api/public/colleges/${testId}`); const data = await response.json();
        if (!response.ok) throw new Error(data.message || `Failed to fetch colleges (Status: ${response.status})`);
        console.log(`[IPC fetch-colleges] Fetched ${data.length} colleges.`); return { success: true, colleges: data };
    } catch (error) { console.error('[IPC fetch-colleges] Error:', error); return { success: false, error: error.message || 'Server error fetching colleges.' }; }
});

// --- THIS IS THE UPDATED HANDLER ---
ipcMain.handle('submit-verification-details', async (event, receivedToken, details) => {
    console.log('[IPC submit-verification-details] Received details:', details);
    if (!mainWindow || event.sender !== mainWindow.webContents) { console.warn('[IPC submit-verification-details] Unauthorized request origin.'); return { success: false, error: "Unauthorized request." }; }
    if (receivedToken !== currentToken) { console.error('[IPC submit-verification-details] Token mismatch!'); return { success: false, error: "Token mismatch error." }; }
    if (!details || !validatedTestData) { console.error('[IPC submit-verification-details] Missing details or original test data.'); return { success: false, error: "Internal error: Missing data." }; }
    try { // Save Initial Details
        const assignmentId = validatedTestData?.assignmentId; if (!assignmentId) throw new Error("Missing assignment ID.");
        const saveResponse = await fetch(`${BACKEND_URL}/api/save-initial-details`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-auth-token': currentToken }, body: JSON.stringify({ details }) });
        const saveResult = await saveResponse.json(); if (!saveResponse.ok) throw new Error(saveResult.message || `Backend save failed (Status: ${saveResponse.status})`);
        console.log('[IPC submit-verification-details] Backend saved initial details successfully.');
    } catch (saveError) { console.error('[IPC submit-verification-details] Error saving initial details:', saveError); dialog.showErrorBox('Initialization Error', `Failed to save verification details: ${saveError.message}. Please restart.`); return { success: false, error: `Save failed: ${saveError.message}` }; }
    try { // Load Test Page
        // --- MODIFIED CHECK ---
        // Check if validatedTestData has a 'sections' array with at least one section,
        // AND that the first section has a 'problems' array with at least one problem.
        // This robustly identifies a coding test with the new structure.
        const isCodingTest = !!(
            validatedTestData &&
            Array.isArray(validatedTestData.sections) &&
            validatedTestData.sections.length > 0 &&
            validatedTestData.sections[0].problems && // Check if the first section has problems array
            Array.isArray(validatedTestData.sections[0].problems) &&
            validatedTestData.sections[0].problems.length > 0
        );
        console.log(`[IPC submit-verification-details] isCodingTest evaluated to: ${isCodingTest}`); // Log the result of the check

        const testPage = isCodingTest ? 'hiring-coding-test.html' : 'hiring-test.html';
        // --- END MODIFIED CHECK ---

        console.log(`[IPC submit-verification-details] Loading page: ${testPage}`); await mainWindow.loadFile(testPage);
        console.log(`[IPC submit-verification-details] Test page ${testPage} loaded.`); return { success: true };
    } catch (loadError) { console.error(`[IPC submit-verification-details] Error loading test page:`, loadError); dialog.showErrorBox('Loading Error', `Failed to load the test page: ${loadError.message}. Please restart.`); return { success: false, error: `Load failed: ${loadError.message}` }; }
});
// --- END OF UPDATED HANDLER ---


ipcMain.handle('get-validated-token', (event) => {
    if (!mainWindow || event.sender !== mainWindow.webContents) { console.warn('[IPC get-validated-token] Unauthorized request origin.'); return null; }
    console.log('[IPC get-validated-token] Providing token to test page.'); return currentToken;
});

ipcMain.on('test-submitted-successfully', (event) => {
    if (!mainWindow || event.sender !== mainWindow.webContents) { console.warn('[IPC test-submitted-successfully] Unauthorized signal origin.'); return; }
    console.log('[IPC test-submitted-successfully] Signal received. Quitting application.');
    isTestSubmitted = true;
    app.quit();
});
// --- End IPC Handlers ---

// --- IPC Handlers ---

// **MODIFIED**: getEnv now only returns isDev, BACKEND_URL is fixed above
ipcMain.handle('get-env', () => {
    console.log(`[IPC get-env] Providing environment. isDev: ${isDev}`);
    // No longer needs to return BACKEND_URL as it's fixed in both main and renderer
    return { isDev: isDev };
});

// The rest of the IPC handlers use the fixed BACKEND_URL constant defined above
// ... rest of main.js ...

