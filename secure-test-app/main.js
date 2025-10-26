// main.js
const { app, BrowserWindow, ipcMain, screen, dialog } = require('electron');
const path = require('path');
const fetch = require('node-fetch'); // Use require for node-fetch v2

let mainWindow;
let validatedTestData = null; // Store the full test details after validation
let currentToken = null; // Store the validated token
let isTestSubmitted = false; // --- NEW FLAG to allow closing ---

// --- !!! DYNAMIC URL & ENVIRONMENT !!! ---
// isDev will be TRUE when you run `npm start` (app is not packaged)
// isDev will be FALSE when you run the final .exe (app is packaged)
const isDev = !app.isPackaged;

// Set the backend URL based on the environment
const BACKEND_URL = isDev
    ? 'http://localhost:3000'         // Use localhost for development (`npm start`)
    : 'https://www.testify-lac.com'; // Use live URL for production (the built .exe)
// --- !!! END OF DYNAMIC URL & ENVIRONMENT !!! ---


// --- !!! KEY CHANGE !!! ---
// The `isDev` variable now dynamically controls lockdown.
// It is no longer forced to `false`.
// const isDev = false; // !app.isPackaged; // <-- This hardcoded line is replaced by the logic above
// --- !!! END OF KEY CHANGE !!! ---


// --- !!! NEW FUNCTION TO CREATE THE SECURE WINDOW !!! ---
function createLockdownWindow() {
    const primaryDisplay = screen.getPrimaryDisplay();
    const { width, height } = primaryDisplay.workAreaSize;

    console.log('[Lockdown] Creating secure lockdown window.');

    // Create the window with lockdown settings from the start
    const lockdownWindow = new BrowserWindow({
        width: width,
        height: height,
        fullscreen: true,
        kiosk: true,
        frame: false,
        resizable: false,
        movable: false,
        minimizable: false,
        // --- MODIFIED: Allow window to be closable ---
        closable: true, // We will block this with an event listener
        // --- END MODIFICATION ---
        alwaysOnTop: true,
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            nodeIntegration: false,
            contextIsolation: true,
            devTools: isDev, // This will now be TRUE during `npm start`
            sandbox: !isDev, // This will be TRUE in the final .exe
            webSecurity: true,
        }
    });

    // --- Relax settings IF in development mode for debugging ---
    // This block will NOW RUN when you use `npm start`
    if (isDev) {
        console.log("[Dev Mode] Relaxing lockdown for debugging.");
        lockdownWindow.setKiosk(false); // Allow exiting kiosk in dev
        lockdownWindow.setAlwaysOnTop(false);
        lockdownWindow.setClosable(true);
        lockdownWindow.webContents.openDevTools();
    }
    
    // --- Attach all lockdown listeners to the new window ---
    lockdownWindow.setMenu(null); // Remove menu

    lockdownWindow.on('close', (e) => {
        // --- This logic now correctly blocks unauthorized closes ---
        // In dev (isDev=true), it will return (allowing close)
        // In prod (isDev=false), it will check isTestSubmitted
        if (isDev || isTestSubmitted) return; // Allow close if dev or test submitted
        // --- END MODIFICATION ---

        console.log('[Lockdown] Window close attempt prevented.');
        e.preventDefault(); // Prevent closing
        lockdownWindow.webContents.send('proctoring-violation', 'Attempted to close the test window.');
    });

    lockdownWindow.on('blur', () => {
        if (isDev) return; // This will be skipped in dev
        console.log('[Lockdown] Window lost focus. Triggering violation.');
        lockdownWindow.flashFrame(true);
        lockdownWindow.webContents.send('proctoring-violation', 'Window lost focus. Attempts to switch applications are monitored.');
        lockdownWindow.focus();
    });

    lockdownWindow.on('leave-full-screen', () => {
        if (isDev) return; // This will be skipped in dev
        console.log('[Lockdown] Attempted to leave full-screen. Re-entering and triggering violation.');
        lockdownWindow.setKiosk(true);
        lockdownWindow.webContents.send('proctoring-violation', 'Exiting full-screen mode is not allowed during the test.');
    });

    lockdownWindow.webContents.on('before-input-event', (event, input) => {
        
        // --- !!! NEW SECRET ESCAPE HATCH !!! ---
        // Press Ctrl+Shift+Alt+Q to force quit the app during locked-down testing
        if (input.control && input.shift && input.alt && input.key.toLowerCase() === 'q') {
            console.log('!!! SECRET ESCAPE HATCH ACTIVATED. QUITTING. !!!');
            app.quit();
            return;
        }
        // --- !!! END ESCAPE HATCH !!! ---

        if (isDev) return; // This will be skipped in dev, allowing copy/paste etc.

        const isShortcut = (input.control || input.meta) && !input.alt && !input.shift;
        const key = input.key.toLowerCase();

        // Block Ctrl+C, Ctrl+V, Ctrl+X
        if (isShortcut && (key === 'c' || key === 'v' || key === 'x')) {
            console.log(`[Lockdown] Blocked shortcut: ${input.meta ? 'Cmd' : 'Ctrl'}+${key}`);
            event.preventDefault();
            lockdownWindow.webContents.send('proctoring-violation', 'Copy/paste/cut actions are disabled.');
        }

        // Block Alt+Tab, Alt+F4, Ctrl+Shift+Esc, Windows Key, etc.
        if (input.alt || input.meta || (input.control && input.shift && key === 'escape')) {
            console.log(`[Lockdown] Blocked system shortcut attempt.`);
            event.preventDefault();
            lockdownWindow.webContents.send('proctoring-violation', 'System shortcuts are disabled.');
        }
    });

    return lockdownWindow; // Return the new window
}
// --- !!! END OF NEW FUNCTION !!! ---


// --- MODIFIED: This function now *only* creates the initial token window ---
function createWindow() {
    console.log('[Startup] Creating initial token entry window.');
    mainWindow = new BrowserWindow({
        width: 800,
        height: 600,
        center: true,
        frame: true, // Show frame for token entry
        resizable: isDev, // This will now be TRUE during `npm start`
        movable: true,
        minimizable: true,
        closable: true,
        alwaysOnTop: false, // Not always on top for token entry
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            nodeIntegration: false,
            contextIsolation: true,
            devTools: isDev, // This will now be TRUE during `npm start`
            sandbox: !isDev, // This will be TRUE in the final .exe
            webSecurity: true,
        }
    });
    // --- END OF MODIFICATION ---

    // This block is still useful for debugging the *initial* window
    // This block will NOW RUN when you use `npm start`
    if (isDev) {
        mainWindow.webContents.openDevTools();
    }
    
    // Load the initial token entry page
    mainWindow.loadFile('token-entry.html');

    // Remove default menu (disables copy/paste from menu, but not shortcuts)
    mainWindow.setMenu(null);

    // --- All strict lockdown handlers have been MOVED to createLockdownWindow() ---
}

// --- App Lifecycle ---
app.whenReady().then(createWindow); // Start with the token window
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });

// --- IPC Handlers ---

// Handle Token Validation (from token-entry.js)
ipcMain.handle('validate-token', async (event, token) => {
    console.log(`[IPC validate-token] Received token: ${token ? '******' : '<empty>'}`);
    if (!token) return { isValid: false, error: 'Token cannot be empty.' };

    try {
        const response = await fetch(`${BACKEND_URL}/api/public/test-details`, {
            headers: { 'x-auth-token': token }
        });
        const data = await response.json();

        if (!response.ok) {
            console.error(`[IPC validate-token] Backend validation failed (Status: ${response.status}):`, data.message);
            throw new Error(data?.message || `Validation failed (Status: ${response.status})`);
        }

        console.log(`[IPC validate-token] SUCCESS. Token valid for test: ${data?.title}`);
        validatedTestData = data; // Store the full test details
        currentToken = token; // Store the valid token

        // --- !!! KEY CHANGE HERE !!! ---
        // Close the old window and create the new lockdown window
        console.log('[IPC validate-token] Closing token window and creating lockdown window...');
        if (mainWindow) {
            mainWindow.close();
        }
        mainWindow = createLockdownWindow(); // Create the new secure window
        // --- !!! END OF KEY CHANGE !!! ---


        // Load the candidate verification page AFTER successful validation
        console.log('[IPC validate-token] Loading candidate verification page...');
        await mainWindow.loadFile('candidate-verification.html');

        return { isValid: true, error: null }; // Signal success to renderer

    } catch (error) {
        console.error('[IPC validate-token] Error:', error);
        // Reset state on error
        validatedTestData = null;
        currentToken = null;
        return { isValid: false, error: error.message || 'Network error or invalid response during validation.' };
    }
});

// Provide initial data (token, testDetails) to verification page
ipcMain.handle('get-initial-verification-data', (event) => {
    console.log('[IPC get-initial-verification-data] Providing token and test details.');
    if (event.sender !== mainWindow.webContents) return null; // Security check
    // Return the stored token and test details
    return { token: currentToken, testDetails: validatedTestData };
});

// Handle photo upload (proxied through main process)
ipcMain.handle('upload-photo', async (event, imageDataUrl) => {
    console.log('[IPC upload-photo] Received photo upload request...');
    if (event.sender !== mainWindow.webContents) return { success: false, error: "Unauthorized request origin." };
    if (!imageDataUrl || !imageDataUrl.startsWith('data:image/jpeg;base64,')) {
        return { success: false, error: "Invalid image data format." };
    }
    try {
        console.log('[IPC upload-photo] Forwarding upload to backend...');
        const response = await fetch(`${BACKEND_URL}/api/public/upload-image`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ imageData: imageDataUrl })
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.message || `Backend upload failed (Status: ${response.status})`);
        console.log('[IPC upload-photo] Backend upload successful. URL:', result.imageUrl);
        return { success: true, imageUrl: result.imageUrl };
    } catch (error) {
        console.error('[IPC upload-photo] Error during upload:', error);
        return { success: false, error: error.message || "Server error during upload." };
    }
});

// Handle fetching colleges (proxied)
ipcMain.handle('fetch-colleges', async (event, testId) => {
     console.log(`[IPC fetch-colleges] Request for testId: ${testId}`);
     if (event.sender !== mainWindow.webContents) return { success: false, error: "Unauthorized request." };
     if (!testId) return { success: false, error: "Test ID is required." };
     try {
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

// Handle submission of verification details (from candidate-verification.js)
ipcMain.handle('submit-verification-details', async (event, receivedToken, details) => {
    console.log('[IPC submit-verification-details] Received details:', details);
    if (event.sender !== mainWindow.webContents) return { success: false, error: "Unauthorized request." };
    if (receivedToken !== currentToken) {
        console.error('[IPC submit-verification-details] Token mismatch!');
        return { success: false, error: "Token mismatch error." };
    }
    if (!details || !validatedTestData) {
        console.error('[IPC submit-verification-details] Missing details or original test data.');
        return { success: false, error: "Internal error: Missing data." };
    }

    // --- Save Initial Details to Backend ---
    try {
        console.log('[IPC submit-verification-details] Saving initial details to backend...');
        const assignmentId = validatedTestData?.assignmentId; // Get assignmentId from the fetched test data
        if (!assignmentId) {
             console.error('[IPC submit-verification-details] Critical Error: assignmentId missing from validatedTestData!');
             throw new Error("Missing assignment ID. Cannot save initial details.");
        }

        const saveResponse = await fetch(`${BACKEND_URL}/api/save-initial-details`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'x-auth-token': currentToken },
            body: JSON.stringify({ /* No need for assignmentId here, token provides it */ details })
        });
        const saveResult = await saveResponse.json();
        if (!saveResponse.ok) throw new Error(saveResult.message || `Backend failed to save details (Status: ${saveResponse.status})`);
        console.log('[IPC submit-verification-details] Backend saved initial details successfully.');

    } catch (saveError) {
         console.error('[IPC submit-verification-details] Error saving initial details to backend:', saveError);
         dialog.showErrorBox('Initialization Error', `Failed to save verification details: ${saveError.message}. Please restart.`);
         // Consider app.quit() if saving is critical before starting test
         return { success: false, error: `Failed to save verification details: ${saveError.message}` };
    }

    // --- Load the Correct Test Page ---
    try {
        // Determine test type based on presence of 'problems' (coding) vs 'sections' (aptitude)
        // This relies on your backend sending distinct structures for each test type.
        const isCodingTest = !!(validatedTestData.problems && Array.isArray(validatedTestData.problems) && validatedTestData.problems.length > 0);
        const testPage = isCodingTest ? 'hiring-coding-test.html' : 'hiring-test.html';

        console.log(`[IPC submit-verification-details] Determined test type: ${isCodingTest ? 'Coding' : 'Aptitude'}. Loading page: ${testPage}`);
        await mainWindow.loadFile(testPage);
        console.log(`[IPC submit-verification-details] Test page ${testPage} loaded successfully.`);
        return { success: true }; // Signal success to renderer

    } catch (loadError) {
         console.error(`[IPC submit-verification-details] Error loading test page:`, loadError);
         dialog.showErrorBox('Loading Error', `Failed to load the test page: ${loadError.message}. Please restart.`);
         // Consider app.quit() on critical load failure
         return { success: false, error: `Failed to load the test page: ${loadError.message}` };
    }
});

// Provide the validated token TO the actual test page (hiring-test.html or hiring-coding-test.html)
ipcMain.handle('get-validated-token', (event) => {
    if (event.sender !== mainWindow.webContents) return null;
    console.log('[IPC get-validated-token] Providing token to test page.');
    return currentToken; // Send the stored token
});

// Handle signal from renderer that test was submitted successfully
ipcMain.on('test-submitted-successfully', () => {
    console.log('[IPC test-submitted-successfully] Signal received. Quitting application.');
    // --- MODIFIED: Set the flag BEFORE quitting ---
    isTestSubmitted = true;
    // --- END MODIFICATION ---
    app.quit();
});



