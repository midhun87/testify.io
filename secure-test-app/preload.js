const { contextBridge, ipcRenderer } = require('electron');

console.log('[Preload] Script executing...'); // Log start

contextBridge.exposeInMainWorld('electronAPI', {
    // --- Generic Functions ---
    getEnv: () => ipcRenderer.invoke('get-env'), // Needed by test pages

    // --- System Check Functions ---
    checkRunningApps: () => ipcRenderer.invoke('check-running-apps'),
    checkScreenRecording: () => ipcRenderer.invoke('check-screen-recording'),
    notifySystemCheckPassed: () => ipcRenderer.send('system-check-passed'),
    quitApp: () => ipcRenderer.send('quit-app'),

    // --- Token Entry Page Functions ---
    validateToken: (token) => ipcRenderer.invoke('validate-token', token),

    // --- Verification Page Functions ---
    getInitialVerificationData: () => ipcRenderer.invoke('get-initial-verification-data'),
    uploadPhoto: (imageDataUrl) => ipcRenderer.invoke('upload-photo', imageDataUrl),
    fetchColleges: (testId) => ipcRenderer.invoke('fetch-colleges', testId),
    submitVerificationDetails: (token, details) => ipcRenderer.invoke('submit-verification-details', token, details),

    // --- Test Page Functions ---
    getValidatedToken: () => ipcRenderer.invoke('get-validated-token'), // Needed by test pages
    onProctoringViolation: (callback) => ipcRenderer.on('proctoring-violation', (_event, value) => callback(value)), // Renamed event for clarity
    notifyTestSubmitted: () => ipcRenderer.send('test-submitted-successfully')
});

console.log('[Preload] electronAPI exposed to main world.'); // Log success

