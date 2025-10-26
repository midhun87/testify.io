const { contextBridge, ipcRenderer } = require('electron');

console.log('Preload script loaded.'); // Log when preload starts

contextBridge.exposeInMainWorld('electronAPI', {
    // --- Token Entry Page Functions ---
    validateToken: (token) => ipcRenderer.invoke('validate-token', token),
    // ** NEW: Get initial data for verification page **
    getInitialVerificationData: () => ipcRenderer.invoke('get-initial-verification-data'),
    // ** NEW: Upload photo via main process **
    uploadPhoto: (imageDataUrl) => ipcRenderer.invoke('upload-photo', imageDataUrl),
     // ** NEW: Fetch colleges via main process **
    fetchColleges: (testId) => ipcRenderer.invoke('fetch-colleges', testId),
    // ** NEW: Submit final verification details **
    submitVerificationDetails: (token, details) => ipcRenderer.invoke('submit-verification-details', token, details),

    // --- Test Page Functions ---
    getValidatedToken: () => ipcRenderer.invoke('get-validated-token'),
    onProctoringViolation: (callback) => ipcRenderer.on('proctoring-violation', (event, message) => callback(message)),
    notifyTestSubmitted: () => ipcRenderer.send('test-submitted-successfully')
});

console.log('electronAPI exposed to main world.'); // Log successful exposure

