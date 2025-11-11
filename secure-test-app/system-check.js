document.addEventListener('DOMContentLoaded', () => {
    const statusMessage = document.getElementById('status-message');
    const resultsArea = document.getElementById('results-area');
    const failureBox = document.getElementById('failure-box');
    const failureReason = document.getElementById('failure-reason');
    const successBox = document.getElementById('success-box');
    const quitBtn = document.getElementById('quit-btn');
    const retryBtn = document.getElementById('retry-btn');
    const startBtn = document.getElementById('start-btn'); // Added
    const buttonContainer = document.getElementById('button-container');
    const checkItemsContainer = document.getElementById('check-items-container'); // Added

    // Check item elements
    const checkCameraEl = document.getElementById('check-camera');
    const checkMicEl = document.getElementById('check-mic');
    const checkAppsEl = document.getElementById('check-apps');
    const checkRecordingEl = document.getElementById('check-recording');
    const allCheckItems = [checkCameraEl, checkMicEl, checkAppsEl, checkRecordingEl];

    // --- Helper to update check status UI ---
    function updateCheckUI(element, status, message = '') {
        const iconContainer = element.querySelector('.check-icon');
        
        let iconHtml;
        if (status === 'success') {
            iconHtml = '<i class="fas fa-check-circle text-green-500"></i>';
            element.classList.replace('bg-gray-50', 'bg-green-50');
            element.classList.replace('border-gray-200', 'border-green-200');
        } else if (status === 'fail') {
            iconHtml = '<i class="fas fa-times-circle text-red-500"></i>';
            element.classList.replace('bg-gray-50', 'bg-red-50');
            element.classList.replace('border-gray-200', 'border-red-200');
            const span = element.querySelector('span');
            span.title = message; // Add tooltip for failure reason
        } else { // 'running'
            iconHtml = '<i class="fas fa-spinner fa-spin text-gray-400"></i>';
            element.classList.replace('bg-green-50', 'bg-gray-50');
            element.classList.replace('bg-red-50', 'bg-gray-50');
            element.classList.replace('border-green-200', 'border-gray-200');
            element.classList.replace('border-red-200', 'border-gray-200');
        }
        iconContainer.innerHTML = iconHtml;
    }

    // --- Check Functions ---
    async function checkCamera() {
        try {
            const stream = await navigator.mediaDevices.getUserMedia({ video: true });
            stream.getTracks().forEach(track => track.stop()); // Stop immediately
            updateCheckUI(checkCameraEl, 'success');
            return true;
        } catch (err) {
            console.error('Camera check failed:', err);
            updateCheckUI(checkCameraEl, 'fail', 'Camera access denied or no camera found.');
            return false;
        }
    }

    async function checkMicrophone() {
        try {
            const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
            stream.getTracks().forEach(track => track.stop()); // Stop immediately
            updateCheckUI(checkMicEl, 'success');
            return true;
        } catch (err) {
            console.error('Mic check failed:', err);
            updateCheckUI(checkMicEl, 'fail', 'Microphone access denied or no microphone found.');
            return false;
        }
    }

    async function checkRunningApps() {
        try {
            // Mock electronAPI if it doesn't exist (for browser testing)
            if (typeof window.electronAPI === 'undefined') {
                console.warn('window.electronAPI is not defined. Mocking success for app check.');
                await new Promise(resolve => setTimeout(resolve, 500)); // Simulate async work
                updateCheckUI(checkAppsEl, 'success');
                return { pass: true };
                // To test failure:
                // updateCheckUI(checkAppsEl, 'fail', 'Please close: MockApp.exe');
                // return { pass: false, reason: `Please close the following application(s):<br><b>MockApp.exe</b>` };
            }

            const result = await window.electronAPI.checkRunningApps();
            if (result.error) throw new Error(result.error);
            if (result.forbiddenApps.length > 0) {
                const appNames = result.forbiddenApps.join(', ');
                updateCheckUI(checkAppsEl, 'fail', `Please close: ${appNames}`);
                return { pass: false, reason: `Please close the following application(s):<br><b>${appNames}</b>` };
            }
            updateCheckUI(checkAppsEl, 'success');
            return { pass: true };
        } catch (err) {
            console.error('App check failed:', err);
            const specificError = err.message || 'Failed to scan for conflicting applications.';
            updateCheckUI(checkAppsEl, 'fail', specificError);
            return { pass: false, reason: specificError };
        }
    }

    async function checkScreenRecording() {
        try {
            // Mock electronAPI if it doesn't exist (for browser testing)
            if (typeof window.electronAPI === 'undefined') {
                console.warn('window.electronAPI is not defined. Mocking success for recording check.');
                await new Promise(resolve => setTimeout(resolve, 500)); // Simulate async work
                updateCheckUI(checkRecordingEl, 'success');
                return { pass: true };
                // To test failure:
                // updateCheckUI(checkRecordingEl, 'fail', 'Screen recording detected.');
                // return { pass: false, reason: 'Active screen recording was detected.' };
            }

            const result = await window.electronAPI.checkScreenRecording();
            if (result.isRecording) {
                updateCheckUI(checkRecordingEl, 'fail', result.reason);
                return { pass: false, reason: result.reason };
            }
            updateCheckUI(checkRecordingEl, 'success');
            return { pass: true };
        } catch (err) {
            console.error('Recording check failed:', err);
            updateCheckUI(checkRecordingEl, 'fail', 'Could not check screen recording status.');
            return { pass: false, reason: 'Failed to scan for screen recording software.' };
        }
    }

    // --- Main Execution ---
    async function runAllChecks() {
        // Reset UI for retry
        statusMessage.textContent = 'Running system checks...';
        statusMessage.classList.replace('text-green-600', 'text-gray-500');
        failureBox.classList.add('hidden');
        successBox.classList.add('hidden');
        buttonContainer.classList.add('hidden'); // Hide all buttons during check
        checkItemsContainer.classList.remove('hidden'); // Ensure checks are visible
        
        allCheckItems.forEach(el => updateCheckUI(el, 'running'));

        // Run checks
        const camPass = await checkCamera();
        const micPass = await checkMicrophone();
        const appResult = await checkRunningApps();
        const recordingResult = await checkScreenRecording();

        const allPassed = camPass && micPass && appResult.pass && recordingResult.pass;

        resultsArea.classList.remove('hidden');
        if (allPassed) {
            statusMessage.textContent = 'All checks passed!';
            statusMessage.classList.replace('text-gray-500', 'text-green-600');
            successBox.classList.remove('hidden');
            // All good, notify main process to proceed
            // Mock electronAPI if it doesn't exist
            if (typeof window.electronAPI !== 'undefined') {
                setTimeout(() => {
                    window.electronAPI.notifySystemCheckPassed();
                }, 1500); // Wait 1.5s to show success
            } else {
                console.log('Mock: Notifying main process to proceed.');
            }
        } else {
            statusMessage.textContent = 'System check failed.';
            // Build error message
            let errorMsg = 'Please resolve the following issues:';
            if (!camPass) errorMsg += '<br>• Camera access is required.';
            if (!micPass) errorMsg += '<br>• Microphone access is required.';
            if (!appResult.pass) errorMsg += `<br>• ${appResult.reason}`;
            if (!recordingResult.pass) errorMsg += `<br>• ${recordingResult.reason}`;
            
            failureReason.innerHTML = errorMsg;
            failureBox.classList.remove('hidden');
            
            // Show buttons
            buttonContainer.classList.remove('hidden');
            startBtn.classList.add('hidden'); // Ensure start is hidden
            quitBtn.classList.remove('hidden');
            retryBtn.classList.remove('hidden');
        }
    }

    // --- Event Listeners ---
    quitBtn.addEventListener('click', () => {
        // Mock electronAPI if it doesn't exist
        if (typeof window.electronAPI !== 'undefined') {
            window.electronAPI.quitApp();
        } else {
            console.log('Mock: Quitting application.');
            // Replaced alert with console log
        }
    });

    retryBtn.addEventListener('click', () => {
        runAllChecks();
    });

    // Added Start Button Listener
    startBtn.addEventListener('click', () => {
        // No need to hide startBtn here, runAllChecks hides the whole container
        runAllChecks();
    });

    // CRITICAL FIX: Removed the automatic runAllChecks() call from here.
});

