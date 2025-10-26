document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Elements ---
    const form = document.getElementById('candidate-details-form');
    const collegeSelect = document.getElementById('college-select');
    const cameraFeed = document.getElementById('camera-feed');
    const capturedPhoto = document.getElementById('captured-photo');
    const cameraPlaceholder = document.getElementById('camera-placeholder');
    const cameraPlaceholderText = document.getElementById('camera-placeholder-text');
    const captureCanvas = document.getElementById('capture-canvas');
    const captureBtn = document.getElementById('capture-btn');
    const recaptureBtn = document.getElementById('recapture-btn');
    const cameraError = document.getElementById('camera-error');
    const startTestBtn = document.getElementById('start-test-btn');
    const startBtnText = document.getElementById('start-btn-text');
    const startSpinner = document.getElementById('start-spinner');
    const formErrorMessage = document.getElementById('form-error-message');
    const messageContainer = document.getElementById('message-box-container');
    const uploadProgress = document.getElementById('upload-progress');

    // --- State ---
    let capturedImageData = null;
    let cameraStream = null;
    let testDetails = null; // Store test details fetched by main process
    let token = null; // Store the original token

    // --- Utility: Show Message ---
    function showMessage(message, type = 'error', duration = 4000) {
        // ... (same showMessage function as before) ...
         const box = document.createElement('div');
         box.textContent = message;
         box.className = `message-box ${type}`;
         messageContainer.appendChild(box);
         requestAnimationFrame(() => { box.classList.add('show'); });
         setTimeout(() => {
             box.classList.remove('show');
             box.addEventListener('transitionend', () => box.remove(), { once: true });
         }, duration);
    }

    // --- Camera Logic --- (Mostly copied from original test page)
    async function startCamera() {
        // Reset UI
        cameraFeed.classList.remove('hidden');
        capturedPhoto.classList.add('hidden');
        cameraPlaceholder.classList.remove('show');
        cameraError.classList.add('hidden');
        captureBtn.disabled = true;
        captureBtn.classList.remove('hidden');
        recaptureBtn.classList.add('hidden');
        uploadProgress.classList.add('hidden');

        try {
            if (cameraStream) cameraStream.getTracks().forEach(track => track.stop());
            console.log("[VERIFY CAMERA] Requesting camera access...");
            if (!navigator.mediaDevices?.getUserMedia) throw new Error("Camera access not supported.");

            cameraStream = await navigator.mediaDevices.getUserMedia({ video: true });
            console.log("[VERIFY CAMERA] Access granted.");
            cameraFeed.srcObject = cameraStream;

            await new Promise((resolve, reject) => {
                cameraFeed.onloadedmetadata = () => {
                     console.log("[VERIFY CAMERA] Metadata loaded.");
                     cameraFeed.play().then(resolve).catch(reject);
                };
                cameraFeed.onerror = (e) => reject(new Error("Video element error"));
                cameraFeed.onplaying = () => {
                     console.log("[VERIFY CAMERA] Video stream playing.");
                     resolve();
                 };
                 setTimeout(() => reject(new Error("Camera playback timed out")), 5000);
            });
             captureBtn.disabled = false;

        } catch (e) {
            console.error("[VERIFY CAMERA ERROR]", e.name, e.message);
            let userMsg = 'Camera access is required.', phMsg = 'Camera Error';
            if (e.name === 'NotAllowedError') { userMsg = 'Camera permission denied.'; phMsg = 'Permission Denied';}
            else if (e.name === 'NotFoundError') { userMsg = 'No camera found.'; phMsg = 'No Camera';}
            else if (e.name === 'NotReadableError') { userMsg = 'Camera in use or hardware error.'; phMsg = 'Camera In Use / Error';}
            else { userMsg = `Unexpected camera error (${e.name}). Try refreshing.`; phMsg = 'Unexpected Error';}

            cameraError.textContent = userMsg;
            cameraError.classList.remove('hidden');
            cameraPlaceholderText.textContent = phMsg;
            cameraPlaceholder.classList.add('show');
            cameraFeed.classList.add('hidden');
            captureBtn.disabled = true;
            showMessage(userMsg, 'error');
        }
     }

     function stopCamera() {
        if (cameraStream) {
            console.log("[VERIFY CAMERA] Stopping video stream.");
            cameraStream.getTracks().forEach(track => track.stop());
            cameraStream = null;
        }
     }

    captureBtn.addEventListener('click', async () => {
        if (!cameraStream || !cameraFeed.srcObject || cameraFeed.ended || cameraFeed.paused) {
            showMessage('Camera is not active.', 'warning'); startCamera(); return;
        }
        console.log("[VERIFY CAPTURE] Capturing photo...");
        captureBtn.disabled = true; // Disable during capture/upload
        uploadProgress.textContent = 'Capturing...'; uploadProgress.classList.remove('hidden');

        const video = cameraFeed, canvas = captureCanvas, photo = capturedPhoto;
         if (video.videoWidth === 0) { showMessage('Camera initializing...', 'warning'); captureBtn.disabled = false; return; }
        canvas.width = video.videoWidth; canvas.height = video.videoHeight;
        try {
            canvas.getContext('2d').drawImage(video, 0, 0);
            const imageDataUrl = canvas.toDataURL('image/jpeg', 0.8);
            console.log("[VERIFY CAPTURE] Photo captured. Uploading via IPC...");
            uploadProgress.textContent = 'Uploading photo...';

            // --- Upload via IPC ---
            if (!window.electronAPI?.uploadPhoto) {
                 throw new Error("Photo upload function not available.");
            }
            const result = await window.electronAPI.uploadPhoto(imageDataUrl);
            if (!result.success || !result.imageUrl) {
                 throw new Error(result.error || "Failed to upload photo via main process.");
            }
            // --- End Upload ---

            capturedImageData = result.imageUrl; // Store the CLOUDINARY URL
            console.log("[VERIFY CAPTURE] Photo uploaded:", capturedImageData);
            photo.src = imageDataUrl; // Show preview
            video.classList.add('hidden'); photo.classList.remove('hidden'); cameraPlaceholder.classList.remove('show');
            captureBtn.classList.add('hidden'); recaptureBtn.classList.remove('hidden');
            stopCamera();
            uploadProgress.textContent = 'Upload complete!';
            setTimeout(() => uploadProgress.classList.add('hidden'), 2000); // Hide progress message

        } catch (e) {
             console.error("[VERIFY CAPTURE/UPLOAD ERROR]", e);
             showMessage(`Failed to capture or upload photo: ${e.message}. Please try again.`, "error");
             startCamera(); // Restart camera
             captureBtn.classList.remove('hidden'); recaptureBtn.classList.add('hidden');
             captureBtn.disabled = false; // Re-enable capture
             uploadProgress.classList.add('hidden');
         }
     });

    recaptureBtn.addEventListener('click', () => {
        console.log("[VERIFY RECAPTURE] Recapturing photo.");
        capturedImageData = null;
        capturedPhoto.classList.add('hidden');
        startCamera();
        captureBtn.classList.remove('hidden'); recaptureBtn.classList.add('hidden');
        uploadProgress.classList.add('hidden');
    });

    // --- Form Submission ---
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        console.log("[VERIFY FORM SUBMIT] Attempting to start test...");
        formErrorMessage.classList.add('hidden');

        if (!collegeSelect.value) { showMessage('Please select your college.', 'warning'); return; }
        if (!capturedImageData) { showMessage('Please capture your photo.', 'warning'); return; }
        if (!token || !testDetails) { showMessage('Initialization error. Missing token or test details.', 'error'); return; }

        startTestBtn.disabled = true; startBtnText.textContent = 'Processing...'; startSpinner.classList.remove('hidden');

        const details = {
            fullName: document.getElementById('student-name').value.trim(),
            rollNumber: document.getElementById('roll-number').value.trim(),
            collegeName: collegeSelect.value,
            department: document.getElementById('department').value.trim(),
            profileImageUrl: capturedImageData // The Cloudinary URL from upload
        };

        try {
             console.log("[VERIFY FORM SUBMIT] Sending details to main process:", details);
             if (!window.electronAPI?.submitVerificationDetails) {
                 throw new Error("Verification submission function not available.");
             }
             // Send token and details to main process to save and load test page
             const result = await window.electronAPI.submitVerificationDetails(token, details);

             if (!result.success) {
                 throw new Error(result.error || "Failed to start test after verification.");
             }
             // Main process will handle loading the actual test page on success.
             // This page doesn't need to do anything else.
             console.log("[VERIFY FORM SUBMIT] Details sent successfully. Main process is loading the test.");
             startBtnText.textContent = 'Loading Test...'; // Keep disabled

        } catch (error) {
            console.error("[VERIFY FORM SUBMIT ERROR]", error);
            showMessage(`Error starting test: ${error.message}`, 'error');
            formErrorMessage.textContent = `Error: ${error.message}`;
            formErrorMessage.classList.remove('hidden');
            startTestBtn.disabled = false; startBtnText.textContent = 'Proceed to Test'; startSpinner.classList.add('hidden');
        }
    });

    // --- Initialization ---
    async function loadInitialData() {
        console.log("[VERIFY INIT] Loading initial data (token, test details, colleges)...");
        try {
             if (!window.electronAPI?.getInitialVerificationData) {
                throw new Error("Cannot get initial data from main process.");
            }
            const initialData = await window.electronAPI.getInitialVerificationData();
            if (!initialData || !initialData.token || !initialData.testDetails) {
                 throw new Error("Invalid initial data received.");
            }
            token = initialData.token;
            testDetails = initialData.testDetails; // Contains testId needed for colleges
            console.log("[VERIFY INIT] Received token and test details:", testDetails);

            // Fetch and populate colleges
            await populateColleges(testDetails.aptitudeTestId || testDetails.codingTestId);

            // Start camera AFTER fetching colleges
            await startCamera();

        } catch (error) {
             console.error("[VERIFY INIT ERROR]", error);
             formErrorMessage.textContent = `Initialization Error: ${error.message}. Please restart the application.`;
             formErrorMessage.classList.remove('hidden');
             startTestBtn.disabled = true; // Disable form if init fails
             showMessage(`Initialization Error: ${error.message}`, 'error', 10000);
         }
    }

    async function populateColleges(testIdForColleges) {
         collegeSelect.innerHTML = '<option value="" disabled selected>Loading colleges...</option>';
         if (!testIdForColleges) {
            console.error("[VERIFY COLLEGES] Test ID missing.");
            collegeSelect.innerHTML = '<option value="" disabled selected>Error: Missing Test ID</option>';
            return;
         }
         try {
            console.log("[VERIFY COLLEGES] Fetching colleges for test ID:", testIdForColleges);
            // Fetch colleges using the Electron API (proxied through main process)
            if (!window.electronAPI?.fetchColleges) {
                 throw new Error("College fetching function not available.");
            }
            const result = await window.electronAPI.fetchColleges(testIdForColleges);

            if (!result.success) {
                throw new Error(result.error || `Server error fetching colleges.`);
            }

            const data = result.colleges || [];
            console.log("[VERIFY COLLEGES] Received colleges:", data);

            collegeSelect.innerHTML = '<option value="" disabled selected>Select your college</option>';
            if (data.length === 0) {
                collegeSelect.innerHTML += '<option value="N/A">Not Applicable</option>';
            } else {
                data.forEach(c => { if (c && c.collegeName) { collegeSelect.innerHTML += `<option value="${c.collegeName}">${c.collegeName}</option>`; } });
                collegeSelect.innerHTML += '<option value="N/A">Not Listed</option>'; // Add "Not Listed" option
            }
            console.log("[VERIFY COLLEGES] Colleges populated.");

         } catch (e) {
            console.error("[VERIFY COLLEGES ERROR] Error loading colleges:", e);
            collegeSelect.innerHTML = '<option value="" disabled selected>College load failed</option>';
            showMessage(`Error loading colleges: ${e.message}`, 'error');
         }
    }


    loadInitialData(); // Start loading data when the page is ready
});
