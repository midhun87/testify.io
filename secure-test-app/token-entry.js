document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('token-form');
    const tokenInput = document.getElementById('token-input');
    const submitBtn = document.getElementById('submit-token-btn');
    const submitSpinner = document.getElementById('submit-spinner');
    const submitBtnText = document.getElementById('submit-btn-text');
    const errorMessage = document.getElementById('error-message');
    const proctoringWarning = document.getElementById('proctoring-warning');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const token = tokenInput.value.trim();
        if (!token) {
            errorMessage.textContent = 'Please enter a token.';
            errorMessage.classList.remove('hidden');
            return;
        }

        // Disable form, show spinner
        tokenInput.disabled = true;
        submitBtn.disabled = true;
        submitBtnText.textContent = 'Validating...';
        submitSpinner.classList.remove('hidden');
        errorMessage.classList.add('hidden');
        proctoringWarning.classList.remove('hidden'); // Show warning

        try {
            console.log("Sending token to main for validation:", token ? '******' : '<empty>');
            if (!window.electronAPI || !window.electronAPI.validateToken) {
                 throw new Error("Validation API is not available.");
            }
            const result = await window.electronAPI.validateToken(token);
            console.log("Validation result from main:", result);

            if (result.isValid) {
                // ** CHANGE: Don't load page here. Main process handles it. **
                console.log("Token validation successful. Main process will load next page.");
                submitBtnText.textContent = 'Validation Success!';
                // Keep button disabled, main process handles next step
            } else {
                throw new Error(result.error || 'Invalid token or test inactive.');
            }
        } catch (error) {
            console.error("Token validation error:", error);
            errorMessage.textContent = `Error: ${error.message}`;
            errorMessage.classList.remove('hidden');
            proctoringWarning.classList.add('hidden'); // Hide warning on error

            // Re-enable form on error
            tokenInput.disabled = false;
            submitBtn.disabled = false;
            submitBtnText.textContent = 'Validate Token & Start Test';
            submitSpinner.classList.add('hidden');
        }
    });
});

