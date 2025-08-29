document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    const signupForm = document.getElementById('signup-form');
    const messageDiv = document.getElementById('message');

    // --- SIGNUP PAGE LOGIC ---
    if (signupForm) {
        signupForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(signupForm);
            const data = Object.fromEntries(formData.entries());

            try {
                const response = await fetch('/api/signup', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data),
                });

                const result = await response.json();
                showMessage(result.message, response.ok);

                if (response.ok) {
                    setTimeout(() => {
                        window.location.href = '/login.html'; // Redirect to login on success
                    }, 2000);
                }
            } catch (error) {
                console.error('Signup Fetch Error:', error);
                showMessage('An error occurred. Please try again.', false);
            }
        });
    }

    // --- LOGIN PAGE LOGIC ---
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(loginForm);
            const data = Object.fromEntries(formData.entries());

            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data),
                });

                const result = await response.json();
                
                if (!response.ok) {
                    showMessage(result.message, false);
                    return;
                }

                // On successful login, save token and user data
                localStorage.setItem('token', result.token);
                localStorage.setItem('user', JSON.stringify(result.user));

                // Show success message before redirecting
                showMessage(result.message, true);

                // Redirect based on role after a short delay
                setTimeout(() => {
                    if (result.user.role === 'Admin') {
                        window.location.href = '/admin/dashboard.html';
                    } else {
                        window.location.href = '/student/dashboard.html';
                    }
                }, 1000);

            } catch (error) {
                console.error('Login Fetch Error:', error);
                showMessage('An error occurred. Please try again.', false);
            }
        });
    }

    // --- UTILITY FUNCTION to display messages ---
    function showMessage(message, isSuccess) {
        if (!messageDiv) return;
        
        messageDiv.textContent = message;
        // Reset classes and unhide
        messageDiv.className = 'text-center mt-4 p-3 rounded-lg font-medium';
        
        if (isSuccess) {
            messageDiv.classList.add('bg-green-100', 'text-green-800');
        } else {
            messageDiv.classList.add('bg-red-100', 'text-red-800');
        }
    }
});
