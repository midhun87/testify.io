// --- FILE: sme-common.js ---
// This is a NEW common.js file specifically for the SME portal.
// It will handle auth, sidebar, and user menu for all SME pages.

function initializeSmePage(pageTitle) {
    const token = localStorage.getItem('token');
    const userString = localStorage.getItem('user');
    let user = null;

    if (userString) {
        try {
            user = JSON.parse(userString);
        } catch (e) {
            console.error("Failed to parse user data", e);
            token = null; // Force re-login
        }
    }

    // Auth Check: Must have a token AND the user role must be "SME"
    if (!token || !user || user.role !== 'SME') {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        window.location.href = 'sme-login.html';
        return;
    }

    // --- Inject SME Sidebar ---
    const sidebarNav = document.getElementById('sidebar-nav');
    if (sidebarNav) {
        sidebarNav.innerHTML = `
            <a href="sme-dashboard.html" class="sidebar-link flex items-center py-3 px-4 rounded-lg text-gray-300 hover:text-white" data-page="Dashboard">
                <svg class="w-6 h-6 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"></path></svg>
                Dashboard
            </a>
            <a href="sme-manage-problems.html" class="sidebar-link flex items-center py-3 px-4 rounded-lg text-gray-300 hover:text-white" data-page="Manage Coding Problems">
                <svg class="w-6 h-6 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path></svg>
                Manage Coding Problems
            </a>
            <a href="sme-manage-tests.html" class="sidebar-link flex items-center py-3 px-4 rounded-lg text-gray-300 hover:text-white" data-page="Manage Aptitude Tests">
                <svg class="w-6 h-6 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01"></path></svg>
                Manage Aptitude Tests
            </a>
        `;
        
        // Set active link
        const activeLink = sidebarNav.querySelector(`.sidebar-link[data-page="${pageTitle}"]`);
        if (activeLink) {
            activeLink.classList.add('active');
            activeLink.classList.remove('text-gray-300', 'hover:text-white');
            activeLink.classList.add('text-white');
        }
    }

    // --- Inject User Menu ---
    const userMenuContainer = document.getElementById('user-menu-container');
    if (userMenuContainer) {
        userMenuContainer.innerHTML = `
            <div class="relative">
                <button id="user-menu-btn" class="flex items-center space-x-2 focus:outline-none">
                    <span class="font-semibold text-gray-700">${user.fullName || 'SME User'}</span>
                    <svg class="w-5 h-5 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>
                </button>
                <div id="user-menu-dropdown" class="hidden absolute right-0 mt-2 w-48 bg-white rounded-md shadow-lg py-1 z-50">
                    <a href="#" id="logout-btn" class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">Sign out</a>
                </div>
            </div>
        `;

        const userMenuBtn = document.getElementById('user-menu-btn');
        const userMenuDropdown = document.getElementById('user-menu-dropdown');
        const logoutBtn = document.getElementById('logout-btn');

        userMenuBtn.addEventListener('click', () => {
            userMenuDropdown.classList.toggle('hidden');
        });

        logoutBtn.addEventListener('click', (e) => {
            e.preventDefault();
            localStorage.removeItem('token');
            localStorage.removeItem('user');
            window.location.href = 'sme-login.html';
        });

        // Close dropdown if clicking outside
        document.addEventListener('click', (e) => {
            if (!userMenuBtn.contains(e.target) && !userMenuDropdown.contains(e.target)) {
                userMenuDropdown.classList.add('hidden');
            }
        });
    }
}