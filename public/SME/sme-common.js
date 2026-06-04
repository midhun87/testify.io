// --- FILE: sme-common.js ---
// Handles auth, sidebar, and user menu for all SME pages.

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
        window.location.href = 'login.html';
        return;
    }

    // --- Inject SME Sidebar ---
    const sidebarNav = document.getElementById('sidebar-nav');
    if (sidebarNav) {
        sidebarNav.innerHTML = `
            <a href="sme-dashboard.html" class="sidebar-link flex items-center py-3 px-4 rounded-lg text-gray-300 hover:text-white transition-colors duration-200" data-page="Dashboard">
                <svg class="w-6 h-6 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"></path></svg>
                Dashboard
            </a>
            <a href="sme-create-public-test.html" class="sidebar-link flex items-center py-3 px-4 rounded-lg text-gray-300 hover:text-white transition-colors duration-200" data-page="Create Test">
                <svg class="w-6 h-6 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v3m0 0v3m0-3h3m-3 0H9m12 0a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                Create Test
            </a>
            <a href="sme-test-results.html" class="sidebar-link flex items-center py-3 px-4 rounded-lg text-gray-300 hover:text-white transition-colors duration-200" data-page="Test Results">
                <svg class="w-6 h-6 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
                Test Results
            </a>
   
            <a href="sme-create-public-test.html" class="sidebar-link flex items-center py-3 px-4 rounded-lg text-gray-300 hover:text-white transition-colors duration-200" data-page="Create Test">
                <svg class="w-6 h-6 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v3m0 0v3m0-3h3m-3 0H9m12 0a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                Create Test
            </a>
            <a href="sme-manage-public-tests.html" class="sidebar-link flex items-center py-3 px-4 rounded-lg text-gray-300 hover:text-white transition-colors duration-200" data-page="Manage Tests">
                <svg class="w-6 h-6 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16"></path></svg>
                Manage Tests
            </a>
            <a href="sme-test-results.html" class="sidebar-link flex items-center py-3 px-4 rounded-lg text-gray-300 hover:text-white transition-colors duration-200" data-page="Test Results">

        `;

        // Highlight active page
        const links = sidebarNav.querySelectorAll('.sidebar-link');
        links.forEach(link => {
            if (link.dataset.page === pageTitle) {
                link.classList.add('bg-indigo-600', 'text-white', 'font-semibold');
                link.classList.remove('text-gray-300');
            }
        });
    }

    // --- Inject User Profile Menu ---
    const userProfileContainer = document.getElementById('user-profile-container');
    if (userProfileContainer) {
        userProfileContainer.innerHTML = `
            <div class="relative">
                <button id="user-menu-btn" class="flex items-center focus:outline-none space-x-2 bg-white px-3 py-2 rounded-lg shadow-sm border border-gray-200 hover:bg-gray-50 transition-colors">
                    <div class="w-8 h-8 rounded-full bg-indigo-100 flex items-center justify-center text-indigo-700 font-bold">
                        ${user.fullName ? user.fullName.charAt(0).toUpperCase() : 'S'}
                    </div>
                    <span class="text-sm font-semibold text-gray-700 hidden sm:block">${user.fullName || 'SME User'}</span>
                    <svg class="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>
                </button>
                <div id="user-menu-dropdown" class="hidden absolute right-0 mt-2 w-48 bg-white rounded-md shadow-xl py-1 z-50 border border-gray-100">
                    <div class="px-4 py-2 border-b border-gray-100">
                        <p class="text-xs text-gray-500">Signed in as</p>
                        <p class="text-sm font-medium text-gray-900 truncate">${user.email || 'user@example.com'}</p>
                    </div>
                    <a href="#" id="logout-btn" class="block px-4 py-2 text-sm text-red-600 hover:bg-red-50 transition-colors">Sign out</a>
                </div>
            </div>
        `;

        const userMenuBtn = document.getElementById('user-menu-btn');
        const userMenuDropdown = document.getElementById('user-menu-dropdown');
        const logoutBtn = document.getElementById('logout-btn');

        userMenuBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            userMenuDropdown.classList.toggle('hidden');
        });

        logoutBtn.addEventListener('click', (e) => {
            e.preventDefault();
            localStorage.removeItem('token');
            localStorage.removeItem('user');
            window.location.href = 'login.html';
        });

        document.addEventListener('click', (e) => {
            if (!userMenuBtn.contains(e.target) && !userMenuDropdown.contains(e.target)) {
                userMenuDropdown.classList.add('hidden');
            }
        });
    }
}