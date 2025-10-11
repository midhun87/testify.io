function initializePage(activeLinkText) {
    const user = JSON.parse(localStorage.getItem('user'));
    const token = localStorage.getItem('token');

    if (!token || !user || user.role !== 'Hiring Moderator') {
        window.location.href = 'hiring-moderator-login.html';
        return;
    }

    // User Menu
    const userMenuContainer = document.getElementById('user-menu-container');
    if (userMenuContainer) {
        userMenuContainer.innerHTML = `
            <div class="relative">
                <button id="user-menu-button" class="flex items-center space-x-2">
                    <span class="font-semibold text-gray-700">${user.fullName}</span>
                    <svg class="h-5 w-5 text-gray-500" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd" /></svg>
                </button>
                <div id="user-menu" class="hidden absolute right-0 mt-2 w-48 bg-white rounded-md shadow-lg py-1 z-20">
                    <a href="#" id="logout-button" class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">Logout</a>
                </div>
            </div>`;
        
        document.getElementById('user-menu-button').addEventListener('click', () => {
            document.getElementById('user-menu').classList.toggle('hidden');
        });
        document.getElementById('logout-button').addEventListener('click', () => {
            localStorage.clear();
            window.location.href = 'hiring-moderator-login.html';
        });
    }

    // Sidebar Navigation
    const sidebarNav = document.getElementById('sidebar-nav');
    if (sidebarNav) {
        const links = [
            { href: "hiring-dashboard.html", icon: '<svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"></path></svg>', text: "Dashboard" },
            { href: "hiring-create-job.html", icon: '<svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v3m0 0v3m0-3h3m-3 0H9m12 0a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>', text: "Create Job" },
            { href: "hiring-jobs.html", icon: '<svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 13.255A23.931 23.931 0 0112 15c-3.183 0-6.22-.62-9-1.745M16 6V4a2 2 0 00-2-2h-4a2 2 0 00-2 2v2m4 6h.01M5 20h14a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" /></svg>', text: "Manage Jobs" },
            { href: "hiring-create-test.html", icon: '<svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path></svg>', text: "Create Test" },
            { href: "hiring-assign-test.html", icon: '<svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"></path></svg>', text: "Assign Test" },
            { href: "hiring-test-history.html", icon: '<svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>', text: "Test History" },
            { href: "hiring-manage-colleges.html", icon: '<svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 14v3m4-3v3m4-3v3M3 21h18M3 10h18M3 7l9-4 9 4M4 10h16v11H4V10z"></path></svg>', text: "Manage Colleges" },
        ];

        sidebarNav.innerHTML = links.map(link => `
            <a href="${link.href}" class="sidebar-link ${link.text === activeLinkText ? 'active' : ''} flex items-center px-4 py-3 mt-2 rounded-lg">
                ${link.icon}
                <span class="ml-3">${link.text}</span>
            </a>
        `).join('');
    }
}
