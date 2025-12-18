function initializePage() {
    const user = JSON.parse(localStorage.getItem("user"));
    const token = localStorage.getItem("token");

    // ---------------- ACCESS CONTROL ----------------
    if (!token || !user || (user.role !== "Hiring Moderator" && user.role !== "Admin")) {
        window.location.href = "/hiring/moderator-login";
        return;
    }

    // ✅ Ensure FontAwesome is loaded once
    if (!document.querySelector('link[href*="font-awesome"]')) {
        const faLink = document.createElement("link");
        faLink.rel = "stylesheet";
        faLink.href = "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css";
        document.head.appendChild(faLink);
    }

    // ---------------- USER MENU ----------------
    const userMenuContainer = document.getElementById("user-menu-container");
    if (userMenuContainer) {
        userMenuContainer.innerHTML = `
            <div class="relative">
                <button id="user-menu-button"
                    class="flex items-center gap-2 bg-white border border-gray-200 rounded-full px-4 py-2 hover:shadow-md transition duration-200">
                    <div class="flex items-center justify-center w-8 h-8 rounded-full bg-indigo-100 text-indigo-700 font-semibold">
                        ${user.fullName.charAt(0).toUpperCase()}
                    </div>
                    <span class="font-semibold text-gray-800">${user.fullName}</span>
                    <i class="fas fa-chevron-down text-gray-500 text-sm"></i>
                </button>
                <div id="user-menu"
                    class="hidden absolute right-0 mt-3 w-48 bg-white rounded-xl shadow-lg border border-gray-100 overflow-hidden z-20">
                    <a href="#" id="logout-button"
                        class="block px-4 py-2.5 text-sm text-gray-700 hover:bg-gray-50 hover:text-indigo-600 transition">
                        <i class="fas fa-sign-out-alt mr-2"></i> Logout
                    </a>
                </div>
            </div>`;

        document.getElementById("user-menu-button").addEventListener("click", () => {
            document.getElementById("user-menu").classList.toggle("hidden");
        });
        document.getElementById("logout-button").addEventListener("click", () => {
            localStorage.clear();
            window.location.href = "/hiring/moderator-login";
        });
    }

    // ---------------- SIDEBAR NAVIGATION ----------------
    const sidebarNav = document.getElementById("sidebar-nav");
    if (sidebarNav) {

        // ✅ Updated Sidebar Links (now match Express routes)
        const links = [
            { href: "/hiring/dashboard", icon: "fa-home", text: "Dashboard" },
            { href: "/hiring/hiring-proctor-dashboard.html", icon: "fa-home", text: "Proctor - Dashboard" },
            { href: "/hiring/create-job", icon: "fa-plus-circle", text: "Create Job" },
            { href: "/hiring/jobs", icon: "fa-briefcase", text: "Manage Jobs" },
            { href: "/hiring/create-test", icon: "fa-file-alt", text: "Create Aptitude Test" },
            { href: "/hiring/create-problem", icon: "fa-code", text: "Manage Coding Problems" },
            { href: "/hiring/create-coding-test", icon: "fa-file-code", text: "Create Coding Test" },
            { href: "/hiring/assign-test", icon: "fa-paper-plane", text: "Assign Test" },
            { href: "/hiring/sta", icon: "fa-laptop-code", text: "Assign Coding Test" },
            { href: "/hiring/coding-test-results", icon: "fa-chart-line", text: "Coding Test Results" },
            { href: "/hiring/test-reports", icon: "fa-chart-bar", text: "Test Reports" },
            { href: "/hiring/report-details", icon: "fa-file-invoice", text: "Report Details" },
            { href: "/hiring/manage-tests", icon: "fa-tasks", text: "Manage Tests" },
            { href: "/hiring/manage-colleges", icon: "fa-school", text: "Manage Colleges" },
            { href: "/hiring/manage-interviewers", icon: "fa-users-cog", text: "Manage Interviewers" },
            { href: "/hiring/schedule-interview", icon: "fa-calendar-alt", text: "Schedule Interview" },
            { href: "/hiring/interview-reports", icon: "fa-file-signature", text: "Interview Reports" },
            { href: "/hiring/test-history", icon: "fa-history", text: "Test History" },
            { href: "/hiring/view-applicants", icon: "fa-user-check", text: "View Applicants" },
        ];

        // ✅ Detect current page by route
        const currentPath = window.location.pathname.toLowerCase();

        // ✅ Role-based sidebar control
        let finalLinks = links;
        if (user.role === "Admin") {
            finalLinks = [
                { href: "/hiring/manage-interviewers", icon: "fa-users-cog", text: "Manage Interviewers" },
                { href: "/hiring/manage-colleges", icon: "fa-school", text: "Manage Colleges" },
            ];
            if (!finalLinks.some(link => link.href === currentPath)) {
                window.location.href = "/hiring/manage-interviewers";
                return;
            }
        }

        // ✅ Render sidebar
        sidebarNav.innerHTML = `
            <div class="flex flex-col h-full bg-gradient-to-b from-[#363359] to-[#363359] text-gray-200 shadow-xl">
                <div class="text-center py-5 border-b border-indigo-900 bg-opacity-90">
                    <h1 class="text-lg font-bold tracking-wide text-white">XETA-HIRE</h1>
                </div>

                <nav id="sidebar-scrollable" class="flex-1 overflow-y-auto py-4 px-3 space-y-1">
                    ${finalLinks.map(link => `
                        <a href="${link.href}"
                           class="group flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm font-medium transition-all duration-200
                               ${link.href === currentPath
                                   ? 'bg-indigo-500 text-white shadow-inner'
                                   : 'hover:bg-indigo-600 hover:text-white'}">
                            <i class="fas ${link.icon} text-base w-5 text-center"></i>
                            <span>${link.text}</span>
                        </a>`).join('')}
                </nav>

                <div class="text-center text-xs text-gray-400 border-t border-indigo-900 py-3">
                    © ${new Date().getFullYear()} Xeta Solutions
                </div>
            </div>`;

        // ✅ Restore sidebar scroll
        const sidebar = document.getElementById("sidebar-scrollable");
        const savedScroll = localStorage.getItem("sidebar-scroll");
        if (savedScroll) sidebar.scrollTop = savedScroll;

        sidebar.addEventListener("scroll", () => {
            localStorage.setItem("sidebar-scroll", sidebar.scrollTop);
        });

        // ✅ Auto-scroll to active link
        const activeLink = Array.from(sidebar.querySelectorAll("a"))
            .find(a => a.href.endsWith(currentPath));
        if (activeLink) {
            activeLink.scrollIntoView({ behavior: "smooth", block: "center" });
        }
    }
}
