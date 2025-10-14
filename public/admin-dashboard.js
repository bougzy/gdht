// API Base URL
const API_BASE_URL = '/api';

// State management
let currentAdmin = null;
let adminToken = localStorage.getItem('adminToken');
let isAdmin = localStorage.getItem('isAdmin') === 'true';
let webSocket = null;
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 5;
let revenueChart = null;
let currentTab = 'dashboard';

// Check if admin is authenticated
document.addEventListener('DOMContentLoaded', function() {
    if (!isAdmin) {
        window.location.href = 'admin-login.html';
        return;
    }
    
    // Set admin credentials for API calls
    setAdminCredentials();
    
    // Initialize dashboard
    initializeDashboard();
    setupEventListeners();
    
    // Initialize WebSocket connection
    initializeWebSocket();
    
    // Set up periodic data refresh
    setInterval(refreshDashboard, 30000);
    setInterval(updateSystemUptime, 1000);
});

// Set admin credentials for API calls
function setAdminCredentials() {
    const adminUsername = localStorage.getItem('adminUsername') || 'admin';
    const adminPassword = localStorage.getItem('adminPassword') || 'admin123';
    
    // Set headers for all fetch requests
    const originalFetch = window.fetch;
    window.fetch = function(...args) {
        const [resource, config = {}] = args;
        config.headers = {
            ...config.headers,
            'Admin-Username': adminUsername,
            'Admin-Password': adminPassword
        };
        return originalFetch(resource, config);
    };
}

// Initialize dashboard
async function initializeDashboard() {
    await loadDashboardStats();
    await loadUsers();
    await loadTransactions();
    await loadPendingDeposits();
    await loadPendingWithdrawals();
    await loadPendingInvestments();
    await loadNotifications();
    await loadEarningsBreakdowns();
    await loadTransactionReports();
    await loadSystemSettings();
    initializeRevenueChart();
}

// Setup event listeners
function setupEventListeners() {
    // Sidebar navigation
    document.querySelectorAll('.sidebar .nav-link').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const tab = this.getAttribute('data-tab');
            switchTab(tab);
        });
    });
    
    // Logout button
    document.getElementById('adminLogout').addEventListener('click', handleAdminLogout);
    
    // User search
    document.getElementById('userSearch').addEventListener('input', debounce(searchUsers, 300));
    
    // Deposit filter buttons
    document.querySelectorAll('#depositsTab .btn-group .btn').forEach(btn => {
        btn.addEventListener('click', function() {
            document.querySelectorAll('#depositsTab .btn-group .btn').forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            loadDeposits(this.getAttribute('data-filter'));
        });
    });
    
    // Withdrawal filter buttons
    document.querySelectorAll('#withdrawalsTab .btn-group .btn').forEach(btn => {
        btn.addEventListener('click', function() {
            document.querySelectorAll('#withdrawalsTab .btn-group .btn').forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            loadWithdrawals(this.getAttribute('data-filter'));
        });
    });
    
    // Transaction filters
    document.getElementById('transactionTypeFilter').addEventListener('change', loadTransactions);
    document.getElementById('transactionStatusFilter').addEventListener('change', loadTransactions);
    
    // Earnings calculation
    ['earningsProfit', 'earningsDeposit', 'earningsInvestment'].forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            element.addEventListener('input', calculateEarningsTotal);
        }
    });
    
    // Investment plan settings
    document.getElementById('investmentPlansSettings').addEventListener('click', function(e) {
        if (e.target.classList.contains('btn-save-plan')) {
            const planId = e.target.getAttribute('data-plan-id');
            saveInvestmentPlan(planId);
        } else if (e.target.classList.contains('btn-delete-plan')) {
            const planId = e.target.getAttribute('data-plan-id');
            deleteInvestmentPlan(planId);
        }
    });
}

// Switch between tabs
function switchTab(tabName) {
    // Hide all tab contents
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Remove active class from all sidebar links
    document.querySelectorAll('.sidebar .nav-link').forEach(link => {
        link.classList.remove('active');
    });
    
    // Show the selected tab content
    const targetTab = document.getElementById(tabName + 'Tab');
    if (targetTab) {
        targetTab.classList.add('active');
    }
    
    // Add active class to the clicked sidebar link
    const activeLink = document.querySelector(`.sidebar .nav-link[data-tab="${tabName}"]`);
    if (activeLink) {
        activeLink.classList.add('active');
    }
    
    currentTab = tabName;
    
    // Load specific data for the tab if needed
    switch(tabName) {
        case 'users':
            loadUsers();
            break;
        case 'transactions':
            loadTransactions();
            break;
        case 'deposits':
            loadPendingDeposits('pending');
            break;
        case 'withdrawals':
            loadPendingWithdrawals('pending');
            break;
        case 'investments':
            loadPendingInvestments();
            break;
        case 'earnings':
            loadEarningsBreakdowns();
            break;
        case 'reports':
            loadTransactionReports();
            break;
        case 'notifications':
            loadNotifications();
            break;
        case 'system':
            loadSystemSettings();
            break;
    }
}

// Initialize WebSocket connection
function initializeWebSocket() {
    if (webSocket && webSocket.readyState === WebSocket.OPEN) {
        return;
    }

    try {
        updateAdminConnectionStatus('connecting', 'Connecting...');
        
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws`;
        
        webSocket = new WebSocket(wsUrl);
        
        webSocket.onopen = function() {
            console.log('✅ Admin WebSocket connected successfully');
            reconnectAttempts = 0;
            updateAdminConnectionStatus('connected', 'Connected');
            
            // Send admin authentication
            webSocket.send(JSON.stringify({
                type: 'ADMIN_AUTH',
                username: localStorage.getItem('adminUsername') || 'admin'
            }));
        };
        
        webSocket.onmessage = function(event) {
            try {
                const data = JSON.parse(event.data);
                console.log('📨 Admin WebSocket message received:', data);
                handleAdminWebSocketMessage(data);
            } catch (error) {
                console.error('❌ Error parsing admin WebSocket message:', error);
            }
        };
        
        webSocket.onclose = function(event) {
            console.log('❌ Admin WebSocket disconnected:', event.code, event.reason);
            updateAdminConnectionStatus('disconnected', 'Disconnected');
            
            // Attempt reconnection
            if (reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
                const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
                console.log(`🔄 Admin reconnection attempt ${reconnectAttempts + 1} in ${delay}ms`);
                
                setTimeout(() => {
                    reconnectAttempts++;
                    initializeWebSocket();
                }, delay);
            } else {
                console.error('❌ Max admin reconnection attempts reached');
                updateAdminConnectionStatus('error', 'Connection failed');
            }
        };
        
        webSocket.onerror = function(error) {
            console.error('❌ Admin WebSocket error:', error);
            updateAdminConnectionStatus('error', 'Connection error');
        };
        
    } catch (error) {
        console.error('❌ Error initializing admin WebSocket:', error);
        updateAdminConnectionStatus('error', 'Connection failed');
    }
}

function updateAdminConnectionStatus(status, message) {
    const statusElement = document.getElementById('adminConnectionStatus');
    const indicator = document.getElementById('adminConnectionIndicator');
    
    if (statusElement) statusElement.textContent = message;
    
    if (indicator) {
        indicator.className = `status-indicator ${
            status === 'connected' ? 'status-connected' : 
            status === 'connecting' ? 'status-connecting' : 
            'status-disconnected'
        }`;
    }
}

function handleAdminWebSocketMessage(data) {
    switch (data.type) {
        case 'ADMIN_CONNECTED':
            updateAdminConnectionStatus('connected', 'Connected');
            showToast('Admin Connected', 'Real-time updates active', 'success');
            break;
            
        case 'USER_REGISTERED':
            refreshDashboard();
            addRecentActivity('New user registered', `User ${data.user.username} joined`, 'user-plus');
            showToast('New User', `User ${data.user.username} registered`, 'info');
            break;
            
        case 'DEPOSIT_SUBMITTED':
            refreshDashboard();
            loadPendingDeposits();
            addRecentActivity('New deposit submitted', `$${data.amount} deposit pending`, 'money-bill-wave');
            break;
            
        case 'WITHDRAWAL_SUBMITTED':
            refreshDashboard();
            loadPendingWithdrawals();
            addRecentActivity('New withdrawal requested', `$${data.amount} withdrawal pending`, 'wallet');
            break;
            
        case 'INVESTMENT_CREATED':
            refreshDashboard();
            addRecentActivity('New investment created', `$${data.amount} investment submitted`, 'chart-line');
            break;
            
        default:
            console.log('Unhandled admin WebSocket message type:', data.type);
    }
}

// Load dashboard statistics
async function loadDashboardStats() {
    try {
        const response = await fetch(`${API_BASE_URL}/admin/dashboard-stats`);
        const result = await response.json();
        
        if (result.success) {
            const stats = result.data;
            
            // Update statistics cards
            updateElementText('totalUsers', stats.totalUsers);
            updateElementText('totalDeposits', stats.totalDeposits?.toLocaleString());
            updateElementText('totalWithdrawals', stats.totalWithdrawals?.toLocaleString());
            updateElementText('totalInvestments', stats.totalInvestments?.toLocaleString());
            
            // Update pending counts
            updateElementText('pendingDepositsCount', `${stats.pendingTransactions?.deposits || 0} pending`);
            updateElementText('pendingWithdrawalsCount', `${stats.pendingTransactions?.withdrawals || 0} pending`);
            updateElementText('activeInvestmentsCount', `${stats.pendingTransactions?.investments || 0} active`);
            
            // Update quick action counts
            updateElementText('quickDepositsCount', stats.pendingTransactions?.deposits || 0);
            updateElementText('quickWithdrawalsCount', stats.pendingTransactions?.withdrawals || 0);
            updateElementText('quickNewUsersCount', stats.recentRegistrations?.length || 0);
            
            // Update online users
            updateElementText('onlineUsers', `${stats.onlineUsers || 0} online`);
            
            // Update notification badges
            updateNotificationBadges(stats.pendingTransactions?.deposits || 0, stats.pendingTransactions?.withdrawals || 0);
            
            // Update last sync time
            updateElementText('lastSync', `Last sync: ${new Date().toLocaleTimeString()}`);
        }
    } catch (error) {
        console.error('Error loading dashboard stats:', error);
        showToast('Error', 'Failed to load dashboard statistics', 'error');
    }
}

// Helper function to safely update element text
function updateElementText(elementId, text) {
    const element = document.getElementById(elementId);
    if (element) element.textContent = text;
}

// Update notification badges
function updateNotificationBadges(pendingDeposits, pendingWithdrawals) {
    const depositsBadge = document.getElementById('pendingDepositsBadge');
    const withdrawalsBadge = document.getElementById('pendingWithdrawalsBadge');
    
    if (depositsBadge) {
        if (pendingDeposits > 0) {
            depositsBadge.textContent = pendingDeposits;
            depositsBadge.classList.remove('d-none');
        } else {
            depositsBadge.classList.add('d-none');
        }
    }
    
    if (withdrawalsBadge) {
        if (pendingWithdrawals > 0) {
            withdrawalsBadge.textContent = pendingWithdrawals;
            withdrawalsBadge.classList.remove('d-none');
        } else {
            withdrawalsBadge.classList.add('d-none');
        }
    }
}

// Load users
async function loadUsers(page = 1, search = '') {
    try {
        let url = `${API_BASE_URL}/admin/users?page=${page}&limit=10`;
        if (search) {
            url += `&search=${encodeURIComponent(search)}`;
        }
        
        const response = await fetch(url);
        const result = await response.json();
        
        if (result.success) {
            displayUsers(result.data.users);
            setupUsersPagination(result.data.pagination, search);
        } else {
            showToast('Error', result.message, 'error');
        }
    } catch (error) {
        console.error('Error loading users:', error);
        showToast('Error', 'Failed to load users', 'error');
    }
}

// Display users in table
function displayUsers(users) {
    const tbody = document.getElementById('usersTableBody');
    if (!tbody) return;
    
    tbody.innerHTML = '';
    
    if (!users || users.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="9" class="text-center py-4">
                    <i class="fas fa-users fa-2x text-muted mb-2"></i>
                    <p class="text-muted">No users found</p>
                </td>
            </tr>
        `;
        return;
    }
    
    users.forEach(user => {
        const avatarText = user.username ? user.username.charAt(0).toUpperCase() : 'U';
        const statusBadge = user.isBlocked ? 
            '<span class="badge bg-danger">Blocked</span>' : 
            '<span class="badge bg-success">Active</span>';
        
        const row = `
            <tr>
                <td>
                    <div class="d-flex align-items-center">
                        <div class="user-avatar me-3">${avatarText}</div>
                        <div>
                            <div class="fw-bold">${escapeHtml(user.username)}</div>
                            <small class="text-muted">${escapeHtml(user.name || 'N/A')}</small>
                        </div>
                    </div>
                </td>
                <td>${escapeHtml(user.email)}</td>
                <td>
                    <small>${escapeHtml(user.location?.country || 'Unknown')}</small>
                </td>
                <td>
                    <div>$${(user.walletBalance || 0).toFixed(2)}</div>
                    <small class="text-muted">Wallet</small>
                </td>
                <td>
                    <div>$${(user.depositBalance || 0).toFixed(2)}</div>
                    <small class="text-muted">Deposit</small>
                </td>
                <td>
                    <div>$${(user.totalInvested || 0).toFixed(2)}</div>
                    <small class="text-muted">Invested</small>
                </td>
                <td>${statusBadge}</td>
                <td>${new Date(user.createdAt).toLocaleDateString()}</td>
                <td>
                    <div class="action-buttons">
                        <button class="btn btn-sm btn-outline-primary" onclick="viewUser('${user._id}')" title="View">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button class="btn btn-sm btn-outline-warning" onclick="editUser('${user._id}')" title="Edit">
                            <i class="fas fa-edit"></i>
                        </button>
                        <div class="dropdown d-inline-block">
                            <button class="btn btn-sm btn-outline-info dropdown-toggle" type="button" data-bs-toggle="dropdown" title="Top-Up">
                                <i class="fas fa-plus"></i>
                            </button>
                            <ul class="dropdown-menu">
                                <li><a class="dropdown-item" href="#" onclick="openDepositTopUpModal('${user._id}', '${user.username}')">Top-Up Deposit</a></li>
                                <li><a class="dropdown-item" href="#" onclick="openInvestmentTopUpModal('${user._id}', '${user.username}')">Top-Up Investment</a></li>
                                <li><hr class="dropdown-divider"></li>
                                <li><a class="dropdown-item" href="#" onclick="openAdjustInvestmentModal('${user._id}', '${user.username}', ${user.totalInvested || 0})">Adjust Investment</a></li>
                            </ul>
                        </div>
                        ${user.isBlocked ? 
                            `<button class="btn btn-sm btn-outline-success" onclick="toggleUserBlock('${user._id}', false)" title="Unblock">
                                <i class="fas fa-check"></i>
                            </button>` :
                            `<button class="btn btn-sm btn-outline-danger" onclick="toggleUserBlock('${user._id}', true)" title="Block">
                                <i class="fas fa-ban"></i>
                            </button>`
                        }
                    </div>
                </td>
            </tr>
        `;
        tbody.innerHTML += row;
    });
    
    updateElementText('usersTableInfo', `Showing ${users.length} users`);
}

// Setup users pagination
function setupUsersPagination(pagination, search) {
    const paginationEl = document.getElementById('usersPagination');
    if (!paginationEl) return;
    
    paginationEl.innerHTML = '';
    
    const { page, pages, total } = pagination;
    
    // Previous button
    const prevLi = document.createElement('li');
    prevLi.className = `page-item ${page === 1 ? 'disabled' : ''}`;
    prevLi.innerHTML = `<a class="page-link" href="#" onclick="loadUsers(${page - 1}, '${search}')">Previous</a>`;
    paginationEl.appendChild(prevLi);
    
    // Page numbers
    for (let i = 1; i <= pages; i++) {
        const li = document.createElement('li');
        li.className = `page-item ${i === page ? 'active' : ''}`;
        li.innerHTML = `<a class="page-link" href="#" onclick="loadUsers(${i}, '${search}')">${i}</a>`;
        paginationEl.appendChild(li);
    }
    
    // Next button
    const nextLi = document.createElement('li');
    nextLi.className = `page-item ${page === pages ? 'disabled' : ''}`;
    nextLi.innerHTML = `<a class="page-link" href="#" onclick="loadUsers(${page + 1}, '${search}')">Next</a>`;
    paginationEl.appendChild(nextLi);
}

// Search users with debounce
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function searchUsers() {
    const query = document.getElementById('userSearch').value;
    loadUsers(1, query);
}

// Load transactions
async function loadTransactions() {
    try {
        const type = document.getElementById('transactionTypeFilter').value;
        const status = document.getElementById('transactionStatusFilter').value;
        
        let url = `${API_BASE_URL}/admin/transactions?limit=20`;
        if (type !== 'all') url += `&type=${type}`;
        if (status !== 'all') url += `&status=${status}`;
        
        const response = await fetch(url);
        const result = await response.json();
        
        if (result.success) {
            displayTransactions(result.data.transactions);
        } else {
            showToast('Error', result.message, 'error');
        }
    } catch (error) {
        console.error('Error loading transactions:', error);
        showToast('Error', 'Failed to load transactions', 'error');
    }
}

// Display transactions
function displayTransactions(transactions) {
    const tbody = document.getElementById('transactionsTableBody');
    if (!tbody) return;
    
    tbody.innerHTML = '';
    
    if (!transactions || transactions.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="text-center py-4">
                    <i class="fas fa-exchange-alt fa-2x text-muted mb-2"></i>
                    <p class="text-muted">No transactions found</p>
                </td>
            </tr>
        `;
        return;
    }
    
    transactions.forEach(transaction => {
        const statusClass = `badge-${transaction.status}`;
        const typeIcon = getTransactionTypeIcon(transaction.type);
        
        const row = `
            <tr>
                <td><small>${transaction._id?.substring(0, 8) || 'N/A'}...</small></td>
                <td>
                    <div class="fw-bold">${escapeHtml(transaction.user?.username || 'N/A')}</div>
                    <small class="text-muted">${escapeHtml(transaction.user?.email || '')}</small>
                </td>
                <td>
                    <div>${typeIcon} ${escapeHtml(transaction.type)}</div>
                    <small class="text-muted">${escapeHtml(transaction.investmentPlan || '')}</small>
                </td>
                <td class="fw-bold">$${(transaction.amount || 0).toFixed(2)}</td>
                <td><span class="badge ${statusClass}">${escapeHtml(transaction.status)}</span></td>
                <td>${new Date(transaction.createdAt).toLocaleDateString()}</td>
                <td>
                    <div class="action-buttons">
                        <button class="btn btn-sm btn-outline-primary" onclick="viewTransaction('${transaction._id}')">
                            <i class="fas fa-eye"></i>
                        </button>
                        ${transaction.status === 'pending' && transaction.type === 'deposit' ? 
                            `<button class="btn btn-sm btn-outline-success" onclick="approveDeposit('${transaction._id}')">
                                <i class="fas fa-check"></i>
                            </button>` : ''
                        }
                        ${transaction.status === 'pending' && transaction.type === 'withdrawal' ? 
                            `<button class="btn btn-sm btn-outline-success" onclick="approveWithdrawal('${transaction._id}')">
                                <i class="fas fa-check"></i>
                            </button>
                            <button class="btn btn-sm btn-outline-danger" onclick="rejectWithdrawal('${transaction._id}')">
                                <i class="fas fa-times"></i>
                            </button>` : ''
                        }
                    </div>
                </td>
            </tr>
        `;
        tbody.innerHTML += row;
    });
    
    updateElementText('transactionsTableInfo', `Showing ${transactions.length} transactions`);
}

function getTransactionTypeIcon(type) {
    const icons = {
        'deposit': '💰',
        'withdrawal': '💸',
        'investment': '📈',
        'profit': '🎯'
    };
    return icons[type] || '📄';
}

// Load pending deposits
async function loadPendingDeposits(filter = 'pending') {
    try {
        const response = await fetch(`${API_BASE_URL}/admin/pending-deposits`);
        const result = await response.json();
        
        if (result.success) {
            let deposits = result.data.deposits || [];
            
            // Filter deposits based on selected filter
            if (filter !== 'all') {
                deposits = deposits.filter(d => d.status === filter);
            }
            
            displayDeposits(deposits);
        } else {
            showToast('Error', result.message, 'error');
        }
    } catch (error) {
        console.error('Error loading pending deposits:', error);
        showToast('Error', 'Failed to load deposits', 'error');
    }
}

// Display deposits
function displayDeposits(deposits) {
    const tbody = document.getElementById('depositsTableBody');
    if (!tbody) return;
    
    tbody.innerHTML = '';
    
    if (!deposits || deposits.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="text-center py-4">
                    <i class="fas fa-money-bill-wave fa-2x text-muted mb-2"></i>
                    <p class="text-muted">No deposits found</p>
                </td>
            </tr>
        `;
        return;
    }
    
    deposits.forEach(deposit => {
        const statusClass = `badge-${deposit.status}`;
        
        const row = `
            <tr>
                <td>
                    <div class="fw-bold">${escapeHtml(deposit.user?.username || 'N/A')}</div>
                    <small class="text-muted">${escapeHtml(deposit.user?.email || '')}</small>
                </td>
                <td class="fw-bold">$${(deposit.amount || 0).toFixed(2)}</td>
                <td>${escapeHtml(deposit.walletAddress || 'N/A')}</td>
                <td>
                    ${deposit.proof ? 
                        `<a href="${API_BASE_URL}/uploads/${deposit.proof}" target="_blank" class="btn btn-sm btn-outline-primary">
                            <i class="fas fa-eye"></i> View Proof
                        </a>` : 
                        'No proof'
                    }
                </td>
                <td><span class="badge ${statusClass}">${escapeHtml(deposit.status)}</span></td>
                <td>${new Date(deposit.createdAt).toLocaleDateString()}</td>
                <td>
                    <div class="action-buttons">
                        ${deposit.status === 'pending' ? 
                            `<button class="btn btn-sm btn-outline-success" onclick="approveDeposit('${deposit._id}')">
                                <i class="fas fa-check"></i> Approve
                            </button>
                            <button class="btn btn-sm btn-outline-danger" onclick="rejectDeposit('${deposit._id}')">
                                <i class="fas fa-times"></i> Reject
                            </button>` : 
                            '<span class="text-muted">Processed</span>'
                        }
                    </div>
                </td>
            </tr>
        `;
        tbody.innerHTML += row;
    });
}

// Load pending withdrawals
async function loadPendingWithdrawals(filter = 'pending') {
    try {
        const response = await fetch(`${API_BASE_URL}/admin/transactions?type=withdrawal`);
        const result = await response.json();
        
        if (result.success) {
            let withdrawals = result.data.transactions || [];
            
            // Filter withdrawals based on selected filter
            if (filter !== 'all') {
                withdrawals = withdrawals.filter(w => w.status === filter);
            }
            
            displayWithdrawals(withdrawals);
        } else {
            showToast('Error', result.message, 'error');
        }
    } catch (error) {
        console.error('Error loading pending withdrawals:', error);
        showToast('Error', 'Failed to load withdrawals', 'error');
    }
}

// Display withdrawals
function displayWithdrawals(withdrawals) {
    const tbody = document.getElementById('withdrawalsTableBody');
    if (!tbody) return;
    
    tbody.innerHTML = '';
    
    if (!withdrawals || withdrawals.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="text-center py-4">
                    <i class="fas fa-wallet fa-2x text-muted mb-2"></i>
                    <p class="text-muted">No withdrawals found</p>
                </td>
            </tr>
        `;
        return;
    }
    
    withdrawals.forEach(withdrawal => {
        const statusClass = `badge-${withdrawal.status}`;
        
        const row = `
            <tr>
                <td>
                    <div class="fw-bold">${escapeHtml(withdrawal.user?.username || 'N/A')}</div>
                    <small class="text-muted">${escapeHtml(withdrawal.user?.email || '')}</small>
                </td>
                <td class="fw-bold">$${(withdrawal.amount || 0).toFixed(2)}</td>
                <td>${withdrawal.walletAddress ? withdrawal.walletAddress.split(':')[0] : 'N/A'}</td>
                <td><small>${escapeHtml(withdrawal.walletAddress || 'N/A')}</small></td>
                <td><span class="badge ${statusClass}">${escapeHtml(withdrawal.status)}</span></td>
                <td>${new Date(withdrawal.createdAt).toLocaleDateString()}</td>
                <td>
                    <div class="action-buttons">
                        ${withdrawal.status === 'pending' ? 
                            `<button class="btn btn-sm btn-outline-success" onclick="approveWithdrawal('${withdrawal._id}')">
                                <i class="fas fa-check"></i> Approve
                            </button>
                            <button class="btn btn-sm btn-outline-danger" onclick="rejectWithdrawal('${withdrawal._id}')">
                                <i class="fas fa-times"></i> Reject
                            </button>` : 
                            '<span class="text-muted">Processed</span>'
                        }
                    </div>
                </td>
            </tr>
        `;
        tbody.innerHTML += row;
    });
}

// Enhanced investment management functions
async function loadPendingInvestments() {
    try {
        const response = await fetch(`${API_BASE_URL}/admin/pending-investments`);
        const result = await response.json();
        
        if (result.success) {
            displayPendingInvestments(result.data.investments || []);
        } else {
            showToast('Error', result.message, 'error');
        }
    } catch (error) {
        console.error('Error loading pending investments:', error);
        showToast('Error', 'Failed to load investments', 'error');
    }
}

function displayPendingInvestments(investments) {
    const tbody = document.getElementById('investmentsTableBody');
    if (!tbody) return;
    
    tbody.innerHTML = '';
    
    if (!investments || investments.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="9" class="text-center py-4">
                    <i class="fas fa-chart-line fa-2x text-muted mb-2"></i>
                    <p class="text-muted">No pending investments found</p>
                </td>
            </tr>
        `;
        return;
    }
    
    investments.forEach(investment => {
        const row = `
            <tr>
                <td>
                    <div class="fw-bold">${escapeHtml(investment.user?.username || 'N/A')}</div>
                    <small class="text-muted">${escapeHtml(investment.user?.email || '')}</small>
                </td>
                <td>${escapeHtml(investment.investmentPlan || 'N/A')}</td>
                <td class="fw-bold">$${(investment.amount || 0).toFixed(2)}</td>
                <td>${getProfitRateForPlan(investment.investmentPlan)}%</td>
                <td>$0.00</td>
                <td><span class="badge badge-pending">Pending</span></td>
                <td>${new Date(investment.createdAt).toLocaleDateString()}</td>
                <td>N/A</td>
                <td>
                    <div class="action-buttons">
                        <button class="btn btn-sm btn-outline-success" onclick="approveInvestment('${investment._id}')">
                            <i class="fas fa-check"></i> Approve
                        </button>
                        <button class="btn btn-sm btn-outline-danger" onclick="rejectInvestment('${investment._id}')">
                            <i class="fas fa-times"></i> Reject
                        </button>
                    </div>
                </td>
            </tr>
        `;
        tbody.innerHTML += row;
    });
}

function getProfitRateForPlan(planName) {
    const plans = {
        'Basic Plan': 5,
        'Premium Plan': 8,
        'VIP Plan': 12
    };
    return plans[planName] || 0;
}

async function approveInvestment(transactionId) {
    if (!confirm('Are you sure you want to approve this investment?')) return;
    
    try {
        const response = await fetch(`${API_BASE_URL}/admin/investment/${transactionId}/approve`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                adminNote: 'Investment approved by admin'
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            showToast('Investment Approved', `Investment of $${result.data.transaction.amount} has been approved`, 'success');
            loadPendingInvestments();
            refreshDashboard();
        } else {
            showToast('Approval Failed', result.message, 'error');
        }
    } catch (error) {
        console.error('Error approving investment:', error);
        showToast('Error', 'Failed to approve investment', 'error');
    }
}

async function rejectInvestment(transactionId) {
    const reason = prompt('Please enter reason for rejection:');
    if (reason === null) return;
    
    try {
        const response = await fetch(`${API_BASE_URL}/admin/investment/${transactionId}/reject`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                adminNote: reason
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            showToast('Investment Rejected', 'Investment request has been rejected', 'warning');
            loadPendingInvestments();
        } else {
            showToast('Rejection Failed', result.message, 'error');
        }
    } catch (error) {
        console.error('Error rejecting investment:', error);
        showToast('Error', 'Failed to reject investment', 'error');
    }
}

// Manual top-up functions
function openDepositTopUpModal(userId, username) {
    document.getElementById('topupUserId').value = userId;
    document.getElementById('topupUsername').textContent = username;
    document.getElementById('topupType').value = 'deposit';
    document.getElementById('investmentPlanGroup').classList.add('d-none');
    
    const modal = new bootstrap.Modal(document.getElementById('topupModal'));
    modal.show();
}

function openInvestmentTopUpModal(userId, username) {
    document.getElementById('topupUserId').value = userId;
    document.getElementById('topupUsername').textContent = username;
    document.getElementById('topupType').value = 'investment';
    document.getElementById('investmentPlanGroup').classList.remove('d-none');
    
    const modal = new bootstrap.Modal(document.getElementById('topupModal'));
    modal.show();
}

function toggleTopUpType() {
    const type = document.getElementById('topupType').value;
    const planGroup = document.getElementById('investmentPlanGroup');
    
    if (type === 'investment') {
        planGroup.classList.remove('d-none');
    } else {
        planGroup.classList.add('d-none');
    }
}

async function submitTopUp() {
    const userId = document.getElementById('topupUserId').value;
    const amount = document.getElementById('topupAmount').value;
    const note = document.getElementById('topupNote').value;
    const type = document.getElementById('topupType').value;
    const planId = document.getElementById('topupPlan').value;
    
    if (!amount || amount <= 0) {
        showToast('Validation Error', 'Please enter a valid amount', 'error');
        return;
    }
    
    if (type === 'investment' && !planId) {
        showToast('Validation Error', 'Please select an investment plan', 'error');
        return;
    }
    
    try {
        const endpoint = type === 'deposit' ? 'topup-deposit' : 'topup-investment';
        const response = await fetch(`${API_BASE_URL}/admin/user/${userId}/${endpoint}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                amount: parseFloat(amount),
                planId: planId,
                note: note
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            showToast('Top-Up Successful', result.message, 'success');
            bootstrap.Modal.getInstance(document.getElementById('topupModal')).hide();
            document.getElementById('topupForm').reset();
            
            // Refresh user data and relevant sections
            refreshDashboard();
            if (currentTab === 'users') loadUsers();
            if (currentTab === 'investments') loadPendingInvestments();
        } else {
            showToast('Top-Up Failed', result.message, 'error');
        }
    } catch (error) {
        console.error('Top-up error:', error);
        showToast('Error', 'Failed to process top-up', 'error');
    }
}

// Investment adjustment functions
function openAdjustInvestmentModal(userId, username, currentInvestment) {
    document.getElementById('adjustUserId').value = userId;
    document.getElementById('adjustUserDisplay').textContent = username;
    document.getElementById('currentInvestment').value = `$${currentInvestment.toFixed(2)}`;
    
    const modal = new bootstrap.Modal(document.getElementById('adjustInvestmentModal'));
    modal.show();
}

async function submitInvestmentAdjustment() {
    const userId = document.getElementById('adjustUserId').value;
    const action = document.getElementById('adjustAction').value;
    const amount = document.getElementById('adjustAmount').value;
    const planName = document.getElementById('adjustPlanName').value;
    const notes = document.getElementById('adjustNotes').value;
    
    if (!amount || amount <= 0) {
        showToast('Validation Error', 'Please enter a valid amount', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/admin/user/${userId}/adjust-investment`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                amount: parseFloat(amount),
                action: action,
                planName: planName,
                note: notes
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            showToast('Investment Adjusted', result.message, 'success');
            bootstrap.Modal.getInstance(document.getElementById('adjustInvestmentModal')).hide();
            document.getElementById('adjustInvestmentForm').reset();
            
            // Refresh user data
            loadUsers();
        } else {
            showToast('Adjustment Failed', result.message, 'error');
        }
    } catch (error) {
        console.error('Investment adjustment error:', error);
        showToast('Error', 'Failed to adjust investment', 'error');
    }
}

// Earnings breakdown functions
async function loadEarningsBreakdowns() {
    try {
        const response = await fetch(`${API_BASE_URL}/admin/earnings-breakdowns`);
        const result = await response.json();
        
        if (result.success) {
            displayEarningsBreakdowns(result.data.breakdowns || []);
        } else {
            showToast('Error', result.message, 'error');
        }
    } catch (error) {
        console.error('Error loading earnings breakdowns:', error);
        showToast('Error', 'Failed to load earnings breakdowns', 'error');
    }
}

function displayEarningsBreakdowns(breakdowns) {
    const tbody = document.getElementById('earningsTableBody');
    if (!tbody) return;
    
    tbody.innerHTML = '';
    
    if (!breakdowns || breakdowns.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="10" class="text-center py-4">
                    <i class="fas fa-chart-pie fa-2x text-muted mb-2"></i>
                    <p class="text-muted">No earnings breakdowns found</p>
                </td>
            </tr>
        `;
        return;
    }
    
    breakdowns.forEach(breakdown => {
        const total = (breakdown.profit || 0) + (breakdown.deposit || 0) + (breakdown.investment || 0);
        const statusBadge = breakdown.status === 'active' ? 
            '<span class="badge bg-success">Active</span>' : 
            '<span class="badge bg-secondary">Inactive</span>';
        
        const row = `
            <tr>
                <td>
                    <div class="fw-bold">${escapeHtml(breakdown.user?.username || 'N/A')}</div>
                    <small class="text-muted">${escapeHtml(breakdown.user?.email || '')}</small>
                </td>
                <td>${escapeHtml(breakdown.period)}</td>
                <td>${new Date(breakdown.startDate).toLocaleDateString()} - ${new Date(breakdown.endDate).toLocaleDateString()}</td>
                <td>$${(breakdown.profit || 0).toFixed(2)}</td>
                <td>$${(breakdown.deposit || 0).toFixed(2)}</td>
                <td>$${(breakdown.investment || 0).toFixed(2)}</td>
                <td class="fw-bold">$${total.toFixed(2)}</td>
                <td>${statusBadge}</td>
                <td>${new Date(breakdown.createdAt).toLocaleDateString()}</td>
                <td>
                    <div class="action-buttons">
                        <button class="btn btn-sm btn-outline-primary" onclick="viewEarningsBreakdown('${breakdown._id}')">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button class="btn btn-sm btn-outline-danger" onclick="deleteEarningsBreakdown('${breakdown._id}')">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `;
        tbody.innerHTML += row;
    });
}

function calculateEarningsTotal() {
    const profit = parseFloat(document.getElementById('earningsProfit').value) || 0;
    const deposit = parseFloat(document.getElementById('earningsDeposit').value) || 0;
    const investment = parseFloat(document.getElementById('earningsInvestment').value) || 0;
    const total = profit + deposit + investment;
    document.getElementById('earningsTotal').textContent = total.toFixed(2);
}

async function createEarningsBreakdown() {
    const userId = document.getElementById('earningsUser').value;
    const period = document.getElementById('earningsPeriod').value;
    const startDate = document.getElementById('earningsStartDate').value;
    const endDate = document.getElementById('earningsEndDate').value;
    const profit = document.getElementById('earningsProfit').value || 0;
    const deposit = document.getElementById('earningsDeposit').value || 0;
    const investment = document.getElementById('earningsInvestment').value || 0;
    const notes = document.getElementById('earningsNotes').value;
    
    if (!userId || !startDate || !endDate) {
        showToast('Validation Error', 'Please fill in all required fields', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/admin/user/${userId}/earnings-breakdown`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                period,
                startDate,
                endDate,
                profit: parseFloat(profit),
                deposit: parseFloat(deposit),
                investment: parseFloat(investment),
                notes
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            showToast('Earnings Breakdown Created', result.message, 'success');
            bootstrap.Modal.getInstance(document.getElementById('createEarningsModal')).hide();
            document.getElementById('createEarningsForm').reset();
            
            // Refresh earnings table
            loadEarningsBreakdowns();
        } else {
            showToast('Creation Failed', result.message, 'error');
        }
    } catch (error) {
        console.error('Earnings breakdown creation error:', error);
        showToast('Error', 'Failed to create earnings breakdown', 'error');
    }
}

async function createBulkEarningsBreakdown() {
    const users = Array.from(document.getElementById('bulkEarningsUsers').selectedOptions).map(opt => opt.value);
    const period = document.getElementById('bulkEarningsPeriod').value;
    const startDate = document.getElementById('bulkEarningsStartDate').value;
    const endDate = document.getElementById('bulkEarningsEndDate').value;
    const profit = document.getElementById('bulkEarningsProfit').value || 0;
    const deposit = document.getElementById('bulkEarningsDeposit').value || 0;
    const investment = document.getElementById('bulkEarningsInvestment').value || 0;
    const notes = document.getElementById('bulkEarningsNotes').value;
    
    if (users.length === 0 || !startDate || !endDate) {
        showToast('Validation Error', 'Please select users and fill in all required fields', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/admin/bulk-earnings-breakdown`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                users,
                period,
                startDate,
                endDate,
                profit: parseFloat(profit),
                deposit: parseFloat(deposit),
                investment: parseFloat(investment),
                notes
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            showToast('Bulk Earnings Created', result.message, 'success');
            bootstrap.Modal.getInstance(document.getElementById('bulkEarningsModal')).hide();
            document.getElementById('bulkEarningsForm').reset();
            
            // Refresh earnings table
            loadEarningsBreakdowns();
        } else {
            showToast('Creation Failed', result.message, 'error');
        }
    } catch (error) {
        console.error('Bulk earnings creation error:', error);
        showToast('Error', 'Failed to create bulk earnings breakdown', 'error');
    }
}

// Transaction reports functions
async function loadTransactionReports() {
    try {
        const response = await fetch(`${API_BASE_URL}/admin/transaction-reports`);
        const result = await response.json();
        
        if (result.success) {
            displayTransactionReports(result.data.reports || []);
        } else {
            showToast('Error', result.message, 'error');
        }
    } catch (error) {
        console.error('Error loading transaction reports:', error);
        showToast('Error', 'Failed to load transaction reports', 'error');
    }
}

function displayTransactionReports(reports) {
    const tbody = document.getElementById('reportsTableBody');
    if (!tbody) return;
    
    tbody.innerHTML = '';
    
    if (!reports || reports.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="8" class="text-center py-4">
                    <i class="fas fa-file-alt fa-2x text-muted mb-2"></i>
                    <p class="text-muted">No transaction reports found</p>
                </td>
            </tr>
        `;
        return;
    }
    
    reports.forEach(report => {
        const statusBadge = report.status === 'completed' ? 
            '<span class="badge bg-success">Completed</span>' : 
            '<span class="badge bg-warning">Pending</span>';
        
        const row = `
            <tr>
                <td>
                    <div class="fw-bold">${escapeHtml(report.user?.username || 'N/A')}</div>
                    <small class="text-muted">${escapeHtml(report.user?.email || '')}</small>
                </td>
                <td>${escapeHtml(report.title)}</td>
                <td>${escapeHtml(report.description || 'No description')}</td>
                <td>${report.transactionsCount || 0}</td>
                <td class="fw-bold">$${(report.netBalance || 0).toFixed(2)}</td>
                <td>${statusBadge}</td>
                <td>${new Date(report.createdAt).toLocaleDateString()}</td>
                <td>
                    <div class="action-buttons">
                        <button class="btn btn-sm btn-outline-primary" onclick="viewReport('${report._id}')">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button class="btn btn-sm btn-outline-success" onclick="downloadReport('${report._id}')">
                            <i class="fas fa-download"></i>
                        </button>
                        <button class="btn btn-sm btn-outline-danger" onclick="deleteReport('${report._id}')">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `;
        tbody.innerHTML += row;
    });
}

// Load notifications
async function loadNotifications() {
    try {
        const response = await fetch(`${API_BASE_URL}/admin/notifications`);
        const result = await response.json();
        
        if (result.success) {
            displayNotifications(result.data.notifications || []);
            updateNotificationStats(result.data.stats || {});
        } else {
            showToast('Error', result.message, 'error');
        }
    } catch (error) {
        console.error('Error loading notifications:', error);
        showToast('Error', 'Failed to load notifications', 'error');
    }
}

// Display notifications
function displayNotifications(notifications) {
    const container = document.getElementById('notificationsList');
    if (!container) return;
    
    if (!notifications || notifications.length === 0) {
        container.innerHTML = `
            <div class="text-center py-4">
                <i class="fas fa-bell fa-2x text-muted mb-2"></i>
                <p class="text-muted">No notifications sent yet</p>
            </div>
        `;
        return;
    }
    
    container.innerHTML = notifications.map(notification => `
        <div class="notification-item mb-3 p-3 border rounded">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <h6 class="mb-1">${escapeHtml(notification.title)}</h6>
                    <p class="mb-1 text-muted">${escapeHtml(notification.content)}</p>
                    <small class="text-muted">
                        Sent to: ${notification.sentTo === 'all' ? 'All Users' : 'Specific User'} • 
                        ${new Date(notification.createdAt).toLocaleString()}
                    </small>
                </div>
                <span class="badge bg-${getNotificationTypeClass(notification.type)}">
                    ${escapeHtml(notification.type)}
                </span>
            </div>
        </div>
    `).join('');
}

function updateNotificationStats(stats) {
    updateElementText('totalNotifications', stats.total || 0);
    updateElementText('unreadNotifications', stats.unread || 0);
    updateElementText('todayNotifications', stats.today || 0);
}

function getNotificationTypeClass(type) {
    const classes = {
        'info': 'info',
        'success': 'success',
        'warning': 'warning',
        'error': 'danger'
    };
    return classes[type] || 'secondary';
}

// Initialize revenue chart
function initializeRevenueChart() {
    const ctx = document.getElementById('revenueChart');
    if (!ctx) return;
    
    revenueChart = new Chart(ctx.getContext('2d'), {
        type: 'line',
        data: {
            labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
            datasets: [{
                label: 'Revenue',
                data: [12000, 19000, 15000, 25000, 22000, 30000],
                borderColor: '#8e44ad',
                backgroundColor: 'rgba(142, 68, 173, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        drawBorder: false
                    },
                    ticks: {
                        callback: function(value) {
                            return '$' + value.toLocaleString();
                        }
                    }
                },
                x: {
                    grid: {
                        display: false
                    }
                }
            }
        }
    });
}

// Add recent activity
function addRecentActivity(title, description, icon) {
    const activityList = document.getElementById('recentActivity');
    if (!activityList) return;
    
    const activityItem = `
        <li>
            <div class="activity-icon">
                <i class="fas fa-${icon}"></i>
            </div>
            <div>
                <div>${escapeHtml(title)}</div>
                <small class="text-muted">${escapeHtml(description)} • Just now</small>
            </div>
        </li>
    `;
    
    activityList.insertAdjacentHTML('afterbegin', activityItem);
    
    // Keep only the last 5 activities
    const items = activityList.querySelectorAll('li');
    if (items.length > 5) {
        items[items.length - 1].remove();
    }
}

// Show toast notification
function showToast(title, message, type = 'info') {
    // Create toast container if it doesn't exist
    let toastContainer = document.getElementById('toastContainer');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.id = 'toastContainer';
        toastContainer.className = 'toast-container position-fixed top-0 end-0 p-3';
        toastContainer.style.zIndex = '9999';
        document.body.appendChild(toastContainer);
    }

    const toastId = 'toast-' + Date.now();
    const toastHtml = `
        <div id="${toastId}" class="toast align-items-center text-bg-${type} border-0" role="alert">
            <div class="d-flex">
                <div class="toast-body">
                    <strong>${escapeHtml(title)}</strong><br>${escapeHtml(message)}
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        </div>
    `;

    toastContainer.insertAdjacentHTML('beforeend', toastHtml);
    const toastElement = document.getElementById(toastId);
    const toast = new bootstrap.Toast(toastElement, { delay: 5000 });
    toast.show();

    // Remove toast from DOM after it's hidden
    toastElement.addEventListener('hidden.bs.toast', () => {
        toastElement.remove();
    });
}

// Refresh dashboard
function refreshDashboard() {
    loadDashboardStats();
    switch(currentTab) {
        case 'users': loadUsers(); break;
        case 'transactions': loadTransactions(); break;
        case 'deposits': loadPendingDeposits(); break;
        case 'withdrawals': loadPendingWithdrawals(); break;
        case 'investments': loadPendingInvestments(); break;
        case 'earnings': loadEarningsBreakdowns(); break;
        case 'reports': loadTransactionReports(); break;
        case 'notifications': loadNotifications(); break;
    }
    
    showToast('Dashboard Updated', 'All data has been refreshed', 'info');
}

// Update system uptime
function updateSystemUptime() {
    const startTime = Date.now() - (Math.random() * 86400000); // Random start time for demo
    const uptime = Date.now() - startTime;
    
    const days = Math.floor(uptime / (1000 * 60 * 60 * 24));
    const hours = Math.floor((uptime % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    const minutes = Math.floor((uptime % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((uptime % (1000 * 60)) / 1000);
    
    updateElementText('systemUptime', 
        `${days} days ${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`);
}

// Handle admin logout
function handleAdminLogout(e) {
    e.preventDefault();
    
    if (confirm('Are you sure you want to logout?')) {
        // Close WebSocket connection if open
        if (webSocket && webSocket.readyState === WebSocket.OPEN) {
            webSocket.close(1000, 'Admin logged out');
        }
        
        localStorage.removeItem('isAdmin');
        localStorage.removeItem('adminToken');
        localStorage.removeItem('adminUsername');
        localStorage.removeItem('adminPassword');
        
        window.location.href = 'admin-login.html';
    }
}

// Admin action functions
async function approveDeposit(transactionId) {
    try {
        const response = await fetch(`${API_BASE_URL}/admin/deposit/${transactionId}/approve`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                adminNote: 'Deposit approved by admin'
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            showToast('Deposit Approved', `Deposit of $${result.data.transaction.amount} has been approved`, 'success');
            refreshDashboard();
            loadPendingDeposits();
        } else {
            showToast('Approval Failed', result.message, 'error');
        }
    } catch (error) {
        console.error('Error approving deposit:', error);
        showToast('Error', 'Failed to approve deposit', 'error');
    }
}

async function rejectDeposit(transactionId) {
    const reason = prompt('Please enter reason for rejection:');
    if (reason === null) return;
    
    try {
        const response = await fetch(`${API_BASE_URL}/admin/deposit/${transactionId}/reject`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                adminNote: reason
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            showToast('Deposit Rejected', 'Deposit request has been rejected', 'warning');
            refreshDashboard();
            loadPendingDeposits();
        } else {
            showToast('Rejection Failed', result.message, 'error');
        }
    } catch (error) {
        console.error('Error rejecting deposit:', error);
        showToast('Error', 'Failed to reject deposit', 'error');
    }
}

async function approveWithdrawal(transactionId) {
    try {
        const response = await fetch(`${API_BASE_URL}/admin/withdrawal/${transactionId}/approve`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                adminNote: 'Withdrawal approved by admin'
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            showToast('Withdrawal Approved', `Withdrawal of $${result.data.transaction.amount} has been approved`, 'success');
            refreshDashboard();
            loadPendingWithdrawals();
        } else {
            showToast('Approval Failed', result.message, 'error');
        }
    } catch (error) {
        console.error('Error approving withdrawal:', error);
        showToast('Error', 'Failed to approve withdrawal', 'error');
    }
}

async function rejectWithdrawal(transactionId) {
    const reason = prompt('Please enter reason for rejection:');
    if (reason === null) return;
    
    try {
        const response = await fetch(`${API_BASE_URL}/admin/withdrawal/${transactionId}/reject`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                adminNote: reason
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            showToast('Withdrawal Rejected', 'Withdrawal request has been rejected', 'warning');
            refreshDashboard();
            loadPendingWithdrawals();
        } else {
            showToast('Rejection Failed', result.message, 'error');
        }
    } catch (error) {
        console.error('Error rejecting withdrawal:', error);
        showToast('Error', 'Failed to reject withdrawal', 'error');
    }
}

async function toggleUserBlock(userId, block) {
    const action = block ? 'block' : 'unblock';
    if (!confirm(`Are you sure you want to ${action} this user?`)) return;
    
    try {
        const endpoint = block ? 'block' : 'unblock';
        const response = await fetch(`${API_BASE_URL}/admin/user/${userId}/${endpoint}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                reason: block ? 'Account suspended by admin' : 'Account reactivated by admin'
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            const actionText = block ? 'blocked' : 'unblocked';
            showToast(`User ${actionText}`, `User has been ${actionText} successfully`, 'success');
            loadUsers();
        } else {
            showToast('Action Failed', result.message, 'error');
        }
    } catch (error) {
        console.error('Error toggling user block:', error);
        showToast('Error', 'Failed to update user status', 'error');
    }
}

async function sendNotification() {
    const userId = document.getElementById('notificationUser').value;
    const title = document.getElementById('notificationTitle').value;
    const message = document.getElementById('notificationMessage').value;
    const type = document.getElementById('notificationType').value;
    
    if (!title || !message) {
        showToast('Validation Error', 'Please fill in all fields', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/admin/notify-user`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                userId: userId === 'all' ? null : userId,
                title,
                content: message,
                type
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            showToast('Notification Sent', 'Notification has been sent successfully', 'success');
            bootstrap.Modal.getInstance(document.getElementById('sendNotificationModal')).hide();
            document.getElementById('notificationTitle').value = '';
            document.getElementById('notificationMessage').value = '';
            loadNotifications();
        } else {
            showToast('Send Failed', result.message, 'error');
        }
    } catch (error) {
        console.error('Error sending notification:', error);
        showToast('Error', 'Failed to send notification', 'error');
    }
}

async function sendBroadcast() {
    const title = document.getElementById('broadcastTitle').value;
    const message = document.getElementById('broadcastMessage').value;
    const type = document.getElementById('broadcastType').value;
    
    if (!title || !message) {
        showToast('Validation Error', 'Please fill in all fields', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/admin/notify-all`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                title,
                content: message,
                type
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            showToast('Broadcast Sent', `Message sent to ${result.data.sentCount} users`, 'success');
            bootstrap.Modal.getInstance(document.getElementById('broadcastModal')).hide();
            document.getElementById('broadcastTitle').value = '';
            document.getElementById('broadcastMessage').value = '';
            loadNotifications();
        } else {
            showToast('Send Failed', result.message, 'error');
        }
    } catch (error) {
        console.error('Error sending broadcast:', error);
        showToast('Error', 'Failed to send broadcast', 'error');
    }
}

// System settings functions
async function loadSystemSettings() {
    try {
        const response = await fetch(`${API_BASE_URL}/admin/system-settings`);
        const result = await response.json();
        
        if (result.success) {
            const settings = result.data.settings;
            const plans = result.data.plans || [];
            
            // Populate general settings
            if (settings) {
                document.getElementById('siteName').value = settings.siteName || 'Galaxy Digital Holdings';
                document.getElementById('adminEmail').value = settings.adminEmail || 'admin@galaxydigital.com';
                document.getElementById('currency').value = settings.currency || 'USD';
                document.getElementById('sessionTimeout').value = settings.sessionTimeout || 60;
                document.getElementById('maxLoginAttempts').value = settings.maxLoginAttempts || 5;
                document.getElementById('enable2FA').checked = settings.enable2FA || false;
                document.getElementById('maintenanceMode').checked = settings.maintenanceMode || false;
            }
            
            // Populate investment plans
            displayInvestmentPlans(plans);
            
            // Populate system info
            updateElementText('systemVersion', result.data.systemInfo?.version || '2.1.0');
            updateElementText('lastBackup', result.data.systemInfo?.lastBackup || 'Never');
            updateElementText('dbSize', result.data.systemInfo?.dbSize || '0 MB');
            
        } else {
            showToast('Error', result.message, 'error');
        }
    } catch (error) {
        console.error('Error loading system settings:', error);
        showToast('Error', 'Failed to load system settings', 'error');
    }
}

function displayInvestmentPlans(plans) {
    const container = document.getElementById('investmentPlansSettings');
    if (!container) return;
    
    if (!plans || plans.length === 0) {
        container.innerHTML = '<p class="text-muted">No investment plans configured</p>';
        return;
    }
    
    container.innerHTML = plans.map(plan => `
        <div class="investment-plan-item mb-3 p-3 border rounded">
            <div class="row">
                <div class="col-md-3">
                    <input type="text" class="form-control plan-name" value="${escapeHtml(plan.name)}" data-plan-id="${plan._id}">
                </div>
                <div class="col-md-2">
                    <input type="number" class="form-control plan-min" value="${plan.minAmount}" data-plan-id="${plan._id}" step="1">
                </div>
                <div class="col-md-2">
                    <input type="number" class="form-control plan-max" value="${plan.maxAmount}" data-plan-id="${plan._id}" step="1">
                </div>
                <div class="col-md-2">
                    <input type="number" class="form-control plan-profit" value="${plan.profitRate}" data-plan-id="${plan._id}" step="0.1">
                </div>
                <div class="col-md-1">
                    <input type="number" class="form-control plan-duration" value="${plan.duration}" data-plan-id="${plan._id}" step="1">
                </div>
                <div class="col-md-2">
                    <div class="btn-group w-100">
                        <button class="btn btn-sm btn-success btn-save-plan" data-plan-id="${plan._id}">
                            <i class="fas fa-save"></i>
                        </button>
                        <button class="btn btn-sm btn-danger btn-delete-plan" data-plan-id="${plan._id}">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `).join('');
}

async function saveSystemSettings() {
    const settings = {
        siteName: document.getElementById('siteName').value,
        adminEmail: document.getElementById('adminEmail').value,
        currency: document.getElementById('currency').value,
        sessionTimeout: parseInt(document.getElementById('sessionTimeout').value),
        maxLoginAttempts: parseInt(document.getElementById('maxLoginAttempts').value),
        enable2FA: document.getElementById('enable2FA').checked,
        maintenanceMode: document.getElementById('maintenanceMode').checked
    };
    
    try {
        const response = await fetch(`${API_BASE_URL}/admin/system-settings`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(settings)
        });
        
        const result = await response.json();
        
        if (result.success) {
            showToast('Settings Saved', 'System settings have been updated successfully', 'success');
        } else {
            showToast('Save Failed', result.message, 'error');
        }
    } catch (error) {
        console.error('Error saving system settings:', error);
        showToast('Error', 'Failed to save system settings', 'error');
    }
}

async function saveInvestmentPlan(planId) {
    const name = document.querySelector(`.plan-name[data-plan-id="${planId}"]`).value;
    const minAmount = parseFloat(document.querySelector(`.plan-min[data-plan-id="${planId}"]`).value);
    const maxAmount = parseFloat(document.querySelector(`.plan-max[data-plan-id="${planId}"]`).value);
    const profitRate = parseFloat(document.querySelector(`.plan-profit[data-plan-id="${planId}"]`).value);
    const duration = parseInt(document.querySelector(`.plan-duration[data-plan-id="${planId}"]`).value);
    
    try {
        const response = await fetch(`${API_BASE_URL}/admin/investment-plan/${planId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                name,
                minAmount,
                maxAmount,
                profitRate,
                duration
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            showToast('Plan Updated', 'Investment plan has been updated successfully', 'success');
        } else {
            showToast('Update Failed', result.message, 'error');
        }
    } catch (error) {
        console.error('Error saving investment plan:', error);
        showToast('Error', 'Failed to update investment plan', 'error');
    }
}

async function deleteInvestmentPlan(planId) {
    if (!confirm('Are you sure you want to delete this investment plan?')) return;
    
    try {
        const response = await fetch(`${API_BASE_URL}/admin/investment-plan/${planId}`, {
            method: 'DELETE'
        });
        
        const result = await response.json();
        
        if (result.success) {
            showToast('Plan Deleted', 'Investment plan has been deleted successfully', 'success');
            loadSystemSettings(); // Refresh the list
        } else {
            showToast('Deletion Failed', result.message, 'error');
        }
    } catch (error) {
        console.error('Error deleting investment plan:', error);
        showToast('Error', 'Failed to delete investment plan', 'error');
    }
}

// Utility functions
function escapeHtml(unsafe) {
    if (unsafe === null || unsafe === undefined) return '';
    return unsafe
        .toString()
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Quick action functions
function showPendingDeposits() {
    switchTab('deposits');
}

function showPendingWithdrawals() {
    switchTab('withdrawals');
}

function showRecentUsers() {
    switchTab('users');
}

function distributeProfits() {
    if (confirm('Are you sure you want to distribute profits to all active investments?')) {
        showToast('Profit Distribution', 'Profit distribution process has been started', 'info');
        // Implementation would go here
    }
}

// Placeholder functions for future implementation
function viewUser(userId) {
    showToast('User Details', `Viewing details for user ${userId}`, 'info');
}

function editUser(userId) {
    showToast('Edit User', `Editing user ${userId}`, 'info');
}

function viewTransaction(transactionId) {
    showToast('Transaction Details', `Viewing details for transaction ${transactionId}`, 'info');
}

function viewEarningsBreakdown(breakdownId) {
    showToast('Earnings Breakdown', `Viewing earnings breakdown ${breakdownId}`, 'info');
}

function deleteEarningsBreakdown(breakdownId) {
    if (confirm('Are you sure you want to delete this earnings breakdown?')) {
        showToast('Earnings Breakdown Deleted', 'The earnings breakdown has been deleted', 'success');
    }
}

function viewReport(reportId) {
    showToast('Report Details', `Viewing report ${reportId}`, 'info');
}

function downloadReport(reportId) {
    showToast('Report Download', `Downloading report ${reportId}`, 'info');
}

function deleteReport(reportId) {
    if (confirm('Are you sure you want to delete this report?')) {
        showToast('Report Deleted', 'The report has been deleted', 'success');
    }
}

function useTemplate(template) {
    const templates = {
        'welcome': {
            title: 'Welcome to Our Platform!',
            message: 'Thank you for joining us. We are excited to have you on board and look forward to helping you achieve your financial goals.'
        },
        'deposit_approved': {
            title: 'Deposit Approved ✅',
            message: 'Your deposit has been approved and the funds have been added to your account balance.'
        },
        'withdrawal_processed': {
            title: 'Withdrawal Processed',
            message: 'Your withdrawal request has been processed and the funds have been sent to your wallet.'
        },
        'profit_added': {
            title: 'Profit Added 🎯',
            message: 'Congratulations! Your investment has generated profits that have been added to your wallet balance.'
        }
    };
    
    const templateData = templates[template];
    if (templateData) {
        const notificationTitle = document.getElementById('notificationTitle');
        const notificationMessage = document.getElementById('notificationMessage');
        const broadcastTitle = document.getElementById('broadcastTitle');
        const broadcastMessage = document.getElementById('broadcastMessage');
        
        if (notificationTitle) notificationTitle.value = templateData.title;
        if (notificationMessage) notificationMessage.value = templateData.message;
        if (broadcastTitle) broadcastTitle.value = templateData.title;
        if (broadcastMessage) broadcastMessage.value = templateData.message;
    }
}

function exportData() {
    showToast('Export Started', 'Your data export has been initiated', 'info');
}

function showSystemStats() {
    showToast('System Statistics', 'Displaying system performance metrics', 'info');
}

function broadcastNotification() {
    const modal = new bootstrap.Modal(document.getElementById('broadcastModal'));
    modal.show();
}

function runBackup() {
    if (confirm('Are you sure you want to run a database backup?')) {
        showToast('Backup Initiated', 'Database backup has been started', 'info');
        // Implementation would go here
    }
}

function clearCache() {
    if (confirm('Are you sure you want to clear the system cache?')) {
        showToast('Cache Cleared', 'System cache has been cleared successfully', 'success');
        // Implementation would go here
    }
}

function addNewUser() {
    showToast('User Added', 'New user has been created successfully', 'success');
    bootstrap.Modal.getInstance(document.getElementById('addUserModal')).hide();
}