// API Base URL - Update this to match your backend URL
const API_BASE_URL = '/api';

// State management
let currentUser = null;
let authToken = localStorage.getItem('authToken');
let isAdmin = localStorage.getItem('isAdmin') === 'true';
let investmentPlans = [];
let webSocket = null;
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 5;

// Check if user is authenticated
document.addEventListener('DOMContentLoaded', function() {
    if (!authToken || isAdmin) {
        window.location.href = 'login.html';
        return;
    }
    
    fetchUserData();
    setupEventListeners();
    loadInvestmentPlans();
    
    // Initialize WebSocket connection
    initializeWebSocket();
    
    // Set up periodic data refresh
    setInterval(fetchUserData, 30000); // Refresh every 30 seconds
});

// Enhanced WebSocket initialization with reconnection
function initializeWebSocket() {
    if (webSocket && webSocket.readyState === WebSocket.OPEN) {
        return;
    }

    try {
        updateConnectionStatus('connecting', 'Connecting to real-time updates...');
        
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws`;
        
        webSocket = new WebSocket(wsUrl);
        
        webSocket.onopen = function() {
            console.log('✅ WebSocket connected successfully');
            reconnectAttempts = 0;
            updateConnectionStatus('connected', 'Real-time Updates Active');
            
            // Authenticate with the server
            webSocket.send(JSON.stringify({
                type: 'AUTH',
                token: authToken
            }));
        };
        
        webSocket.onmessage = function(event) {
            try {
                const data = JSON.parse(event.data);
                console.log('📨 WebSocket message received:', data);
                handleWebSocketMessage(data);
            } catch (error) {
                console.error('❌ Error parsing WebSocket message:', error);
            }
        };
        
        webSocket.onclose = function(event) {
            console.log('❌ WebSocket disconnected:', event.code, event.reason);
            updateConnectionStatus('disconnected', 'Real-time updates disconnected');
            
            // Attempt reconnection
            if (reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
                const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
                console.log(`🔄 Attempting reconnection in ${delay}ms (attempt ${reconnectAttempts + 1})`);
                
                setTimeout(() => {
                    reconnectAttempts++;
                    initializeWebSocket();
                }, delay);
            } else {
                console.error('❌ Max reconnection attempts reached');
                updateConnectionStatus('error', 'Failed to connect to real-time updates');
            }
        };
        
        webSocket.onerror = function(error) {
            console.error('❌ WebSocket error:', error);
            updateConnectionStatus('error', 'Connection error');
        };
        
    } catch (error) {
        console.error('❌ Error initializing WebSocket:', error);
        updateConnectionStatus('error', 'Failed to initialize connection');
    }
}

function updateConnectionStatus(status, message) {
    const statusElement = document.getElementById('realTimeStatus');
    const indicator = document.getElementById('connectionIndicator');
    
    statusElement.className = `badge me-2 connection-status ${
        status === 'connected' ? 'bg-success' : 
        status === 'connecting' ? 'bg-warning' : 
        'bg-danger'
    }`;
    
    indicator.className = `status-indicator ${
        status === 'connected' ? 'status-connected' : 
        status === 'connecting' ? 'status-connecting' : 
        'status-disconnected'
    }`;
    
    statusElement.innerHTML = `<span class="status-indicator ${indicator.className}"></span>${message}`;
}

// Enhanced WebSocket message handler
function handleWebSocketMessage(data) {
    switch (data.type) {
        case 'CONNECTED':
            updateConnectionStatus('connected', 'Real-time Updates Active');
            showToast('Connected', 'Real-time updates are now active', 'success');
            break;
            
        case 'BALANCE_UPDATE':
            updateUserBalances(data);
            updateLastUpdateTime();
            showToast('Balance Updated', data.message || 'Your balances have been updated', 'info');
            break;
            
        case 'DEPOSIT_APPROVED':
            updateUserBalances(data);
            loadTransactions();
            updateLastUpdateTime();
            showToast('Deposit Approved', `Deposit of $${data.amount} has been approved`, 'success');
            break;
            
        case 'WITHDRAWAL_APPROVED':
            updateUserBalances(data);
            loadTransactions();
            updateLastUpdateTime();
            showToast('Withdrawal Approved', `Withdrawal of $${data.amount} has been approved`, 'success');
            break;
            
        case 'WITHDRAWAL_REJECTED':
            updateUserBalances(data);
            loadTransactions();
            updateLastUpdateTime();
            showToast('Withdrawal Rejected', data.message || 'Your withdrawal request was rejected', 'error');
            break;
            
        case 'INVESTMENT_APPROVED':
            updateUserBalances(data);
            loadActiveInvestments();
            updateLastUpdateTime();
            showToast('Investment Approved', `Your investment of $${data.amount} has been approved and activated`, 'success');
            break;
            
        case 'INVESTMENT_REJECTED':
            loadTransactions();
            updateLastUpdateTime();
            showToast('Investment Rejected', data.message || 'Your investment request was rejected', 'error');
            break;
            
        case 'INVESTMENT_TOPUP':
            updateUserBalances(data);
            loadActiveInvestments();
            loadTransactions();
            updateLastUpdateTime();
            showToast('Investment Added', `Admin added a new investment of $${data.amount} to your account`, 'success');
            break;
            
        case 'DEPOSIT_TOPUP':
            updateUserBalances(data);
            loadTransactions();
            updateLastUpdateTime();
            showToast('Deposit Top-Up', `Admin added $${data.amount} to your deposit balance`, 'success');
            break;
            
        case 'PROFIT_ADDED':
            updateUserBalances(data);
            loadTransactions();
            updateLastUpdateTime();
            showToast('Profit Added', `$${data.amount} profit has been added to your account`, 'success');
            break;
            
        case 'NEW_NOTIFICATION':
            loadUserNotifications();
            if (data.notification) {
                showToast('New Notification', data.notification.title, 'info');
            }
            break;
            
        case 'ADMIN_BALANCE_ADJUSTMENT':
            updateUserBalances(data);
            updateLastUpdateTime();
            showToast('Balance Adjusted', data.message || 'Admin has adjusted your balance', 'warning');
            break;
            
        case 'ACCOUNT_BLOCKED':
            showToast('Account Blocked', 'Your account has been blocked by admin', 'error');
            setTimeout(() => {
                handleLogout();
            }, 3000);
            break;
            
        case 'ACCOUNT_UNBLOCKED':
            showToast('Account Unblocked', 'Your account has been reactivated', 'success');
            break;
            
        default:
            console.log('Unhandled WebSocket message type:', data.type);
    }
}

// Toast notification function
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

// Utility function to escape HTML
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

// Fetch user data with the auth token
async function fetchUserData() {
    try {
        const response = await fetch(`${API_BASE_URL}/me`, {
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        });

        if (response.ok) {
            const result = await response.json();
            if (result.success) {
                currentUser = result.data.user;
                updateDashboardData();
                
                // Load additional data if not already loaded
                if (document.getElementById('transactionsTab').classList.contains('active')) {
                    loadTransactions();
                }
                if (document.getElementById('referralsTab').classList.contains('active')) {
                    loadReferrals();
                }
                if (document.getElementById('investTab').classList.contains('active')) {
                    loadActiveInvestments();
                }
                if (document.getElementById('notificationsTab').classList.contains('active')) {
                    loadUserNotifications();
                }
                if (document.getElementById('earningsTab').classList.contains('active')) {
                    loadUserEarnings();
                }
                if (document.getElementById('reportsTab').classList.contains('active')) {
                    loadUserTransactionReports();
                }
            } else {
                // Token is invalid, redirect to login
                window.location.href = 'login.html';
            }
        } else {
            // Token is invalid, redirect to login
            window.location.href = 'login.html';
        }
    } catch (error) {
        console.error('Error fetching user data:', error);
        // Don't redirect on network errors, just log
    }
}

// Update dashboard with user data
function updateDashboardData() {
    if (currentUser) {
        document.getElementById('userName').textContent = currentUser.name;
        document.getElementById('walletBalance').textContent = currentUser.walletBalance ? currentUser.walletBalance.toFixed(2) : '0.00';
        document.getElementById('depositBalance').textContent = currentUser.depositBalance ? currentUser.depositBalance.toFixed(2) : '0.00';
        document.getElementById('totalInvested').textContent = currentUser.totalInvested ? currentUser.totalInvested.toFixed(2) : '0.00';
        document.getElementById('availableBalance').textContent = currentUser.depositBalance ? currentUser.depositBalance.toFixed(2) : '0.00';
        
        // Update recent transactions in overview
        loadRecentTransactions();
    }
}

// Load recent transactions for overview tab
async function loadRecentTransactions() {
    try {
        const response = await fetch(`${API_BASE_URL}/user/transactions?limit=5`, {
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        });
        
        const result = await response.json();
        
        if (result.success && result.data && result.data.length > 0) {
            const container = document.getElementById('recentTransactions');
            let html = '';
            
            result.data.slice(0, 5).forEach(transaction => {
                const date = new Date(transaction.createdAt).toLocaleDateString();
                const statusClass = `status-${transaction.status}`;
                const icon = getTransactionIcon(transaction.type);
                
                html += `
                    <div class="transaction-item">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <h6 class="mb-1">${icon} ${transaction.type.charAt(0).toUpperCase() + transaction.type.slice(1)}</h6>
                                <small class="text-muted">${date}</small>
                            </div>
                            <div class="text-end">
                                <div class="fw-bold">$${transaction.amount.toFixed(2)}</div>
                                <span class="transaction-status ${statusClass}">${transaction.status}</span>
                            </div>
                        </div>
                    </div>
                `;
            });
            
            container.innerHTML = html;
        }
    } catch (error) {
        console.error('Error loading recent transactions:', error);
    }
}

function getTransactionIcon(type) {
    const icons = {
        'deposit': '💰',
        'withdrawal': '💸',
        'investment': '📈',
        'profit': '🎯'
    };
    return icons[type] || '📄';
}

// Switch between dashboard tabs
function switchTab(tabName) {
    // Hide all tab contents
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Remove active class from all tab buttons
    document.querySelectorAll('.tab-button').forEach(button => {
        button.classList.remove('active');
    });
    
    // Show the selected tab content
    document.getElementById(tabName + 'Tab').classList.add('active');
    
    // Add active class to the clicked button
    event.target.classList.add('active');
    
    // Load specific data for the tab
    switch(tabName) {
        case 'transactions':
            loadTransactions();
            break;
        case 'referrals':
            loadReferrals();
            break;
        case 'invest':
            loadActiveInvestments();
            break;
        case 'profile':
            loadProfileData();
            break;
        case 'notifications':
            loadUserNotifications();
            break;
        case 'overview':
            loadRecentTransactions();
            break;
        case 'earnings':
            loadUserEarnings();
            break;
        case 'reports':
            loadUserTransactionReports();
            break;
    }
}

// Setup event listeners
function setupEventListeners() {
    // Logout button
    document.getElementById('logoutNavLink').addEventListener('click', handleLogout);
    
    // Deposit form submission
    document.getElementById('depositForm').addEventListener('submit', handleDeposit);
    
    // Withdrawal form submission
    document.getElementById('withdrawalForm').addEventListener('submit', handleWithdrawal);
    
    // Investment form submission
    document.getElementById('investmentForm').addEventListener('submit', handleInvestment);
    
    // Profile form submission
    document.getElementById('profileForm').addEventListener('submit', handleProfileUpdate);
    
    // Password form submission
    document.getElementById('passwordForm').addEventListener('submit', handlePasswordChange);
    
    // Security form submission
    document.getElementById('securityForm').addEventListener('submit', handleSecurityUpdate);
    
    // Check approved deposits button
    document.getElementById('checkApprovedDeposits').addEventListener('click', checkApprovedDeposits);
    
    // Modal show events to refresh data
    document.getElementById('depositModal').addEventListener('show.bs.modal', function() {
        document.getElementById('availableBalance').textContent = currentUser ? currentUser.depositBalance.toFixed(2) : '0.00';
    });
    
    document.getElementById('withdrawalModal').addEventListener('show.bs.modal', function() {
        document.getElementById('withdrawalAmount').setAttribute('max', currentUser ? currentUser.walletBalance : 0);
    });
    
    document.getElementById('investmentModal').addEventListener('show.bs.modal', function() {
        document.getElementById('availableBalance').textContent = currentUser ? currentUser.depositBalance.toFixed(2) : '0.00';
    });
}

// Handle logout
function handleLogout(e) {
    if (e) e.preventDefault();
    
    // Close WebSocket connection if open
    if (webSocket && webSocket.readyState === WebSocket.OPEN) {
        webSocket.close(1000, 'User logged out');
    }
    
    localStorage.removeItem('authToken');
    localStorage.removeItem('isAdmin');
    authToken = null;
    isAdmin = false;
    currentUser = null;
    window.location.href = 'index.html';
}

// Handle deposit
async function handleDeposit(e) {
    e.preventDefault();
    const amount = document.getElementById('depositAmount').value;
    const method = document.getElementById('depositMethod').value;
    const proofFile = document.getElementById('depositProof').files[0];
    const alertEl = document.getElementById('depositAlert');
    
    if (!proofFile) {
        alertEl.className = 'alert alert-danger';
        alertEl.textContent = 'Please select a proof of payment file.';
        alertEl.classList.remove('d-none');
        return;
    }
    
    const formData = new FormData();
    formData.append('amount', amount);
    formData.append('walletAddress', method);
    formData.append('proof', proofFile);
    
    try {
        const response = await fetch(`${API_BASE_URL}/deposits`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${authToken}`
            },
            body: formData
        });
        
        const result = await response.json();
        
        if (result.success) {
            alertEl.className = 'alert alert-success';
            alertEl.textContent = result.message;
            alertEl.classList.remove('d-none');
            
            // Reset form and close modal after 2 seconds
            setTimeout(() => {
                document.getElementById('depositForm').reset();
                bootstrap.Modal.getInstance(document.getElementById('depositModal')).hide();
                alertEl.classList.add('d-none');
                
                // Refresh user data and transactions
                fetchUserData();
                loadTransactions();
                
                showToast('Deposit Submitted', 'Your deposit has been submitted for approval', 'success');
            }, 2000);
        } else {
            alertEl.className = 'alert alert-danger';
            alertEl.textContent = result.message;
            alertEl.classList.remove('d-none');
        }
    } catch (error) {
        console.error('Deposit error:', error);
        alertEl.className = 'alert alert-danger';
        alertEl.textContent = 'An error occurred during deposit submission. Please try again.';
        alertEl.classList.remove('d-none');
    }
}

// Handle withdrawal
async function handleWithdrawal(e) {
    e.preventDefault();
    const amount = parseFloat(document.getElementById('withdrawalAmount').value);
    const method = document.getElementById('withdrawalMethod').value;
    const walletAddress = document.getElementById('withdrawalWallet').value;
    const alertEl = document.getElementById('withdrawalAlert');
    
    if (currentUser && amount > currentUser.walletBalance) {
        alertEl.className = 'alert alert-danger';
        alertEl.textContent = 'Insufficient wallet balance for this withdrawal.';
        alertEl.classList.remove('d-none');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/withdrawals`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                amount, 
                walletAddress: `${method}: ${walletAddress}` 
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            alertEl.className = 'alert alert-success';
            alertEl.textContent = result.message;
            alertEl.classList.remove('d-none');
            
            // Reset form and close modal after 2 seconds
            setTimeout(() => {
                document.getElementById('withdrawalForm').reset();
                bootstrap.Modal.getInstance(document.getElementById('withdrawalModal')).hide();
                alertEl.classList.add('d-none');
                
                // Refresh user data and transactions
                fetchUserData();
                loadTransactions();
                
                showToast('Withdrawal Submitted', 'Your withdrawal request has been submitted', 'success');
            }, 2000);
        } else {
            alertEl.className = 'alert alert-danger';
            alertEl.textContent = result.message;
            alertEl.classList.remove('d-none');
        }
    } catch (error) {
        console.error('Withdrawal error:', error);
        alertEl.className = 'alert alert-danger';
        alertEl.textContent = 'An error occurred during withdrawal submission. Please try again.';
        alertEl.classList.remove('d-none');
    }
}

// Handle investment
async function handleInvestment(e) {
    e.preventDefault();
    const planId = document.getElementById('investmentPlan').value;
    const amount = parseFloat(document.getElementById('investmentAmount').value);
    const alertEl = document.getElementById('investmentAlert');
    
    if (currentUser && amount > currentUser.depositBalance) {
        alertEl.className = 'alert alert-danger';
        alertEl.textContent = 'Insufficient deposit balance for this investment.';
        alertEl.classList.remove('d-none');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/investments`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ planId, amount })
        });
        
        const result = await response.json();
        
        if (result.success) {
            alertEl.className = 'alert alert-success';
            alertEl.textContent = result.message;
            alertEl.classList.remove('d-none');
            
            // Reset form and close modal after 2 seconds
            setTimeout(() => {
                document.getElementById('investmentForm').reset();
                bootstrap.Modal.getInstance(document.getElementById('investmentModal')).hide();
                alertEl.classList.add('d-none');
                
                // Refresh user data and investments
                fetchUserData();
                loadActiveInvestments();
                
                showToast('Investment Submitted', 'Your investment request has been submitted', 'success');
            }, 2000);
        } else {
            alertEl.className = 'alert alert-danger';
            alertEl.textContent = result.message;
            alertEl.classList.remove('d-none');
        }
    } catch (error) {
        console.error('Investment error:', error);
        alertEl.className = 'alert alert-danger';
        alertEl.textContent = 'An error occurred during investment submission. Please try again.';
        alertEl.classList.remove('d-none');
    }
}

// Handle profile update
async function handleProfileUpdate(e) {
    e.preventDefault();
    const formData = {
        name: document.getElementById('profileName').value,
        bitcoinAccount: document.getElementById('profileBitcoin').value,
        tetherTRC20Account: document.getElementById('profileTether').value
    };
    
    try {
        const response = await fetch(`${API_BASE_URL}/user/profile`, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(formData)
        });
        
        const result = await response.json();
        
        if (result.success) {
            // Show success message
            showToast('Profile Updated', 'Your profile has been updated successfully', 'success');
            
            // Update current user data
            currentUser = { ...currentUser, ...formData };
            document.getElementById('userName').textContent = currentUser.name;
        } else {
            showToast('Update Failed', result.message || 'Failed to update profile', 'error');
        }
    } catch (error) {
        console.error('Profile update error:', error);
        showToast('Update Failed', 'An error occurred while updating your profile', 'error');
    }
}

// Handle password change
async function handlePasswordChange(e) {
    e.preventDefault();
    const formData = {
        currentPassword: document.getElementById('currentPassword').value,
        newPassword: document.getElementById('newPassword').value,
        confirmNewPassword: document.getElementById('confirmNewPassword').value
    };
    
    if (formData.newPassword !== formData.confirmNewPassword) {
        showToast('Password Mismatch', 'New passwords do not match', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/user/change-password`, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(formData)
        });
        
        const result = await response.json();
        
        if (result.success) {
            showToast('Password Changed', 'Your password has been changed successfully', 'success');
            document.getElementById('passwordForm').reset();
        } else {
            showToast('Password Change Failed', result.message || 'Failed to change password', 'error');
        }
    } catch (error) {
        console.error('Password change error:', error);
        showToast('Password Change Failed', 'An error occurred while changing your password', 'error');
    }
}

// Handle security update
async function handleSecurityUpdate(e) {
    e.preventDefault();
    const formData = {
        secretQuestion: document.getElementById('securityQuestion').value,
        secretAnswer: document.getElementById('securityAnswer').value
    };
    
    try {
        const response = await fetch(`${API_BASE_URL}/user/profile`, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(formData)
        });
        
        const result = await response.json();
        
        if (result.success) {
            showToast('Security Updated', 'Your security settings have been updated', 'success');
        } else {
            showToast('Update Failed', result.message || 'Failed to update security settings', 'error');
        }
    } catch (error) {
        console.error('Security update error:', error);
        showToast('Update Failed', 'An error occurred while updating security settings', 'error');
    }
}

// Check for approved deposits
async function checkApprovedDeposits() {
    try {
        const response = await fetch(`${API_BASE_URL}/user/check-approved-deposits`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
                }
        });
        
        const result = await response.json();
        
        if (result.success) {
            if (result.data.processedCount > 0) {
                // Update balances
                fetchUserData();
                showToast('Deposits Processed', result.message, 'success');
            } else {
                showToast('No New Deposits', result.message, 'info');
            }
        }
    } catch (error) {
        console.error('Error checking approved deposits:', error);
        showToast('Check Failed', 'Failed to check for approved deposits', 'error');
    }
}

// Load investment plans
async function loadInvestmentPlans() {
    try {
        const response = await fetch(`${API_BASE_URL}/investment-plans`);
        const result = await response.json();
        
        if (result.success) {
            investmentPlans = result.data;
            displayInvestmentPlans();
        }
    } catch (error) {
        console.error('Error loading investment plans:', error);
    }
}

// Display investment plans
function displayInvestmentPlans() {
    const container = document.getElementById('investmentPlansContainer');
    container.innerHTML = '';
    
    investmentPlans.forEach(plan => {
        const planCard = document.createElement('div');
        planCard.className = 'col-md-4';
        planCard.innerHTML = `
            <div class="card plan-card ${plan.name.toLowerCase().includes('basic') ? 'basic' : plan.name.toLowerCase().includes('premium') ? 'premium' : 'vip'}">
                <div class="plan-header">
                    <h4>${escapeHtml(plan.name)}</h4>
                    <h3 class="text-primary">${plan.profitRate}% Profit</h3>
                    <p class="text-muted">${plan.duration}</p>
                </div>
                <div class="plan-body">
                    <p>${escapeHtml(plan.description)}</p>
                    <ul class="plan-features">
                        <li><i class="fas fa-check text-success me-2"></i> Min: $${plan.minDeposit}</li>
                        <li><i class="fas fa-check text-success me-2"></i> Max: $${plan.maxDeposit}</li>
                        <li><i class="fas fa-check text-success me-2"></i> ${plan.profitRate}% Return</li>
                        <li><i class="fas fa-check text-success me-2"></i> Secure Investment</li>
                    </ul>
                    <div class="mt-3">
                        <h6>Wallet Address for Payment:</h6>
                        <div class="wallet-address mb-2" onclick="copyWalletAddress('${plan.name}')">
                            ${getWalletAddress(plan.name)}
                        </div>
                        <small class="text-muted">Click to copy wallet address</small>
                    </div>
                    <button class="btn btn-primary-custom w-100 mt-3" onclick="openInvestmentModal('${plan._id}')">
                        Invest Now
                    </button>
                </div>
            </div>
        `;
        container.appendChild(planCard);
    });
}

// Get wallet address based on plan
function getWalletAddress(planName) {
    // These would typically come from your backend
    const addresses = {
        'Basic Plan': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
        'Premium Plan': '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy',
        'VIP Plan': 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh'
    };
    
    return addresses[planName] || 'Wallet address not available';
}

// Copy wallet address to clipboard
function copyWalletAddress(planName) {
    const address = getWalletAddress(planName);
    navigator.clipboard.writeText(address).then(() => {
        // Visual feedback
        const walletElement = event.target;
        walletElement.classList.add('copied');
        walletElement.innerHTML = `<i class="fas fa-check me-2"></i>Copied!`;
        
        setTimeout(() => {
            walletElement.classList.remove('copied');
            walletElement.textContent = address;
        }, 2000);
        
        showToast('Address Copied', 'Wallet address copied to clipboard', 'success');
    });
}

// Copy referral code to clipboard
function copyReferralCode() {
    const referralCode = document.getElementById('referralCodeDisplay').value;
    navigator.clipboard.writeText(referralCode).then(() => {
        // Visual feedback
        const button = event.target;
        const originalText = button.textContent;
        button.textContent = 'Copied!';
        button.classList.add('btn-success');
        
        setTimeout(() => {
            button.textContent = originalText;
            button.classList.remove('btn-success');
        }, 2000);
        
        showToast('Referral Code Copied', 'Your referral code has been copied', 'success');
    });
}

// Open investment modal with selected plan
function openInvestmentModal(planId) {
    const plan = investmentPlans.find(p => p._id === planId);
    if (plan) {
        document.getElementById('investmentPlan').value = planId;
        document.getElementById('investmentAmount').setAttribute('min', plan.minDeposit);
        document.getElementById('investmentAmount').setAttribute('max', plan.maxDeposit);
        document.getElementById('investmentAmount').value = plan.minDeposit;
        
        const modal = new bootstrap.Modal(document.getElementById('investmentModal'));
        modal.show();
    }
}

// Load transactions
async function loadTransactions() {
    try {
        const filter = document.getElementById('transactionFilter').value;
        const url = filter === 'all' 
            ? `${API_BASE_URL}/user/transactions` 
            : `${API_BASE_URL}/user/transactions?type=${filter}`;
        
        const response = await fetch(url, {
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        });
        
        const result = await response.json();
        
        if (result.success) {
            displayTransactions(result.data);
        } else {
            document.getElementById('transactionHistory').innerHTML = '<p class="text-muted">Error loading transactions</p>';
        }
    } catch (error) {
        console.error('Error loading transactions:', error);
        document.getElementById('transactionHistory').innerHTML = '<p class="text-muted">Error loading transactions</p>';
    }
}

// Display transactions
function displayTransactions(transactions) {
    const container = document.getElementById('transactionHistory');
    
    if (!transactions || transactions.length === 0) {
        container.innerHTML = '<p class="text-muted">No transactions found</p>';
        return;
    }
    
    let html = '';
    transactions.forEach(transaction => {
        const date = new Date(transaction.createdAt).toLocaleDateString();
        const statusClass = `status-${transaction.status}`;
        const icon = getTransactionIcon(transaction.type);
        
        html += `
            <div class="transaction-item">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h6 class="mb-1">${icon} ${transaction.type.charAt(0).toUpperCase() + transaction.type.slice(1)}</h6>
                        <small class="text-muted">${date} • ${transaction.investmentPlan || ''}</small>
                    </div>
                    <div class="text-end">
                        <div class="fw-bold">$${transaction.amount.toFixed(2)}</div>
                        <span class="transaction-status ${statusClass}">${transaction.status}</span>
                    </div>
                </div>
            </div>
        `;
    });
    
    container.innerHTML = html;
}

// Load referrals
async function loadReferrals() {
    try {
        const response = await fetch(`${API_BASE_URL}/user/referrals`, {
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        });
        
        const result = await response.json();
        
        if (result.success) {
            document.getElementById('totalReferrals').textContent = result.data.totalReferrals;
            document.getElementById('referralCodeDisplay').value = result.data.referralCode;
            
            // Display referral list
            const referralList = document.getElementById('referralList');
            if (result.data.referrals && result.data.referrals.length > 0) {
                let html = '';
                result.data.referrals.forEach(referral => {
                    const date = new Date(referral.createdAt).toLocaleDateString();
                    html += `
                        <div class="transaction-item">
                            <div class="d-flex justify-content-between align-items-center">
                                <div>
                                    <h6 class="mb-1">${escapeHtml(referral.username)}</h6>
                                    <small class="text-muted">${escapeHtml(referral.email)} • Joined ${date}</small>
                                </div>
                                <div class="text-end">
                                    <div class="fw-bold">$${referral.totalInvested ? referral.totalInvested.toFixed(2) : '0.00'}</div>
                                    <small class="text-muted">Invested</small>
                                </div>
                            </div>
                        </div>
                    `;
                });
                referralList.innerHTML = html;
            } else {
                referralList.innerHTML = '<p class="text-muted">No referrals yet</p>';
            }
        }
    } catch (error) {
        console.error('Error loading referrals:', error);
    }
}

// Load active investments
async function loadActiveInvestments() {
    try {
        const response = await fetch(`${API_BASE_URL}/user/investments`, {
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        });
        
        const result = await response.json();
        
        if (result.success) {
            displayActiveInvestments(result.data);
        }
    } catch (error) {
        console.error('Error loading investments:', error);
    }
}

// Display active investments
function displayActiveInvestments(investments) {
    const container = document.getElementById('activeInvestments');
    
    if (!investments || investments.length === 0) {
        container.innerHTML = '<p class="text-muted">No active investments</p>';
        return;
    }
    
    let html = '';
    investments.forEach(investment => {
        const startDate = new Date(investment.startDate).toLocaleDateString();
        const endDate = investment.endDate ? new Date(investment.endDate).toLocaleDateString() : 'N/A';
        const profitEarned = investment.totalProfitEarned || 0;
        const statusClass = investment.status === 'active' ? 'status-approved' : 
                          investment.status === 'completed' ? 'status-pending' : 'status-rejected';
        
        html += `
            <div class="transaction-item">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h6 class="mb-1">${escapeHtml(investment.planName)}</h6>
                        <small class="text-muted">Started: ${startDate} • Ends: ${endDate}</small>
                        <br>
                        <small class="text-info">Profit Rate: ${investment.profitRate}% • Expected: $${investment.expectedProfit?.toFixed(2) || '0.00'}</small>
                    </div>
                    <div class="text-end">
                        <div class="fw-bold">$${investment.amount.toFixed(2)}</div>
                        <small class="text-success">+$${profitEarned.toFixed(2)} earned</small>
                        <div><span class="transaction-status ${statusClass}">${investment.status}</span></div>
                    </div>
                </div>
            </div>
        `;
    });
    
    container.innerHTML = html;
}

// Load profile data
function loadProfileData() {
    if (currentUser) {
        document.getElementById('profileName').value = currentUser.name || '';
        document.getElementById('profileEmail').value = currentUser.email || '';
        document.getElementById('profileBitcoin').value = currentUser.bitcoinAccount || '';
        document.getElementById('profileTether').value = currentUser.tetherTRC20Account || '';
        document.getElementById('securityQuestion').value = currentUser.secretQuestion || '';
    }
}

// Load user notifications
async function loadUserNotifications() {
    try {
        if (!authToken) return;
        
        const response = await fetch(`${API_BASE_URL}/user/notifications`, {
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        });
        
        if (response.ok) {
            const result = await response.json();
            if (result.success) {
                const notificationsList = document.getElementById('notificationsList');
                const notificationBadge = document.getElementById('notificationBadge');
                
                if (result.data.notifications && result.data.notifications.length > 0) {
                    let html = '';
                    result.data.notifications.forEach(notif => {
                        const date = new Date(notif.createdAt).toLocaleString();
                        const unreadClass = notif.isRead ? '' : 'unread';
                        const importantClass = notif.type === 'important' ? 'important' : '';
                        const icon = getNotificationIcon(notif.type);
                        
                        html += `
                            <div class="notification-item ${unreadClass} ${importantClass}">
                                <h6>${icon} ${escapeHtml(notif.title)}</h6>
                                <p>${escapeHtml(notif.content)}</p>
                                <small class="text-muted">${date}</small>
                                ${!notif.isRead ? `
                                    <button class="btn btn-sm btn-outline-primary mt-2" onclick="markNotificationAsRead('${notif._id}')">Mark as Read</button>
                                ` : ''}
                            </div>
                        `;
                    });
                    notificationsList.innerHTML = html;
                    
                    // Update notification badge
                    if (result.data.unreadCount > 0) {
                        notificationBadge.textContent = result.data.unreadCount;
                        notificationBadge.classList.remove('d-none');
                    } else {
                        notificationBadge.classList.add('d-none');
                    }
                } else {
                    notificationsList.innerHTML = '<p class="text-muted">No notifications</p>';
                    notificationBadge.classList.add('d-none');
                }
            }
        }
    } catch (error) {
        console.error('Error loading user notifications:', error);
    }
}

function getNotificationIcon(type) {
    const icons = {
        'info': 'ℹ️',
        'success': '✅',
        'warning': '⚠️',
        'error': '❌',
        'deposit': '💰',
        'withdrawal': '💸',
        'investment': '📈',
        'welcome': '👋'
    };
    return icons[type] || '📢';
}

// Mark notification as read
async function markNotificationAsRead(notificationId) {
    try {
        const response = await fetch(`${API_BASE_URL}/user/notifications/${notificationId}/read`, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        });
        
        if (response.ok) {
            loadUserNotifications();
            showToast('Notification Read', 'Notification marked as read', 'success');
        }
    } catch (error) {
        console.error('Error marking notification as read:', error);
    }
}

// Mark all notifications as read
async function markAllNotificationsAsRead() {
    try {
        const response = await fetch(`${API_BASE_URL}/user/notifications/read-all`, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        });
        
        if (response.ok) {
            loadUserNotifications();
            showToast('All Notifications Read', 'All notifications marked as read', 'success');
        }
    } catch (error) {
        console.error('Error marking all notifications as read:', error);
    }
}

function updateLastUpdateTime() {
    const now = new Date();
    document.getElementById('lastUpdate').textContent = `Last update: ${now.toLocaleTimeString()}`;
}

function updateUserBalances(data) {
    if (data.walletBalance !== undefined) {
        document.getElementById('walletBalance').textContent = data.walletBalance.toFixed(2);
        document.getElementById('walletUpdateTime').textContent = `Updated: ${new Date().toLocaleTimeString()}`;
    }
    if (data.depositBalance !== undefined) {
        document.getElementById('depositBalance').textContent = data.depositBalance.toFixed(2);
        document.getElementById('depositUpdateTime').textContent = `Updated: ${new Date().toLocaleTimeString()}`;
    }
    if (data.totalInvested !== undefined) {
        document.getElementById('totalInvested').textContent = data.totalInvested.toFixed(2);
        document.getElementById('investedUpdateTime').textContent = `Updated: ${new Date().toLocaleTimeString()}`;
    }
    if (data.availableBalance !== undefined) {
        document.getElementById('availableBalance').textContent = data.availableBalance.toFixed(2);
    }
    
    // Update current user object if it exists
    if (currentUser) {
        if (data.walletBalance !== undefined) currentUser.walletBalance = data.walletBalance;
        if (data.depositBalance !== undefined) currentUser.depositBalance = data.depositBalance;
        if (data.totalInvested !== undefined) currentUser.totalInvested = data.totalInvested;
    }
}

// Manual refresh function
function manualRefresh() {
    fetchUserData();
    showToast('Refreshing', 'Updating dashboard data...', 'info');
}

// User earnings and reports functions
async function loadUserEarnings() {
    try {
        const response = await fetch(`${API_BASE_URL}/user/earnings-breakdowns`, {
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        });
        
        const result = await response.json();
        
        if (result.success) {
            displayUserEarnings(result.data.earnings);
        }
    } catch (error) {
        console.error('Error loading user earnings:', error);
        document.getElementById('earningsHistory').innerHTML = `
            <tr>
                <td colspan="7" class="text-center py-4">
                    <p class="text-muted">Error loading earnings data</p>
                </td>
            </tr>
        `;
    }
}

function displayUserEarnings(earnings) {
    const container = document.getElementById('earningsHistory');
    
    if (!earnings || earnings.length === 0) {
        container.innerHTML = `
            <tr>
                <td colspan="7" class="text-center py-4">
                    <i class="fas fa-chart-pie fa-2x text-muted mb-2"></i>
                    <p class="text-muted">No earnings breakdown available yet</p>
                </td>
            </tr>
        `;
        return;
    }
    
    let totalEarnings = 0;
    let totalProfit = 0;
    let totalInvestmentEarnings = 0;
    
    let html = '';
    earnings.forEach(earning => {
        totalEarnings += earning.totalEarnings || 0;
        totalProfit += earning.profit || 0;
        totalInvestmentEarnings += earning.investment || 0;
        
        const statusBadge = earning.isFinalized ? 
            '<span class="badge bg-success">Finalized</span>' : 
            '<span class="badge bg-warning">Pending</span>';
        
        html += `
            <tr>
                <td>
                    <span class="text-capitalize">${earning.period}</span>
                </td>
                <td>
                    ${new Date(earning.startDate).toLocaleDateString()} - ${new Date(earning.endDate).toLocaleDateString()}
                </td>
                <td class="text-success">+$${(earning.profit || 0).toFixed(2)}</td>
                <td class="text-primary">+$${(earning.deposit || 0).toFixed(2)}</td>
                <td class="text-info">+$${(earning.investment || 0).toFixed(2)}</td>
                <td class="fw-bold text-dark">$${(earning.totalEarnings || 0).toFixed(2)}</td>
                <td>${statusBadge}</td>
            </tr>
        `;
    });
    
    container.innerHTML = html;
    
    // Update summary cards
    document.getElementById('totalEarnings').textContent = totalEarnings.toFixed(2);
    document.getElementById('totalProfit').textContent = totalProfit.toFixed(2);
    document.getElementById('totalInvestmentEarnings').textContent = totalInvestmentEarnings.toFixed(2);
}

async function loadUserTransactionReports() {
    try {
        const response = await fetch(`${API_BASE_URL}/user/transaction-reports`, {
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        });
        
        const result = await response.json();
        
        if (result.success) {
            displayUserTransactionReports(result.data.reports);
        }
    } catch (error) {
        console.error('Error loading user transaction reports:', error);
        document.getElementById('transactionReportsList').innerHTML = `
            <div class="text-center py-4">
                <p class="text-muted">Error loading transaction reports</p>
            </div>
        `;
    }
}

function displayUserTransactionReports(reports) {
    const container = document.getElementById('transactionReportsList');
    
    if (!reports || reports.length === 0) {
        container.innerHTML = `
            <div class="text-center py-4">
                <i class="fas fa-file-alt fa-2x text-muted mb-2"></i>
                <p class="text-muted">No transaction reports available yet</p>
            </div>
        `;
        return;
    }
    
    let html = '';
    reports.forEach(report => {
        html += `
            <div class="card mb-3">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-start">
                        <div>
                            <h5 class="card-title">${escapeHtml(report.title)}</h5>
                            <p class="card-text">${escapeHtml(report.description || 'No description provided')}</p>
                            <small class="text-muted">Generated on ${new Date(report.createdAt).toLocaleDateString()}</small>
                        </div>
                        <div class="text-end">
                            <div class="fw-bold text-success">Net: $${(report.summary?.netBalance || 0).toFixed(2)}</div>
                            <button class="btn btn-sm btn-outline-primary mt-2" onclick="viewTransactionReport('${report._id}')">
                                <i class="fas fa-eye me-1"></i>View Report
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
    });
    
    container.innerHTML = html;
}

// Placeholder function for viewing transaction report
function viewTransactionReport(reportId) {
    showToast('Report View', `Viewing report ${reportId}`, 'info');
    // Implementation would typically open a modal or new page with detailed report
}