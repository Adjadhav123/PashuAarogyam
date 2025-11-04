// Dashboard JavaScript

document.addEventListener('DOMContentLoaded', function() {
    initializeDashboard();
    animateStats();
    initializeUserMenu();
});

function initializeDashboard() {
    // Initialize any dashboard-specific functionality
    const quickActionButtons = document.querySelectorAll('.quick-actions .btn');
    quickActionButtons.forEach(button => {
        button.addEventListener('click', handleQuickAction);
    });
    
    // Initialize feature cards
    const featureButtons = document.querySelectorAll('.feature-card .btn');
    featureButtons.forEach(button => {
        button.addEventListener('click', handleFeatureAction);
    });
}

function animateStats() {
    // Animate statistics when they come into view
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                animateStatCard(entry.target);
            }
        });
    }, { threshold: 0.5 });
    
    const statCards = document.querySelectorAll('.dashboard-stats .stat-card');
    statCards.forEach(card => observer.observe(card));
}

function animateStatCard(card) {
    const statNumber = card.querySelector('.stat-number');
    const finalValue = statNumber.textContent;
    
    // Only animate numeric values
    if (/^\d+/.test(finalValue)) {
        const numericValue = parseInt(finalValue.replace(/\D/g, ''));
        animateCounter(statNumber, 0, numericValue, finalValue);
    }
}

function animateCounter(element, start, end, finalText) {
    const duration = 2000; // 2 seconds
    const increment = (end - start) / (duration / 16); // 60fps
    let current = start;
    
    const timer = setInterval(() => {
        current += increment;
        if (current >= end) {
            current = end;
            clearInterval(timer);
            element.textContent = finalText; // Use original text (may include %, +, etc.)
        } else {
            element.textContent = Math.floor(current).toLocaleString();
        }
    }, 16);
}

function initializeUserMenu() {
    // Handle user menu dropdown
    const userMenu = document.querySelector('.user-menu');
    const userInfo = document.querySelector('.user-info');
    const userDropdown = document.querySelector('.user-dropdown');
    
    if (userMenu && userInfo && userDropdown) {
        let hoverTimeout;
        
        userMenu.addEventListener('mouseenter', () => {
            clearTimeout(hoverTimeout);
            userDropdown.style.display = 'block';
        });
        
        userMenu.addEventListener('mouseleave', () => {
            hoverTimeout = setTimeout(() => {
                userDropdown.style.display = 'none';
            }, 300);
        });
    }
}

function handleQuickAction(e) {
    const actionText = e.target.textContent.trim();
    
    if (actionText.includes('Disease Prediction')) {
        openPredictionModal();
    } else if (actionText.includes('Health Reports')) {
        showHealthReports();
    }
}

function handleFeatureAction(e) {
    const featureCard = e.target.closest('.feature-card');
    const featureTitle = featureCard.querySelector('h3').textContent;
    
    switch (featureTitle) {
        case 'Disease Detection':
            openPredictionModal();
            break;
        case 'Veterinary Consultant':
            showAlert('Veterinary consultation booking will be available soon!', 'info');
            break;
        case 'AI Veterinary Assistant':
            showAlert('AI Assistant chat feature coming soon!', 'info');
            break;
        default:
            showAlert('This feature is coming soon!', 'info');
    }
}

function showHealthReports() {
    // Show health reports functionality
    showAlert('Health reports feature is under development. You can view your recent predictions below!', 'info');
    
    // Scroll to recent predictions section
    const predictionsSection = document.querySelector('.recent-predictions');
    if (predictionsSection) {
        predictionsSection.scrollIntoView({ behavior: 'smooth' });
    }
}

// Enhanced prediction modal functionality for dashboard
function openPredictionModal() {
    const modal = document.getElementById('predictionModal');
    if (modal) {
        modal.style.display = 'block';
        
        // Reset form
        const form = document.getElementById('predictionForm');
        if (form) {
            form.reset();
        }
        
        // Reset any previous results
        const resultDiv = document.getElementById('predictionResult');
        if (resultDiv) {
            resultDiv.style.display = 'none';
        }
        
        const loadingDiv = document.querySelector('.loading');
        if (loadingDiv) {
            loadingDiv.style.display = 'none';
        }
    }
}

// Enhanced alert system for dashboard
function showAlert(message, type = 'info', duration = 5000) {
    // Remove existing alerts
    const existingAlerts = document.querySelectorAll('.dashboard-alert');
    existingAlerts.forEach(alert => alert.remove());
    
    // Create new alert
    const alertDiv = document.createElement('div');
    alertDiv.className = `dashboard-alert alert alert-${type}`;
    alertDiv.style.cssText = `
        position: fixed;
        top: 100px;
        right: 20px;
        z-index: 3000;
        max-width: 400px;
        border-radius: 8px;
        padding: 1rem 1.5rem;
        box-shadow: 0 4px 20px rgba(0,0,0,0.15);
        animation: slideInRight 0.3s ease;
        backdrop-filter: blur(10px);
    `;
    
    // Set alert styling based on type
    const alertStyles = {
        success: { bg: '#d4edda', color: '#155724', border: '#c3e6cb' },
        error: { bg: '#f8d7da', color: '#721c24', border: '#f5c6cb' },
        warning: { bg: '#fff3cd', color: '#856404', border: '#ffeaa7' },
        info: { bg: '#d1ecf1', color: '#0c5460', border: '#bee5eb' }
    };
    
    const style = alertStyles[type] || alertStyles.info;
    alertDiv.style.backgroundColor = style.bg;
    alertDiv.style.color = style.color;
    alertDiv.style.border = `1px solid ${style.border}`;
    
    alertDiv.innerHTML = `
        <div style="display: flex; align-items: flex-start; justify-content: space-between; gap: 1rem;">
            <div style="flex: 1;">
                <div style="font-weight: 600; margin-bottom: 0.25rem;">${getAlertIcon(type)} ${getAlertTitle(type)}</div>
                <div style="font-size: 0.9rem; line-height: 1.4;">${message}</div>
            </div>
            <button onclick="this.parentElement.parentElement.remove()" 
                    style="background: none; border: none; font-size: 1.2rem; cursor: pointer; color: inherit; opacity: 0.7; padding: 0; width: 20px; height: 20px; display: flex; align-items: center; justify-content: center;">
                ×
            </button>
        </div>
    `;
    
    document.body.appendChild(alertDiv);
    
    // Auto-remove after duration
    setTimeout(() => {
        if (alertDiv.parentNode) {
            alertDiv.style.animation = 'slideOutRight 0.3s ease';
            setTimeout(() => alertDiv.remove(), 300);
        }
    }, duration);
}

function getAlertIcon(type) {
    const icons = {
        success: '✅',
        error: '❌',
        warning: '⚠️',
        info: 'ℹ️'
    };
    return icons[type] || icons.info;
}

function getAlertTitle(type) {
    const titles = {
        success: 'Success',
        error: 'Error',
        warning: 'Warning',
        info: 'Information'
    };
    return titles[type] || titles.info;
}

// Add CSS for animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideInRight {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOutRight {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
    
    .dashboard-stats .stat-card {
        transition: transform 0.3s ease, box-shadow 0.3s ease;
    }
    
    .dashboard-stats .stat-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 10px 25px rgba(46, 139, 87, 0.15);
    }
    
    .prediction-card {
        animation: fadeInUp 0.5s ease;
    }
    
    @keyframes fadeInUp {
        from {
            opacity: 0;
            transform: translateY(20px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
`;
document.head.appendChild(style);

// Make functions globally available
window.showHealthReports = showHealthReports;
window.showAlert = showAlert;