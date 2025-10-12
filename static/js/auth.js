// Authentication JavaScript

document.addEventListener('DOMContentLoaded', function() {
    initializeAuthForms();
    initializePasswordStrength();
});

function initializeAuthForms() {
    // Login form
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }

    // Signup form
    const signupForm = document.getElementById('signupForm');
    if (signupForm) {
        signupForm.addEventListener('submit', handleSignup);
    }

    // Social login buttons
    const socialButtons = document.querySelectorAll('.social-button');
    socialButtons.forEach(button => {
        button.addEventListener('click', handleSocialLogin);
    });
}

function initializePasswordStrength() {
    const passwordField = document.getElementById('password');
    if (passwordField && document.getElementById('signupForm')) {
        passwordField.addEventListener('input', checkPasswordStrength);
    }
}

// Login handler
async function handleLogin(e) {
    e.preventDefault();
    
    const form = e.target;
    const button = form.querySelector('#loginButton');
    const buttonText = button.querySelector('.button-text');
    const buttonSpinner = button.querySelector('.button-spinner');
    
    // Clear previous errors
    clearFormErrors();
    
    // Get form data
    const formData = {
        email: form.email.value.trim(),
        password: form.password.value
    };
    
    // Basic validation
    if (!validateLoginForm(formData)) {
        return;
    }
    
    // Show loading state
    button.disabled = true;
    buttonText.style.display = 'none';
    buttonSpinner.style.display = 'block';
    
    try {
        const response = await fetch('/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(formData)
        });
        
        const data = await response.json();
        
        if (data.success) {
            showAlert('Login successful! Redirecting...', 'success');
            setTimeout(() => {
                window.location.href = data.redirect;
            }, 1000);
        } else {
            showAlert(data.message || 'Login failed', 'error');
        }
    } catch (error) {
        console.error('Login error:', error);
        showAlert('An error occurred during login. Please try again.', 'error');
    } finally {
        // Reset button state
        button.disabled = false;
        buttonText.style.display = 'block';
        buttonSpinner.style.display = 'none';
    }
}

// Signup handler
async function handleSignup(e) {
    e.preventDefault();
    
    const form = e.target;
    const button = form.querySelector('#signupButton');
    const buttonText = button.querySelector('.button-text');
    const buttonSpinner = button.querySelector('.button-spinner');
    
    // Clear previous errors
    clearFormErrors();
    
    // Get form data
    const formData = {
        name: form.name.value.trim(),
        email: form.email.value.trim(),
        password: form.password.value,
        confirm_password: form.confirm_password.value
    };
    
    // Validate form
    if (!validateSignupForm(formData)) {
        return;
    }
    
    // Show loading state
    button.disabled = true;
    buttonText.style.display = 'none';
    buttonSpinner.style.display = 'block';
    
    try {
        const response = await fetch('/auth/signup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(formData)
        });
        
        console.log('Response status:', response.status);
        console.log('Response headers:', response.headers);
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error('Error response:', errorText);
            throw new Error(`HTTP ${response.status}: ${errorText}`);
        }
        
        const data = await response.json();
        console.log('Response data:', data);
        
        if (data.success) {
            showAlert('Account created successfully! Redirecting...', 'success');
            setTimeout(() => {
                window.location.href = data.redirect;
            }, 1000);
        } else {
            showAlert(data.message || 'Signup failed', 'error');
        }
    } catch (error) {
        console.error('Signup error:', error);
        console.error('Error details:', {
            name: error.name,
            message: error.message,
            stack: error.stack
        });
        showAlert('An error occurred during signup. Please check the console for details.', 'error');
    } finally {
        // Reset button state
        button.disabled = false;
        buttonText.style.display = 'block';
        buttonSpinner.style.display = 'none';
    }
}

// Form validation functions
function validateLoginForm(data) {
    let isValid = true;
    
    // Email validation
    if (!data.email) {
        showFieldError('email', 'Email is required');
        isValid = false;
    } else if (!isValidEmail(data.email)) {
        showFieldError('email', 'Please enter a valid email address');
        isValid = false;
    }
    
    // Password validation
    if (!data.password) {
        showFieldError('password', 'Password is required');
        isValid = false;
    }
    
    return isValid;
}

function validateSignupForm(data) {
    let isValid = true;
    
    // Name validation
    if (!data.name) {
        showFieldError('name', 'Name is required');
        isValid = false;
    } else if (data.name.length < 2) {
        showFieldError('name', 'Name must be at least 2 characters long');
        isValid = false;
    }
    
    // Email validation
    if (!data.email) {
        showFieldError('email', 'Email is required');
        isValid = false;
    } else if (!isValidEmail(data.email)) {
        showFieldError('email', 'Please enter a valid email address');
        isValid = false;
    }
    
    // Password validation
    const passwordValidation = validatePassword(data.password);
    if (!passwordValidation.isValid) {
        showFieldError('password', passwordValidation.message);
        isValid = false;
    }
    
    // Confirm password validation
    if (data.password !== data.confirm_password) {
        showFieldError('confirmPassword', 'Passwords do not match');
        isValid = false;
    }
    
    // Terms validation
    const termsCheckbox = document.getElementById('terms');
    if (!termsCheckbox.checked) {
        showFieldError('terms', 'You must agree to the Terms of Service');
        isValid = false;
    }
    
    return isValid;
}

// Password strength checker
function checkPasswordStrength(e) {
    const password = e.target.value;
    const strengthMeter = document.querySelector('.strength-fill');
    const strengthText = document.querySelector('.strength-text');
    
    if (!strengthMeter || !strengthText) return;
    
    let score = 0;
    let feedback = [];
    
    // Length check
    if (password.length >= 8) {
        score += 25;
    } else {
        feedback.push('at least 8 characters');
    }
    
    // Uppercase check
    if (/[A-Z]/.test(password)) {
        score += 25;
    } else {
        feedback.push('uppercase letter');
    }
    
    // Lowercase check
    if (/[a-z]/.test(password)) {
        score += 25;
    } else {
        feedback.push('lowercase letter');
    }
    
    // Number check
    if (/[0-9]/.test(password)) {
        score += 25;
    } else {
        feedback.push('number');
    }
    
    // Update strength meter
    strengthMeter.style.width = `${score}%`;
    
    // Update strength text
    if (score === 0) {
        strengthText.textContent = 'Enter a password';
        strengthMeter.style.background = '#e1e5e9';
    } else if (score < 50) {
        strengthText.textContent = `Weak - Add: ${feedback.join(', ')}`;
        strengthMeter.style.background = '#dc3545';
    } else if (score < 75) {
        strengthText.textContent = `Fair - Add: ${feedback.join(', ')}`;
        strengthMeter.style.background = '#ffc107';
    } else if (score < 100) {
        strengthText.textContent = `Good - Add: ${feedback.join(', ')}`;
        strengthMeter.style.background = '#fd7e14';
    } else {
        strengthText.textContent = 'Strong password';
        strengthMeter.style.background = '#28a745';
    }
}

// Utility functions
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function validatePassword(password) {
    if (password.length < 8) {
        return { isValid: false, message: 'Password must be at least 8 characters long' };
    }
    if (!/[A-Z]/.test(password)) {
        return { isValid: false, message: 'Password must contain at least one uppercase letter' };
    }
    if (!/[a-z]/.test(password)) {
        return { isValid: false, message: 'Password must contain at least one lowercase letter' };
    }
    if (!/[0-9]/.test(password)) {
        return { isValid: false, message: 'Password must contain at least one number' };
    }
    return { isValid: true, message: 'Password is valid' };
}

function showFieldError(fieldName, message) {
    const errorElement = document.getElementById(`${fieldName}-error`);
    if (errorElement) {
        errorElement.textContent = message;
        errorElement.classList.add('show');
    }
}

function clearFormErrors() {
    const errorElements = document.querySelectorAll('.form-error');
    errorElements.forEach(element => {
        element.textContent = '';
        element.classList.remove('show');
    });
    
    // Hide any existing alerts
    const alertElement = document.getElementById('alertMessage');
    if (alertElement) {
        alertElement.style.display = 'none';
    }
}

function showAlert(message, type) {
    const alertElement = document.getElementById('alertMessage');
    if (alertElement) {
        alertElement.textContent = message;
        alertElement.className = `alert ${type}`;
        alertElement.style.display = 'block';
        
        // Auto-hide success messages
        if (type === 'success') {
            setTimeout(() => {
                alertElement.style.display = 'none';
            }, 3000);
        }
    }
}

// Password toggle functionality
function togglePassword(fieldId) {
    const passwordField = document.getElementById(fieldId);
    const toggleIcon = document.getElementById(`${fieldId}-toggle-icon`);
    
    if (passwordField.type === 'password') {
        passwordField.type = 'text';
        toggleIcon.textContent = '🙈';
    } else {
        passwordField.type = 'password';
        toggleIcon.textContent = '👁️';
    }
}

// Social login handler
function handleSocialLogin(e) {
    e.preventDefault();
    const provider = e.target.classList.contains('google-button') ? 'google' : 'facebook';
    
    // For now, just show a message
    showAlert(`${provider.charAt(0).toUpperCase() + provider.slice(1)} login is not implemented yet`, 'warning');
    
    // In a real implementation, you would redirect to OAuth provider:
    // window.location.href = `/auth/${provider}`;
}

// Add this to make togglePassword available globally
window.togglePassword = togglePassword;