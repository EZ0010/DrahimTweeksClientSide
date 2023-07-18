/*!
 * Project Name: Drahim Tweaks
 * Author: Chancellor
 * GitHub: https://github.com/EZ0010/DrahimTweeksClientSide
 * Twitter: https://twitter.com/bitcoin_info_ar
 *
 * Copyright (c) 2023 Chancellor. All rights reserved.
 * Licensed under the MIT License.
 */

const almubasherApi = 'https://www.almubasher.com.sa/retail-mobile/ext/pushnotification/retainedMessages/INBOX/true/false/';
const drahimApi = 'https://api.drahim.sa';
const drahimInsert = drahimApi + '/v1/transactions/insert/sms?sync=true';
const drahimSendOTP = drahimApi + '/v1/oauth/send_login_otp';
const drahimVerifyOTP = drahimApi + '/v1/oauth/verify_otp_for_login';
const drahimLogin = drahimApi + '/v1/oauth/login_direction';
const drahimRefreshToken = drahimApi + '/v1/oauth/refresh';
const clearStorageButton = document.querySelector('#clearStorageButton');
const messageStatus = document.querySelector('#messageStatus');
const userIdInput = document.querySelector('#userIdInput');
const fetchMessagesButton = document.querySelector('#fetchMessages');
const countInput = document.querySelector('#countInput');
const tokenDisplay = document.querySelector('#tokenDisplay');
const phoneInput = document.querySelector('#phoneInput');
const sendOTPButton = document.querySelector('#sendOTP');
const verifyOTPButton = document.querySelector('#verifyOTP');
const loginButton = document.querySelector('#login');
const otpInput = document.querySelector('#otpInput');
const passwordInput = document.querySelector('#passwordInput');
const statusMessage = document.querySelector('#statusMessage');
const phoneInputWrapper = document.querySelector('#phoneInputWrapper');
const otpInputWrapper = document.querySelector('#otpInputWrapper');
const phoneOtpInputWrapper = document.querySelector('#phoneOtpInputWrapper');
const blueBankWrapper = document.querySelector('#blueBankWrapper');
const blueBankWrapperInput = document.querySelector('#blueBankWrapperInput');
const clearStoragewrapper = document.querySelector('#clearStoragewrapper');
const themeSwitch = document.getElementById('themeSwitch');
const thebluebank = document.getElementById('thebluebank');
const userId = localStorage.getItem('userId');
let formattedPhone = '';

// event listeners
clearStorageButton.addEventListener('click', clearLocalStorage);
fetchMessagesButton.addEventListener('click', fetchMessages);
sendOTPButton.addEventListener('click', sendOTP);
verifyOTPButton.addEventListener('click', verifyOTP);
loginButton.addEventListener('click', login);
themeSwitch.addEventListener('change', toggleTheme);

phoneInput.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
        sendOTP();
    }
});
otpInput.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
        verifyOTP();
    }
});
passwordInput.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
        login();
    }
});

userIdInput.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
        fetchMessages();
    }
});
countInput.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
        fetchMessages();
    }
});

// Functions
//
//UI functions
function setControlsDisabled(disabled) {
    // Buttons
    clearStorageButton.disabled = disabled;
    fetchMessagesButton.disabled = disabled;
    sendOTPButton.disabled = disabled;
    verifyOTPButton.disabled = disabled;
    loginButton.disabled = disabled;

    // Inputs
    countInput.disabled = disabled;
    userIdInput.disabled = disabled;
    phoneInput.disabled = disabled;
    otpInput.disabled = disabled;
    passwordInput.disabled = disabled;
}
function clearLocalStorage() {
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    localStorage.removeItem('userId');
    blueBankWrapper.classList.add('d-none');
    updateTokenDisplay();
    setAlert('Local storage cleared, please refresh the page.', 'info');
}
function setSwitchState() {
    const storedTheme = localStorage.getItem('theme');
    const themeSwitch = document.getElementById('themeSwitch');
    const osPreference = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';

    // If a theme is stored in localStorage, use that; otherwise, use the user's OS settings
    const theme = storedTheme ? storedTheme : osPreference;

    if (theme === 'dark') {
        document.documentElement.setAttribute('data-bs-theme', 'dark');
        thebluebank.classList.add('bg-light');
        themeSwitch.checked = true;
    } else {
        document.documentElement.setAttribute('data-bs-theme', 'light');
        themeSwitch.checked = false;
    }
}
function toggleTheme() {
    const themeSwitch = document.getElementById('themeSwitch');
    const theme = themeSwitch.checked ? 'dark' : 'light';

    localStorage.setItem('theme', theme);
    document.documentElement.setAttribute('data-bs-theme', theme);
    thebluebank.classList.add('bg-light');
}
function updateTokenDisplay() {
    const accessToken = localStorage.getItem('accessToken');
    const refreshToken = localStorage.getItem('refreshToken');
    if (accessToken) {
        const tokenDisplayText = 'Access token: ' + accessToken.slice(-20) + '...';
        tokenDisplay.textContent = tokenDisplayText;
        if (refreshToken) {
            const refreshDisplayText = 'Refresh token: ' + refreshToken.slice(-20) + '...';
            const refreshDisplay = document.createElement('div');
            refreshDisplay.textContent = refreshDisplayText;
            tokenDisplay.appendChild(refreshDisplay);
        }
        if (userId) {
            const userIdInputtext = document.createElement('div');
            userIdInputtext.textContent = 'Blue Bank UserId: ' + userId.slice(-20) + '...';
            tokenDisplay.appendChild(userIdInputtext);

        } else {
            blueBankWrapperInput.classList.remove('d-none')
        }
        blueBankWrapper.classList.remove('d-none');
        phoneInputWrapper.classList.add('d-none');
        otpInputWrapper.classList.add('d-none');
        phoneOtpInputWrapper.classList.add('d-none');
    } else {
        tokenDisplay.textContent = '';
        phoneInputWrapper.classList.remove('d-none');
        phoneInput.focus();
    }
    if (localStorage.accessToken || localStorage.refreshToken || localStorage.userId) {
        clearStoragewrapper.classList.remove('d-none');
    }
    setSwitchState();
}
function setAlert(message, type) {
    statusMessage.textContent = message;
    statusMessage.className = ''; // Remove all classes
    statusMessage.classList.add('alert', 'alert-' + type, 'text-break');
}
function setmessageStatus(message, type) {
    messageStatus.textContent = message;
    messageStatus.className = ''; // Remove all classes
    messageStatus.classList.add('alert', 'alert-' + type);
}

// API calls
async function fetchMessages() {
    try {
        setControlsDisabled(true);
        let customCount = countInput.value || 10;
        if (userIdInput.value.length > 0) {
            localStorage.setItem('userId', userIdInput.value)
        }
        const userId = localStorage.getItem('userId');
        if (!userId) {
            setmessageStatus('userId token not available.', 'danger')
            return;
        }
        customCount = Math.min(customCount, 40);
        const response = await fetch(`${almubasherApi}${userId}?count=${customCount}`);
        const result = await response.json();
        if (!result.totalCount) {
            setmessageStatus('Invalid UserID or no transactions in the response.', 'danger')
            return;
        }

        localStorage.setItem('userId', userId);
        const wantedTexts = result.msgs.map(msg => msg.msgBody);
        const accessToken = localStorage.getItem('accessToken');

        if (!accessToken) {
            setmessageStatus('Access token not available.', 'danger')
            return;
        }

        const headers = {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${accessToken}`,
        };

        let successfulRequests = 0;
        let totalRequests = 0;

        for (const wantedText of wantedTexts) {
            const data = { sms_body: wantedText };

            const response = await fetch(drahimInsert, {
                method: 'POST',
                headers: headers,
                body: JSON.stringify(data),
            });

            const result = await response.json();
            totalRequests++;

            if (result.msg === 'Expired token.' || result.msg === 'Invalid token.') {
                const refreshed = await refreshAccessToken();

                if (!refreshed) {
                    setAlert('Token refresh failed. Please re-authenticate.', 'danger');
                    localStorage.removeItem('accessToken');
                    localStorage.removeItem('refreshToken');
                    updateTokenDisplay();
                    break;
                }

                headers.Authorization = `Bearer ${localStorage.getItem('accessToken')}`;
            } else if (result.success) {
                successfulRequests++;
            }
            message = `Sent ${successfulRequests} out of ${totalRequests} messages successfully, ${totalRequests - successfulRequests} requests failed.`;
            if (successfulRequests > 0) {
                type = 'success';
            } else {
                type = 'danger';
            }
            setmessageStatus(message, type);
        }
    } catch (error) {
        setAlert('Error in fetchMessages', 'danger');
    } finally {
        setControlsDisabled(false);
    }
}
async function refreshAccessToken() {
    const refreshToken = localStorage.getItem('refreshToken');
    if (!refreshToken) return false;

    const headers = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${refreshToken}`,
        'User-Agent': 'drahim/5 CFNetwork/1408.0.2 Darwin/22.5.0'
    };

    const response = await fetch(drahimRefreshToken, {
        method: 'POST',
        headers: headers,
    });

    const result = await response.json();

    if (result.data?.authorization?.access_token && result.data?.authorization?.refresh_token) {
        localStorage.setItem('accessToken', result.data.authorization.access_token);
        localStorage.setItem('refreshToken', result.data.authorization.refresh_token);
        updateTokenDisplay();
        return true;
    }

    return false;
}
async function sendOTP() {
    try {
        setControlsDisabled(true);
        const phone = phoneInput.value;
        const saudiPhoneRegex = /^(009665|9665|\+9665|05|5)(5|0|3|6|4|9|1|8|7)([0-9]{7})$/;
        const match = phone.match(saudiPhoneRegex);
        if (!match) {
            setAlert('ERROR: Invalid Saudi phone number format..', 'danger');
            return;
        }
        formattedPhone = `009665${match[2]}${match[3]}`;
        const data = { phone: formattedPhone };
        const response = await fetch(drahimSendOTP, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data),
        });
        const result = await response.json();

        if (result.data === 'OTP sent successfully') {
            setAlert('OTP sent successfully.', 'success');
            phoneInputWrapper.classList.add('d-none');
            otpInputWrapper.classList.remove('d-none');
            setTimeout(() => {
                otpInput.focus();
            }, 0.1);
        } else {
            setAlert(`ERROR: ${JSON.stringify(result)}`, 'danger');
        }
    } catch (error) {
        console.error('Error:', error);
        setAlert('Error in sendOTP.', 'danger');
    } finally {
        setControlsDisabled(false);
    }
}
async function verifyOTP() {
    try {
        setControlsDisabled(true);

        const data = { otp: otpInput.value, phone: formattedPhone };

        const response = await fetch(drahimVerifyOTP, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data),
        });
        const result = await response.json();

        if (result.data === 'otp is valid') {
            setAlert('OTP is valid. Please enter your password.', 'success');
            otpInputWrapper.classList.add('d-none');
            phoneOtpInputWrapper.classList.remove('d-none');
        } else {
            setAlert('OTP is not valid.', 'danger');
        }
    } catch (error) {
        setAlert(`ERROR: ${JSON.stringify(result)}`, 'danger');
    } finally {
        setControlsDisabled(false);
    }
}
async function login() {
    try {
        setControlsDisabled(true);
        const data = { password: passwordInput.value, phone: formattedPhone };
        const response = await fetch(drahimLogin, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data),
        });
        const result = await response.json();

        if (result.data?.authorization?.access_token) {
            localStorage.setItem('accessToken', result.data.authorization.access_token);
            localStorage.setItem('refreshToken', result.data.authorization.refresh_token);
            setAlert('Login successful. Access token and refresh token stored.', 'success');
            phoneOtpInputWrapper.classList.add('d-none');
            updateTokenDisplay();
        } else {
            setAlert(`ERROR: ${JSON.stringify(result)}`, 'danger');
        }
    } catch (error) {
        console.error('Error:', error);
        setAlert('Error in login.', 'danger');
    } finally {
        setControlsDisabled(false);
    }
}
updateTokenDisplay();
