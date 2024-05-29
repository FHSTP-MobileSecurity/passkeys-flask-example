// Check if browser supports passkeys
// Availability of `window.PublicKeyCredential` means WebAuthn is usable.  
// `isUserVerifyingPlatformAuthenticatorAvailable` means the feature detection is usable.  
// `​​isConditionalMediationAvailable` means the feature detection is usable.  
if (window.PublicKeyCredential &&
    PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable &&
    PublicKeyCredential.isConditionalMediationAvailable) {
    // Check if user verifying platform authenticator is available.  
    Promise.all([
        PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(),
        PublicKeyCredential.isConditionalMediationAvailable(),
    ]).then(results => {
        if (results.every(r => r === true)) {
            // Display "Create a new passkey" button  
            document.getElementById('loginViaPassKey').style.display = "block";
            document.getElementById('registerPassKey').style.display = "block";
        } else {
            document.getElementById('passkeysNotAvailable').style.display = "block";
        }
    });
}



async function register() {
    try {
        // Fetch registration options from the server
        const response = await fetch('/register', { method: 'GET' });
        if (!response.ok) {
            const reason = await response.text();
            alert("Registration failed: " + reason);
            return;
        }

        const options = JSON.parse(await response.json());

        // Convert options for WebAuthn API
        options.challenge = base64ToArrayBuffer(options.challenge);
        options.user.id = base64ToArrayBuffer(options.user.id);
        const publicKeyOptions = {
            publicKey: options
        }

        // Call WebAuthn API to create credentials
        const credential = await navigator.credentials.create(publicKeyOptions);

        // Send the credential to the server for verification
        const credentialResponse = {
            id: credential.id,
            rawId: arrayBufferToBase64(credential.rawId),
            type: credential.type,
            response: {
                attestationObject: arrayBufferToBase64(credential.response.attestationObject),
                clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON),
            },
        };

        const verifyResponse = await fetch('/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(credentialResponse),
        });

        const result = await verifyResponse.json();
        alert(result.status === 'ok' ? 'Registration successful!' : `Registration failed: ${result.error}`);
    } catch (error) {
        console.error('Error during registration:', error);
        alert('Registration failed');
    }
}

async function login() {
    // Availability of `window.PublicKeyCredential` means WebAuthn is usable.  
    if (window.PublicKeyCredential &&
        PublicKeyCredential.isConditionalMediationAvailable) {
        // Check if conditional mediation is available.  
        const isCMA = await PublicKeyCredential.isConditionalMediationAvailable();
        if (isCMA) {
            // Call WebAuthn authentication  
            try {
                // Fetch authentication options from the server
                const response = await fetch('/authenticate', { method: 'GET' });
                const options = JSON.parse(await response.json());
                console.log(options);

                // Convert options for WebAuthn API
                options.challenge = base64ToArrayBuffer(options.challenge);
                options.allowCredentials.forEach((cred) => {
                    cred.id = base64ToArrayBuffer(cred.id);
                });

                // Call WebAuthn API to get an assertion
                const publicKeyOptions = {
                    publicKey: options
                };

                // Call WebAuthn API to get an assertion
                const assertion = await navigator.credentials.get(publicKeyOptions);
                console.log(assertion);

                // Send the assertion to the server for verification
                const assertionResponse = {
                    id: assertion.id,
                    rawId: arrayBufferToBase64(assertion.rawId),
                    type: assertion.type,
                    response: {
                        authenticatorData: arrayBufferToBase64(assertion.response.authenticatorData),
                        clientDataJSON: arrayBufferToBase64(assertion.response.clientDataJSON),
                        signature: arrayBufferToBase64(assertion.response.signature),
                        userHandle: arrayBufferToBase64(assertion.response.userHandle),
                    },
                };

                const verifyResponse = await fetch('/authenticate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(assertionResponse),
                });

                const result = await verifyResponse.json();
                alert(result.status === 'ok' ? 'Login successful!' : `Login failed: ${result.error}`);
            } catch (error) {
                console.error('Error during login:', error);
                alert('Login failed');
            }
        }
    }
}

function arrayBufferToBase64(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ToArrayBuffer(base64) {
    // Add padding if necessary
    if (base64.length % 4 !== 0) {
        base64 += '='.repeat(4 - (base64.length % 4));
    }
    // Replace URL-safe characters
    base64 = base64.replace(/-/g, '+').replace(/_/g, '/');

    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}
