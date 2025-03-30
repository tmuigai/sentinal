// Profile page JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Password validation
    const newPasswordInput = document.getElementById('new_password');
    const confirmPasswordInput = document.getElementById('confirm_password');
    const profileForm = document.getElementById('profile-form');
    
    // Only run if we have the profile form
    if (profileForm) {
        // Validate passwords match
        confirmPasswordInput.addEventListener('input', function() {
            if (newPasswordInput.value !== confirmPasswordInput.value) {
                confirmPasswordInput.setCustomValidity('Passwords do not match');
            } else {
                confirmPasswordInput.setCustomValidity('');
            }
        });
        
        newPasswordInput.addEventListener('input', function() {
            if (confirmPasswordInput.value && newPasswordInput.value !== confirmPasswordInput.value) {
                confirmPasswordInput.setCustomValidity('Passwords do not match');
            } else {
                confirmPasswordInput.setCustomValidity('');
            }
        });
        
        // Form submission validation
        profileForm.addEventListener('submit', function(event) {
            // Check if new password is provided but current password is not
            const currentPassword = document.getElementById('current_password');
            if (newPasswordInput.value && !currentPassword.value) {
                event.preventDefault();
                currentPassword.setCustomValidity('Current password is required to set a new password');
                currentPassword.reportValidity();
            } else {
                currentPassword.setCustomValidity('');
            }
            
            // Check if passwords match
            if (newPasswordInput.value !== confirmPasswordInput.value) {
                event.preventDefault();
                confirmPasswordInput.setCustomValidity('Passwords do not match');
                confirmPasswordInput.reportValidity();
            } else {
                confirmPasswordInput.setCustomValidity('');
            }
        });
    }
    
    // Handle token deletion confirmation
    const deleteButtons = document.querySelectorAll('.delete-confirm');
    deleteButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            if (!confirm('Are you sure you want to delete this API token? This may break running scripts that use it.')) {
                e.preventDefault();
            }
        });
    });
    
    // Toggle 2FA explanation
    const twoFactorCheckbox = document.getElementById('two_factor_enabled');
    if (twoFactorCheckbox) {
        twoFactorCheckbox.addEventListener('change', function() {
            if (this.checked) {
                // Show 2FA setup instructions if checked
                const instructionsEl = document.createElement('div');
                instructionsEl.id = 'twofa-instructions';
                instructionsEl.className = 'alert alert-info mt-3';
                instructionsEl.innerHTML = `
                    <h6>Two-Factor Authentication Setup</h6>
                    <p>After saving, you'll need to scan a QR code with your authenticator app to complete setup.</p>
                    <p class="mb-0">Recommended apps: Google Authenticator, Authy, or Microsoft Authenticator.</p>
                `;
                
                // Insert after the checkbox's parent element
                const formCheck = this.closest('.form-check');
                formCheck.parentNode.insertBefore(instructionsEl, formCheck.nextSibling);
            } else {
                // Remove instructions if unchecked
                const instructionsEl = document.getElementById('twofa-instructions');
                if (instructionsEl) {
                    instructionsEl.remove();
                }
            }
        });
    }
});
