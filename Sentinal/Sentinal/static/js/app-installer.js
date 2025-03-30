/**
 * App Installer - Handles PWA installation prompts
 * This script manages the "Install App" button and installation process
 */

let deferredPrompt;
const installButton = document.getElementById('install-button');

// Listen for the beforeinstallprompt event
window.addEventListener('beforeinstallprompt', (e) => {
    // Prevent the default browser prompt
    e.preventDefault();
    
    // Store the event for later use
    deferredPrompt = e;
    
    // Show the install button
    if (installButton) {
        installButton.classList.remove('d-none');
    }
});

// Add click event to the install button
if (installButton) {
    installButton.addEventListener('click', async () => {
        if (!deferredPrompt) {
            return;
        }
        
        // Show the installation prompt
        deferredPrompt.prompt();
        
        // Wait for the user to respond to the prompt
        const { outcome } = await deferredPrompt.userChoice;
        console.log(`Installation outcome: ${outcome}`);
        
        // Clear the deferred prompt
        deferredPrompt = null;
        
        // Hide the install button
        installButton.classList.add('d-none');
    });
}

// Listen for the appinstalled event
window.addEventListener('appinstalled', (e) => {
    // App installed successfully
    console.log('Sentinel Trading Platform was installed');
    
    // Hide the install button
    if (installButton) {
        installButton.classList.add('d-none');
    }
    
    // Optional: Show a success message
    showInstallationSuccess();
});

// Function to show installation success message
function showInstallationSuccess() {
    // Create alert element
    const alertDiv = document.createElement('div');
    alertDiv.className = 'alert alert-success alert-dismissible fade show position-fixed top-0 start-50 translate-middle-x mt-3';
    alertDiv.setAttribute('role', 'alert');
    alertDiv.style.zIndex = '9999';
    
    // Add content
    alertDiv.innerHTML = `
        <i class="bi bi-check-circle me-2"></i>
        App installed successfully! You can now access Sentinel Trading Platform from your home screen.
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    
    // Add to document
    document.body.appendChild(alertDiv);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (alertDiv.parentNode) {
            alertDiv.parentNode.removeChild(alertDiv);
        }
    }, 5000);
}