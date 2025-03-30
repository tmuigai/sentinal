function switchAccount(accountType) {
    fetch('/switch-account-type', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        },
        body: JSON.stringify({ type: accountType }),
        credentials: 'same-origin'
    })
    .then(response => {
        if (!response.ok) throw new Error('Network response was not ok');
        return response.json();
    })
    .then(data => {
        if (data.status === 'success') {
            window.location.reload();
        }
    })
    .catch(error => console.error('Error:', error));
}

// Add event listeners for account switching buttons
document.addEventListener('DOMContentLoaded', function() {
    const realButton = document.querySelector('button[onclick="switchAccount(\'real\')"]');
    const demoButton = document.querySelector('button[onclick="switchAccount(\'demo\')"]');

    if (realButton && demoButton) {
        const currentType = document.querySelector('.btn-group').dataset.accountType;
        if (currentType === 'real') {
            realButton.classList.add('active');
        } else if (currentType === 'demo') {
            demoButton.classList.add('active');
        }
    }
});

// Highlight active account type button
document.addEventListener('DOMContentLoaded', function() {
    const accountType = document.querySelector('[data-account-type]')?.dataset.accountType;
    if (accountType) {
        const buttons = document.querySelectorAll('.btn-group button');
        buttons.forEach(button => {
            button.classList.remove('active');
            if (button.onclick.toString().includes(accountType)) {
                button.classList.add('active');
            }
        });
    }
});