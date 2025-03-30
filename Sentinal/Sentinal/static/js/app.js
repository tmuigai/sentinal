// Main application JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Enable Bootstrap tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Enable Bootstrap popovers
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // Handle delete confirmations
    const deleteButtons = document.querySelectorAll('.delete-confirm');
    deleteButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            if (!confirm('Are you sure you want to delete this? This action cannot be undone.')) {
                e.preventDefault();
            }
        });
    });

    // Handle form validation
    const forms = document.querySelectorAll('.needs-validation');
    Array.from(forms).forEach(form => {
        form.addEventListener('submit', event => {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        }, false);
    });

    // Add parameter fields in script form
    const addParameterBtn = document.getElementById('add-parameter');
    if (addParameterBtn) {
        addParameterBtn.addEventListener('click', function() {
            const parametersContainer = document.getElementById('parameters-container');
            const parameterCount = parametersContainer.children.length;
            
            const parameterDiv = document.createElement('div');
            parameterDiv.className = 'row parameter-row mb-3';
            parameterDiv.innerHTML = `
                <div class="col-md-4">
                    <input type="text" class="form-control" name="param_key" placeholder="Parameter name">
                </div>
                <div class="col-md-3">
                    <select class="form-select" name="param_type">
                        <option value="string">String</option>
                        <option value="number">Number</option>
                        <option value="boolean">Boolean</option>
                    </select>
                </div>
                <div class="col-md-4">
                    <input type="text" class="form-control" name="param_default" placeholder="Default value">
                </div>
                <div class="col-md-1">
                    <button type="button" class="btn btn-danger remove-parameter">
                        <i class="bi bi-trash"></i>
                    </button>
                </div>
            `;
            parametersContainer.appendChild(parameterDiv);
            
            // Add event listener to the new remove button
            parameterDiv.querySelector('.remove-parameter').addEventListener('click', function() {
                parametersContainer.removeChild(parameterDiv);
            });
        });
    }

    // Handle tag selection with Select2 if available
    if (typeof $.fn.select2 !== 'undefined') {
        $('.select2-tags').select2({
            tags: true,
            tokenSeparators: [',', ' '],
            placeholder: 'Select or add tags'
        });
    }

    // Copy code snippets to clipboard
    const copyButtons = document.querySelectorAll('.copy-code');
    copyButtons.forEach(button => {
        button.addEventListener('click', function() {
            const codeElement = this.closest('.code-container').querySelector('code, pre, textarea');
            const textToCopy = codeElement.textContent || codeElement.value;
            
            navigator.clipboard.writeText(textToCopy).then(() => {
                // Change button text temporarily
                const originalText = this.textContent;
                this.textContent = 'Copied!';
                setTimeout(() => {
                    this.textContent = originalText;
                }, 2000);
            }).catch(err => {
                console.error('Could not copy text: ', err);
            });
        });
    });

    // Handle execution logs auto-scroll
    const executionLogs = document.querySelector('.execution-logs');
    if (executionLogs) {
        executionLogs.scrollTop = executionLogs.scrollHeight;
    }
});

// Helper function to format dates
function formatDate(dateString) {
    if (!dateString) return '';
    const date = new Date(dateString);
    return date.toLocaleString();
}

// Helper function to format currency
function formatCurrency(amount) {
    return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: 'USD'
    }).format(amount);
}
