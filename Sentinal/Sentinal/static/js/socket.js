// WebSocket client for real-time updates

document.addEventListener('DOMContentLoaded', function() {
    // Get execution ID from page if available
    const executionIdElement = document.getElementById('execution-id');
    if (!executionIdElement) return;
    
    const executionId = executionIdElement.value;
    if (!executionId) return;
    
    // Connect to WebSocket server
    const socket = io();
    
    // Connection events
    socket.on('connect', function() {
        console.log('Connected to WebSocket server');
        
        // Join the execution room
        socket.emit('join_execution', { execution_id: executionId });
        
        // Show connected status
        updateConnectionStatus('Connected', 'success');
    });
    
    socket.on('disconnect', function() {
        console.log('Disconnected from WebSocket server');
        updateConnectionStatus('Disconnected', 'danger');
    });
    
    socket.on('connect_error', function(error) {
        console.error('Connection error:', error);
        updateConnectionStatus('Connection error', 'danger');
    });
    
    // Execution update events
    socket.on('execution_update', function(data) {
        console.log('Execution update received:', data);
        
        // Update execution status
        const statusElement = document.getElementById('execution-status');
        if (statusElement && data.status) {
            statusElement.textContent = data.status.toUpperCase();
            
            // Update status class
            statusElement.className = 'badge';
            switch (data.status) {
                case 'queued':
                    statusElement.classList.add('bg-warning');
                    break;
                case 'running':
                    statusElement.classList.add('bg-info');
                    break;
                case 'success':
                    statusElement.classList.add('bg-success');
                    break;
                case 'failed':
                    statusElement.classList.add('bg-danger');
                    break;
                default:
                    statusElement.classList.add('bg-secondary');
            }
        }
        
        // Update logs if available
        const logsElement = document.getElementById('execution-logs');
        if (logsElement && data.logs) {
            logsElement.textContent = data.logs;
            logsElement.scrollTop = logsElement.scrollHeight; // Auto-scroll to bottom
        }
        
        // Update completed time if available
        const completedTimeElement = document.getElementById('completed-time');
        if (completedTimeElement && data.completed_at) {
            completedTimeElement.textContent = formatDate(data.completed_at);
        }
        
        // Update profit if available
        const profitElement = document.getElementById('execution-profit');
        if (profitElement && data.profit) {
            profitElement.textContent = formatCurrency(data.profit);
            document.getElementById('profit-container').classList.remove('d-none');
        }
        
        // If execution is complete, refresh the page to show final results
        if (data.status === 'success' || data.status === 'failed') {
            setTimeout(function() {
                window.location.reload();
            }, 3000);
        }
    });
    
    // Helper function to update the connection status indicator
    function updateConnectionStatus(message, type) {
        const statusElement = document.getElementById('connection-status');
        if (statusElement) {
            statusElement.textContent = message;
            statusElement.className = `badge bg-${type}`;
        }
    }
    
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
});
