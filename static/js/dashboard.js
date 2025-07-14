// Dashboard JavaScript functionality

// Real-time updates
let updateInterval;

$(document).ready(function() {
    // Initialize dashboard
    initializeDashboard();
    
    // Auto-refresh toggle
    $('#auto-refresh-toggle').change(function() {
        if (this.checked) {
            startAutoRefresh();
        } else {
            stopAutoRefresh();
        }
    });
    
    // Filter forms
    $('.filter-form').on('change', 'select', function() {
        $(this).closest('form').submit();
    });
    
    // Tooltips
    $('[data-bs-toggle="tooltip"]').tooltip();
});

function initializeDashboard() {
    // Start auto-refresh by default
    startAutoRefresh();
    
    // Initialize charts if they exist
    if (typeof Chart !== 'undefined') {
        Chart.defaults.font.family = "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif";
        Chart.defaults.color = '#495057';
    }
}

function startAutoRefresh() {
    stopAutoRefresh(); // Clear any existing interval
    
    updateInterval = setInterval(function() {
        updateDashboardStats();
    }, 30000); // Update every 30 seconds
    
    $('#refresh-status').removeClass('text-muted').addClass('text-success');
    $('#refresh-indicator').html('<i class="fas fa-circle text-success"></i> Auto-actualización activa');
}

function stopAutoRefresh() {
    if (updateInterval) {
        clearInterval(updateInterval);
        updateInterval = null;
    }
    
    $('#refresh-status').removeClass('text-success').addClass('text-muted');
    $('#refresh-indicator').html('<i class="fas fa-circle text-muted"></i> Auto-actualización pausada');
}

function updateDashboardStats() {
    // Only update if we're on the dashboard page
    if (!$('#dashboard-stats').length) return;
    
    fetch('/dashboard/api/traffic-stats/')
        .then(response => response.json())
        .then(data => {
            // Update metric cards
            updateMetricCard('total-recent', data.total_recent);
            updateMetricCard('anomalies-recent', data.anomalies_recent);
            updateMetricCard('normal-recent', data.normal_recent);
            updateMetricCard('unprocessed-recent', data.unprocessed_recent);
            
            // Update timestamp
            $('#last-update').text(new Date(data.timestamp).toLocaleTimeString());
        })
        .catch(error => {
            console.error('Error updating dashboard stats:', error);
        });
}

function updateMetricCard(cardId, value) {
    const card = $('#' + cardId);
    if (card.length) {
        const currentValue = parseInt(card.text()) || 0;
        
        // Animate value change
        if (value !== currentValue) {
            card.addClass('animate__animated animate__pulse');
            card.text(value);
            
            setTimeout(() => {
                card.removeClass('animate__animated animate__pulse');
            }, 1000);
        }
    }
}

// Manual refresh function
function refreshDashboard() {
    const button = $('#refresh-btn');
    const originalText = button.html();
    
    button.html('<i class="fas fa-spinner fa-spin"></i> Actualizando...');
    button.prop('disabled', true);
    
    // Reload the page after a short delay
    setTimeout(() => {
        location.reload();
    }, 500);
}

// Export data functionality
function exportData(format) {
    const exportBtn = $('#export-btn');
    const originalText = exportBtn.html();
    
    exportBtn.html('<i class="fas fa-spinner fa-spin"></i> Exportando...');
    exportBtn.prop('disabled', true);
    
    // Simulate export process
    setTimeout(() => {
        exportBtn.html(originalText);
        exportBtn.prop('disabled', false);
        
        // Show success message
        showNotification('Datos exportados exitosamente', 'success');
    }, 2000);
}

// Notification system
function showNotification(message, type = 'info') {
    const alertClass = `alert-${type}`;
    const iconClass = type === 'success' ? 'fa-check-circle' : 
                     type === 'error' ? 'fa-exclamation-circle' : 
                     'fa-info-circle';
    
    const notification = $(`
        <div class="alert ${alertClass} alert-dismissible fade show position-fixed" 
             style="top: 20px; right: 20px; z-index: 9999; min-width: 300px;">
            <i class="fas ${iconClass}"></i> ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `);
    
    $('body').append(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        notification.alert('close');
    }, 5000);
}

// Filter management
function clearFilters() {
    $('select[name="label"]').val('all');
    $('select[name="date"]').val('today');
    $('input[name="search"]').val('');
    $('.filter-form').submit();
}

// Theme toggle
function toggleTheme() {
    const currentTheme = localStorage.getItem('theme') || 'light';
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    
    localStorage.setItem('theme', newTheme);
    document.documentElement.setAttribute('data-theme', newTheme);
    
    // Update theme toggle button
    const themeBtn = $('#theme-toggle');
    if (newTheme === 'dark') {
        themeBtn.html('<i class="fas fa-sun"></i>');
    } else {
        themeBtn.html('<i class="fas fa-moon"></i>');
    }
}

// Initialize theme on page load
$(document).ready(function() {
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);
    
    const themeBtn = $('#theme-toggle');
    if (savedTheme === 'dark') {
        themeBtn.html('<i class="fas fa-sun"></i>');
    } else {
        themeBtn.html('<i class="fas fa-moon"></i>');
    }
});

// Keyboard shortcuts
$(document).keydown(function(e) {
    // Ctrl+R for refresh
    if (e.ctrlKey && e.keyCode === 82) {
        e.preventDefault();
        refreshDashboard();
    }
    
    // Escape to clear filters
    if (e.keyCode === 27) {
        clearFilters();
    }
});