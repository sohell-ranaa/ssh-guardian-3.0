/**
 * Timezone Utilities
 * Formats dates to local timezone with GMT offset display
 */

// Format date to local timezone with GMT offset
function formatLocalDateTime(dateString) {
    if (!dateString) return 'N/A';

    const date = new Date(dateString);
    if (isNaN(date.getTime())) return 'Invalid Date';

    // Get timezone offset in minutes and convert to hours
    const offsetMinutes = date.getTimezoneOffset();
    const offsetHours = -offsetMinutes / 60;
    const offsetSign = offsetHours >= 0 ? '+' : '';

    // Format: DD/MM/YYYY HH:MM:SS GMT+X
    const day = String(date.getDate()).padStart(2, '0');
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const year = date.getFullYear();
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    const seconds = String(date.getSeconds()).padStart(2, '0');

    return `${day}/${month}/${year} ${hours}:${minutes}:${seconds} GMT${offsetSign}${offsetHours}`;
}

// Format date to local date only (no time)
function formatLocalDate(dateString) {
    if (!dateString) return 'N/A';

    const date = new Date(dateString);
    if (isNaN(date.getTime())) return 'Invalid Date';

    const day = String(date.getDate()).padStart(2, '0');
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const year = date.getFullYear();

    return `${day}/${month}/${year}`;
}

// Format date to local time only (no date)
function formatLocalTime(dateString) {
    if (!dateString) return 'N/A';

    const date = new Date(dateString);
    if (isNaN(date.getTime())) return 'Invalid Date';

    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    const seconds = String(date.getSeconds()).padStart(2, '0');

    return `${hours}:${minutes}:${seconds}`;
}

// Get current local timezone info
function getLocalTimezoneInfo() {
    const date = new Date();
    const offsetMinutes = date.getTimezoneOffset();
    const offsetHours = -offsetMinutes / 60;
    const offsetSign = offsetHours >= 0 ? '+' : '';

    return {
        offset: offsetHours,
        formatted: `GMT${offsetSign}${offsetHours}`
    };
}
