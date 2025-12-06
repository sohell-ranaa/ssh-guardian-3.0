# Recommendation UI Redesign - SSH Guardian v3.0

## Overview

The recommendation system has been completely redesigned to provide a cleaner, more user-friendly interface with modal-based interactions instead of page redirects.

## Key Changes

### 1. **Compact List View**
- Recommendations are now displayed as compact list items instead of individual large cards
- Each recommendation shows:
  - Icon and action name
  - Priority badge (Critical/High/Medium/Low)
  - Brief reason/description
  - "View Details" button for more information

### 2. **Consolidated Action Buttons**
- All duplicate actions are consolidated into a single smart button
- Action buttons appear at the bottom of the recommendations section
- Shows count badge if multiple recommendations suggest the same action
- Top 4 most important actions (sorted by priority) are displayed
- Example: "Block IP (3)" means 3 recommendations suggest blocking

### 3. **Modal-Based Interactions**
All detail views now use modals instead of redirecting to other pages:

#### **Recommendation Details Modal**
- Click "View Details" on any recommendation
- Shows full reason, supporting evidence, and AI confidence level
- Action button specific to that recommendation
- No page navigation

#### **Events Modal** (`showEventsModal`)
- View all authentication events for an IP
- Displays events in a table with:
  - Timestamp
  - Event type (failed/successful)
  - Username
  - ML risk score
- Fetches data from `/api/events/recent?ip={ip}&limit=50`

#### **Create Alert Rule Modal** (`showCreateRuleModal`)
- Create alert rules inline without leaving the page
- Configurable fields:
  - Rule Type: Threshold or Rate Limit
  - Max Attempts: 1-100
  - Time Window: 1-60 minutes
- Stores configuration in sessionStorage for the Notification Rules page to pick up
- Shows success notification when rule is configured

#### **Rate Limit Modal** (`showRateLimitModal`)
- Same as Create Alert Rule Modal but pre-selects "Rate Limit" type
- Dedicated action for rate limiting recommendations

## Implementation Details

### Consolidated Actions Function
```javascript
function getConsolidatedActions(recommendations, ip) {
    // Deduplicates actions by type
    // Counts how many recommendations suggest each action
    // Sorts by priority (critical > high > medium > low)
    // Returns top 4 unique actions
}
```

### Modal Functions

#### Show Recommendation Details
```javascript
window.showRecDetails = function(index, rec, ip) {
    // Creates modal with recommendation details
    // Shows evidence, AI confidence, and action button
}
```

#### Show Events Modal
```javascript
window.showEventsModal = async function(ip) {
    // Fetches events from API
    // Displays in table format
    // No page navigation
}
```

#### Show Create Rule Modal
```javascript
window.showCreateRuleModal = function(ip) {
    // Form modal for creating alert rules
    // Validates and stores in sessionStorage
}
```

#### Create Alert Rule Inline
```javascript
window.createAlertRuleInline = function(ip) {
    // Reads form data from modal
    // Stores in sessionStorage as 'newRuleData'
    // Shows notification
    // Closes modal
}
```

### Close Modal
```javascript
window.closeModal = function() {
    // Removes all modals from DOM
}
```

## User Experience Flow

1. **User runs a demo scenario** (e.g., Brute Force Attack)
2. **Results appear with:**
   - Critical alert banner (if high-priority recommendations exist)
   - Overall threat status header
   - Detection metrics (Threat Intel, ML, Geo, History)
   - Compact list of recommendations with reasons
   - 4 consolidated action buttons at bottom
3. **User can:**
   - Click "View Details" on any recommendation to see full evidence
   - Click consolidated action buttons to execute actions
   - Click "View Events" to see IP activity in modal
   - Click "Create Alert" to configure rules in modal
   - Dismiss recommendations or dismiss all

## Action Types Supported

### Standard Actions
- `block_ip` - Block IP immediately
- `view_events` - View authentication events
- `create_rule` - Create alert rule
- `rate_limit` - Enable rate limiting

### AI Actions (from AI Engine)
- `ai_honeypot` - Deploy honeypot deception
- `ai_auth_hardening` - Strengthen authentication
- `ai_monitor` - Silent monitoring
- `ai_geo_block` - Geographic blocking
- `ai_temporal_limit` - Adaptive rate limiting
- `ai_account_protection` - Protect high-value accounts
- `ai_preemptive` - Preemptive containment

## Benefits

1. **No Page Navigation**: Users stay on the simulation page
2. **Less Clutter**: Compact list view instead of large cards
3. **No Duplicates**: Consolidated actions prevent confusion
4. **Better Context**: Modals show details without losing context
5. **Faster Workflow**: Quick actions at bottom for immediate response
6. **Smart Prioritization**: Most critical actions shown first
7. **Action Tracking**: Dismiss and completion tracking

## Technical Notes

### Bug Fixes
1. **Fixed**: Variable name collision - renamed `window` variable to `timeWindow` in `createAlertRuleInline`
2. **Fixed**: Removed broken `toggleRecDetails` onclick handler
3. **Fixed**: All action links now use correct API endpoints

### Dependencies
- All modal functions are self-contained in simulation.html
- Uses existing helper functions: `getPriorityColor`, `getPriorityBg`, `showNotification`
- No external libraries required
- Uses sessionStorage for cross-page data sharing

### Styling
- Uses CSS variables for theming (--card-bg, --border, --text-primary, etc.)
- Responsive design with flexbox and grid
- Consistent with existing SSH Guardian v3.0 design system
- Priority-based color coding (Critical: Red, High: Orange, Medium: Blue, Low: Green)

## Future Enhancements

1. Add keyboard shortcuts for modals (ESC to close)
2. Add animation for modal open/close
3. Support for bulk actions (select multiple recommendations)
4. Add export functionality for recommendation reports
5. Add recommendation history and tracking
6. Add ML confidence threshold configuration
7. Add custom action templates

## Testing

To test the new UI:
1. Navigate to Simulation page
2. Run any demo scenario (Brute Force, Credential Stuffing, etc.)
3. Verify recommendations appear as compact list
4. Click "View Details" - modal should open
5. Click consolidated action buttons - appropriate modals should open
6. Click "View Events" - events should load in modal
7. Click "Create Alert" - form should appear in modal
8. Fill form and submit - notification should appear
9. Verify no page redirects occur

## Files Modified

- `/src/dashboard/templates/pages/simulation.html` - Complete UI redesign
  - Lines 1003-1030: Compact recommendations list
  - Lines 1034-1078: Consolidated actions function
  - Lines 1081-1144: Recommendation details modal
  - Lines 1152-1215: Events modal
  - Lines 1218-1257: Create rule modal
  - Lines 1261-1279: Create alert rule inline function
  - Lines 1281-1288: Rate limit modal

## Documentation

This document serves as the complete reference for the new recommendation UI system. For implementation details, see the inline comments in simulation.html.
