# Relocating System Status Bar

The goal is to move the status bar (containing CPU, Memory, Latency, etc.) from the bottom of the page to the top, positioned specifically below the header (search and user details) but above the main content grid.

## User Review Required

- **Visual Hierarchy**: Moving the status bar to the top gives it more prominence. I will ensure it matches the width of the other panels for a clean look.
- **Animations**: I'll adjust the "rise-in" animation timing so the status bar appears smoothly as part of the header sequence.

## Proposed Changes

### Frontend: Structure (`frontend/index.html`)

- Relocate the `<footer class="status-strip panel">` block.
- Place it immediately after the `<header class="topbar panel">` but before the main `<section class="content-grid ...">`.
- Convert it from a `<footer>` to a `<div>` or `<section>` to better reflect its new role as a header component.

### Frontend: Styling (`frontend/css/style.css`)

- Update `.status-strip` styles to ensure it has proper margins when placed at the top.
- Ensure the `status-strip` doesn't conflict with the `topbar` or `content-grid` spacing.
- Adjust the grid or flex properties if necessary to maintain a balanced look.

## Verification Plan

### Manual Verification
- Open the dashboard and verify the status bar is now at the top.
- Check that it still updates live (CPU/MEM percentages).
- Verify the layout remains responsive on smaller screens (the status strip should still look good when stacked).
