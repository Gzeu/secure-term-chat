# Secțiune corectă pentru a înlocui partea problematică din modern_ui.py

def action_toggle_status(self) -> None:
    """Toggle status panel visibility"""
    status_bar = self.query_one("#status-bar")
    status_bar.display = not status_bar.display
    self.status_visible = status_bar.display

def action_dismiss_modal(self) -> None:
    """Dismiss any modal"""
    if self.screen_stack:
        self.pop_screen()

# Main entry point
if __name__ == "__main__":
    app = ModernChatApp()
    app.run()
