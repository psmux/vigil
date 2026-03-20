use ratatui::Frame;

use crate::app::App;

/// Master draw function — dispatches to the active view's renderer.
pub fn draw(f: &mut Frame, _app: &App) {
    // Placeholder: will dispatch to per-view drawing functions
    let area = f.area();
    let block = ratatui::widgets::Block::default()
        .title(" Vigil ")
        .borders(ratatui::widgets::Borders::ALL)
        .style(crate::theme::block_style())
        .title_style(crate::theme::title_style());
    f.render_widget(block, area);
}
