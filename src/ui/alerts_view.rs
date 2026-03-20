//! Alerts view — dedicated alert dashboard with category panes and summary bar.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::data::alerts::{AlertCategory, AlertSeverity};
use crate::theme;

/// Draw the Alerts view (View 3).
///
/// Layout:
/// ```text
/// ┌─ Alert Summary ──────────────────────────────────────────────────┐
/// │  CRIT: N  │  WARN: N  │  INFO: N  │  Total: N  │  Unread: N    │
/// └──────────────────────────────────────────────────────────────────┘
/// ┌─ Security ──────────────┐  ┌─ Network Activity ─────────────────┐
/// │ ...                     │  │ ...                                 │
/// └─────────────────────────┘  └─────────────────────────────────────┘
/// ┌─ Bandwidth ─────────────┐  ┌─ System ───────────────────────────┐
/// │ ...                     │  │ ...                                 │
/// └─────────────────────────┘  └─────────────────────────────────────┘
/// ```
pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // summary bar
            Constraint::Min(8),   // category grid
        ])
        .split(area);

    draw_summary_bar(f, app, chunks[0]);
    draw_category_grid(f, app, chunks[1]);
}

/// Draw the summary bar showing severity counts.
fn draw_summary_bar(f: &mut Frame, app: &App, area: Rect) {
    let crit_count = app.alert_engine.count_by_severity(AlertSeverity::Crit);
    let warn_count = app.alert_engine.count_by_severity(AlertSeverity::Warn);
    let info_count = app.alert_engine.count_by_severity(AlertSeverity::Info);
    let total = app.alert_engine.alerts.len();
    let unread = app.alert_engine.unread_count();

    let crit_style = Style::default()
        .fg(theme::DANGER)
        .add_modifier(Modifier::BOLD);
    let warn_style = Style::default()
        .fg(theme::WARN)
        .add_modifier(Modifier::BOLD);
    let info_style = Style::default()
        .fg(theme::ACCENT)
        .add_modifier(Modifier::BOLD);
    let dim = Style::default().fg(theme::TEXT_DIM);
    let text_style = Style::default().fg(theme::TEXT);
    let unread_style = if unread > 0 {
        Style::default()
            .fg(theme::GOLD)
            .add_modifier(Modifier::BOLD)
    } else {
        dim
    };

    let sep = Span::styled("  \u{2502}  ", dim);

    let line = Line::from(vec![
        Span::styled("  CRIT: ", crit_style),
        Span::styled(format!("{}", crit_count), crit_style),
        sep.clone(),
        Span::styled("WARN: ", warn_style),
        Span::styled(format!("{}", warn_count), warn_style),
        sep.clone(),
        Span::styled("INFO: ", info_style),
        Span::styled(format!("{}", info_count), info_style),
        sep.clone(),
        Span::styled("Total: ", text_style),
        Span::styled(format!("{}", total), text_style),
        sep.clone(),
        Span::styled("Unread: ", unread_style),
        Span::styled(format!("{}", unread), unread_style),
    ]);

    let block = Block::default()
        .title(Span::styled(
            " Alert Summary ",
            Style::default()
                .fg(theme::TITLE)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER))
        .style(Style::default().bg(theme::BG));

    let paragraph = Paragraph::new(line).block(block);
    f.render_widget(paragraph, area);
}

/// Draw the 2x2 grid of category panes.
fn draw_category_grid(f: &mut Frame, app: &App, area: Rect) {
    // Split into two rows
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(50),
        ])
        .split(area);

    // Top row: Security | Network
    let top_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(50),
        ])
        .split(rows[0]);

    // Bottom row: Bandwidth | System
    let bot_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(50),
        ])
        .split(rows[1]);

    draw_category_pane(f, app, top_cols[0], AlertCategory::Security);
    draw_category_pane(f, app, top_cols[1], AlertCategory::Network);
    draw_category_pane(f, app, bot_cols[0], AlertCategory::Bandwidth);
    draw_category_pane(f, app, bot_cols[1], AlertCategory::System);
}

/// Draw a single category pane with scrollable alert list.
fn draw_category_pane(f: &mut Frame, app: &App, area: Rect, category: AlertCategory) {
    let alerts = app.alert_engine.by_category(category);

    // Count unread in this category
    let unread_in_cat = alerts.iter().filter(|a| !a.read).count();

    // Build title with unread indicator
    let title = if unread_in_cat > 0 {
        format!(" {} ({} new) ", category.label(), unread_in_cat)
    } else {
        format!(" {} ", category.label())
    };

    // Choose border color based on highest severity in this category
    let border_color = if alerts.iter().any(|a| !a.read && a.severity == AlertSeverity::Crit) {
        theme::DANGER
    } else if alerts.iter().any(|a| !a.read && a.severity == AlertSeverity::Warn) {
        theme::WARN
    } else if unread_in_cat > 0 {
        theme::ACCENT
    } else {
        theme::BORDER
    };

    let block = Block::default()
        .title(Span::styled(
            title,
            Style::default()
                .fg(theme::TITLE)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color))
        .style(Style::default().bg(theme::BG));

    // Calculate inner area for content
    let inner = block.inner(area);
    f.render_widget(block, area);

    if alerts.is_empty() {
        let empty = Paragraph::new(Line::from(Span::styled(
            "  No alerts",
            Style::default().fg(theme::TEXT_MUTED),
        )))
        .style(Style::default().bg(theme::BG));
        f.render_widget(empty, inner);
        return;
    }

    // Build alert lines (limited to visible area)
    let max_lines = inner.height as usize;
    let lines: Vec<Line> = alerts
        .iter()
        .take(max_lines)
        .map(|alert| format_alert_line(alert, inner.width as usize))
        .collect();

    let paragraph = Paragraph::new(lines).style(Style::default().bg(theme::BG));
    f.render_widget(paragraph, inner);
}

/// Format a single alert as a styled Line.
fn format_alert_line(alert: &crate::data::alerts::Alert, max_width: usize) -> Line<'static> {
    let severity_style = match alert.severity {
        AlertSeverity::Crit => Style::default()
            .fg(theme::DANGER)
            .add_modifier(Modifier::BOLD),
        AlertSeverity::Warn => Style::default()
            .fg(theme::WARN)
            .add_modifier(Modifier::BOLD),
        AlertSeverity::Info => Style::default().fg(theme::ACCENT),
    };

    let severity_label = match alert.severity {
        AlertSeverity::Crit => "CRIT",
        AlertSeverity::Warn => "WARN",
        AlertSeverity::Info => "INFO",
    };

    let timestamp = alert.timestamp.format("%H:%M").to_string();

    // Unread indicator
    let unread_indicator = if !alert.read {
        Span::styled("\u{25cf} ", Style::default().fg(theme::GOLD))
    } else {
        Span::styled("  ", Style::default().fg(theme::TEXT_MUTED))
    };

    let message_style = if alert.read {
        Style::default().fg(theme::TEXT_DIM)
    } else {
        Style::default().fg(theme::TEXT)
    };

    // Truncate message to fit
    let prefix_len = 2 + 4 + 1 + 5 + 1; // indicator + severity + space + time + space
    let msg_max = max_width.saturating_sub(prefix_len);
    let message = if alert.message.len() > msg_max {
        format!("{}...", &alert.message[..msg_max.saturating_sub(3)])
    } else {
        alert.message.clone()
    };

    Line::from(vec![
        unread_indicator,
        Span::styled(format!("{} ", severity_label), severity_style),
        Span::styled(
            format!("{} ", timestamp),
            Style::default().fg(theme::TEXT_DIM),
        ),
        Span::styled(message, message_style),
    ])
}
