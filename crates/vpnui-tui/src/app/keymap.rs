//! Translates key presses into [`Action`]s for the current input context.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use super::{AppState, Modal, View};
use crate::layout::{self, Mode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    Quit,
    Help,
    CloseModal,
    Escape,
    NextView,
    PrevView,
    Goto(View),
    Move(isize),
    Top,
    Bottom,
    Collapse,
    Expand,
    Activate,
    QuickConnect,
    Disconnect,
    ToggleKillSwitch,
    ReconnectNow,
    StartSearch,
    CycleSort,
    SearchChar(char),
    SearchBackspace,
    SearchCommit,
    SearchCancel,
    ChoicePrev,
    ChoiceNext,
    Choose,
    HelpScroll(i16),
}

const PAGE: isize = 10;

pub(crate) fn action_for(state: &AppState, key: KeyEvent) -> Option<Action> {
    if key.kind == KeyEventKind::Release {
        return None;
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return (key.code == KeyCode::Char('c')).then_some(Action::Quit);
    }
    if layout::mode(state.width, state.height) == Mode::TooSmall || state.version_mismatch.is_some()
    {
        return (key.code == KeyCode::Char('q')).then_some(Action::Quit);
    }
    match &state.ui.modal {
        Some(Modal::Help { .. }) => return help_keys(key.code),
        Some(Modal::Confirm { .. }) => return confirm_keys(key.code),
        None => {}
    }
    if state.ui.browser.typing && state.ui.view == View::Servers {
        return search_keys(key);
    }
    global_keys(key.code)
}

#[allow(clippy::wildcard_enum_match_arm, reason = "unbound keys are ignored")]
fn global_keys(code: KeyCode) -> Option<Action> {
    Some(match code {
        KeyCode::Char('q') => Action::Quit,
        KeyCode::Char('?') => Action::Help,
        KeyCode::Char('1') => Action::Goto(View::Home),
        KeyCode::Char('2') => Action::Goto(View::Servers),
        KeyCode::Char('3') => Action::Goto(View::Stats),
        KeyCode::Char('4') => Action::Goto(View::Settings),
        KeyCode::Tab => Action::NextView,
        KeyCode::BackTab => Action::PrevView,
        KeyCode::Char('j') | KeyCode::Down => Action::Move(1),
        KeyCode::Char('k') | KeyCode::Up => Action::Move(-1),
        KeyCode::PageDown => Action::Move(PAGE),
        KeyCode::PageUp => Action::Move(-PAGE),
        KeyCode::Char('g') | KeyCode::Home => Action::Top,
        KeyCode::Char('G') | KeyCode::End => Action::Bottom,
        KeyCode::Char('h') | KeyCode::Left => Action::Collapse,
        KeyCode::Char('l') | KeyCode::Right => Action::Expand,
        KeyCode::Enter => Action::Activate,
        KeyCode::Char('c') => Action::QuickConnect,
        KeyCode::Char('d') => Action::Disconnect,
        KeyCode::Char('s') => Action::ToggleKillSwitch,
        KeyCode::Char('r') => Action::ReconnectNow,
        KeyCode::Char('/') => Action::StartSearch,
        KeyCode::Char('o') => Action::CycleSort,
        KeyCode::Esc => Action::Escape,
        _ => return None,
    })
}

#[allow(clippy::wildcard_enum_match_arm, reason = "unbound keys are ignored")]
fn help_keys(code: KeyCode) -> Option<Action> {
    Some(match code {
        KeyCode::Esc | KeyCode::Char('?') | KeyCode::Enter => Action::CloseModal,
        KeyCode::Char('q') => Action::Quit,
        KeyCode::Char('j') | KeyCode::Down => Action::HelpScroll(1),
        KeyCode::Char('k') | KeyCode::Up => Action::HelpScroll(-1),
        KeyCode::PageDown => Action::HelpScroll(10),
        KeyCode::PageUp => Action::HelpScroll(-10),
        _ => return None,
    })
}

#[allow(clippy::wildcard_enum_match_arm, reason = "unbound keys are ignored")]
fn confirm_keys(code: KeyCode) -> Option<Action> {
    Some(match code {
        KeyCode::Esc => Action::CloseModal,
        KeyCode::Char('q') => Action::Quit,
        KeyCode::Char('k')
        | KeyCode::Up
        | KeyCode::Char('h')
        | KeyCode::Left
        | KeyCode::BackTab => Action::ChoicePrev,
        KeyCode::Char('j') | KeyCode::Down | KeyCode::Char('l') | KeyCode::Right | KeyCode::Tab => {
            Action::ChoiceNext
        }
        KeyCode::Enter | KeyCode::Char(' ') => Action::Choose,
        _ => return None,
    })
}

#[allow(clippy::wildcard_enum_match_arm, reason = "unbound keys are ignored")]
fn search_keys(key: KeyEvent) -> Option<Action> {
    Some(match key.code {
        KeyCode::Esc => Action::SearchCancel,
        KeyCode::Enter => Action::SearchCommit,
        KeyCode::Backspace => Action::SearchBackspace,
        KeyCode::Down => Action::Move(1),
        KeyCode::Up => Action::Move(-1),
        KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::ALT) => Action::SearchChar(c),
        _ => return None,
    })
}
