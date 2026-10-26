//! Short human sentences for daemon error codes. Toasts show the sentence plus the code verbatim.

use vpnui_proto::{ErrorBody, ErrorCode};

pub fn sentence(code: ErrorCode) -> Option<&'static str> {
    Some(match code {
        ErrorCode::BadRequest => "The daemon did not understand the request",
        ErrorCode::UnknownServer => "That server is not in the daemon's catalog",
        ErrorCode::InvalidState => "That action is not possible right now",
        ErrorCode::VersionMismatch => "The daemon speaks a different protocol version",
        ErrorCode::Internal => "The daemon hit an internal error",
        ErrorCode::NoProfiles => "No profiles imported yet",
        ErrorCode::NoNetwork => "No network connection",
        ErrorCode::BinaryUntrusted => {
            "wireguard-go is not installed in a trusted location; run sudo vpnuid install"
        }
        ErrorCode::HandshakeTimeout => "The server did not respond to the handshake",
        ErrorCode::PfFailed => "The kill switch policy could not be applied",
        ErrorCode::RouteFailed => "The tunnel routes could not be set up",
        ErrorCode::DnsFailed => "The tunnel DNS servers could not be applied",
        ErrorCode::WgFailed => "The WireGuard tunnel could not be started",
        ErrorCode::Busy => "The daemon is busy",
        ErrorCode::Unauthorized => "This user is not allowed to control the daemon",
        ErrorCode::Unknown => return None,
    })
}

/// `<sentence> (<code>)`, falling back to the daemon's own message for unknown codes.
pub fn describe(error: &ErrorBody) -> String {
    match sentence(error.code) {
        Some(sentence) => format!("{sentence} ({})", error.code.as_str()),
        None => error.message.clone(),
    }
}

/// Expands a `last_error` of the form `<code>: <detail>`; other text is returned unchanged.
pub fn explain_last_error(text: &str) -> String {
    let Some((code, detail)) = text.split_once(':') else {
        return text.to_owned();
    };
    let code = code.trim();
    match sentence(ErrorCode::parse(code)) {
        Some(sentence) => format!("{sentence} ({code}): {}", detail.trim()),
        None => text.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_known_code_has_a_sentence() {
        for code in ErrorCode::ALL {
            assert!(sentence(code).is_some(), "{code:?}");
        }
        assert!(sentence(ErrorCode::Unknown).is_none());
    }

    #[test]
    fn describe_keeps_the_code_verbatim() {
        let error = ErrorBody {
            code: ErrorCode::HandshakeTimeout,
            message: "no handshake within 15s".into(),
        };
        assert_eq!(
            describe(&error),
            "The server did not respond to the handshake (handshake_timeout)"
        );
        let unknown = ErrorBody {
            code: ErrorCode::Unknown,
            message: "quota exceeded".into(),
        };
        assert_eq!(describe(&unknown), "quota exceeded");
    }

    #[test]
    fn last_error_codes_are_expanded() {
        assert_eq!(
            explain_last_error("handshake_timeout: no handshake within 15s"),
            "The server did not respond to the handshake (handshake_timeout): no handshake within 15s"
        );
        assert_eq!(
            explain_last_error("handshake timed out"),
            "handshake timed out"
        );
        assert_eq!(
            explain_last_error("connection lost: peer stopped responding"),
            "connection lost: peer stopped responding"
        );
    }
}
