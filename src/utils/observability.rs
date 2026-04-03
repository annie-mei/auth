use sha2::{Digest, Sha256};

const IDENTIFIER_FINGERPRINT_BYTES: usize = 6;

pub fn identifier_fingerprint(identifier: &str) -> String {
    let digest = Sha256::digest(identifier.as_bytes());
    digest[..IDENTIFIER_FINGERPRINT_BYTES]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn configure_oauth_scope(
    scope: &mut sentry::Scope,
    operation: &str,
    discord_user_id: Option<&str>,
) {
    scope.set_tag("service", "annie-mei-auth");
    scope.set_tag("oauth.operation", operation);

    if let Some(discord_user_id) = discord_user_id {
        scope.set_tag(
            "oauth.discord_user_fingerprint",
            identifier_fingerprint(discord_user_id),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::identifier_fingerprint;

    #[test]
    fn identifier_fingerprint_is_stable() {
        let first = identifier_fingerprint("1234567890");
        let second = identifier_fingerprint("1234567890");
        assert_eq!(first, second);
        assert_eq!(first.len(), 12);
    }

    #[test]
    fn identifier_fingerprint_changes_with_input() {
        assert_ne!(
            identifier_fingerprint("1234567890"),
            identifier_fingerprint("1234567891")
        );
    }
}
