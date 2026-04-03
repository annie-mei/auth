const IDENTIFIER_FINGERPRINT_HEX_LEN: usize = 16;

pub fn identifier_fingerprint(identifier: &str, salt: &str) -> String {
    let digest = blake3::hash(format!("{salt}{identifier}").as_bytes());
    digest.to_hex()[..IDENTIFIER_FINGERPRINT_HEX_LEN].to_string()
}

pub fn configure_oauth_scope(
    scope: &mut sentry::Scope,
    operation: &str,
    discord_user_fingerprint: Option<&str>,
) {
    scope.set_tag("service", "annie-mei-auth");
    scope.set_tag("oauth.operation", operation);

    if let Some(discord_user_fingerprint) = discord_user_fingerprint {
        scope.set_tag("oauth.discord_user_fingerprint", discord_user_fingerprint);
    }
}

#[cfg(test)]
mod tests {
    use super::identifier_fingerprint;

    #[test]
    fn identifier_fingerprint_is_stable() {
        let first = identifier_fingerprint("1234567890", "shared-salt");
        let second = identifier_fingerprint("1234567890", "shared-salt");
        assert_eq!(first, second);
        assert_eq!(first.len(), 16);
    }

    #[test]
    fn identifier_fingerprint_changes_with_input() {
        assert_ne!(
            identifier_fingerprint("1234567890", "shared-salt"),
            identifier_fingerprint("1234567891", "shared-salt")
        );
    }

    #[test]
    fn identifier_fingerprint_changes_with_salt() {
        assert_ne!(
            identifier_fingerprint("1234567890", "salt-one"),
            identifier_fingerprint("1234567890", "salt-two")
        );
    }
}
