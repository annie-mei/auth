const IDENTIFIER_FINGERPRINT_HEX_LEN: usize = 16;

pub fn identifier_fingerprint(identifier: &str, salt: &str) -> String {
    let digest = blake3::hash(format!("{salt}{identifier}").as_bytes());
    digest.to_hex()[..IDENTIFIER_FINGERPRINT_HEX_LEN].to_string()
}

pub fn record_identifier_fingerprint(
    span: &tracing::Span,
    field: &str,
    identifier: &str,
    salt: &str,
) {
    let fingerprint = identifier_fingerprint(identifier, salt);
    span.record(field, tracing::field::display(fingerprint));
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
        scope.set_user(Some(sentry::User {
            id: Some(discord_user_fingerprint.to_string()),
            ..Default::default()
        }));
    }
}

pub fn redact_url_credentials(input: &str) -> String {
    use linkify::{LinkFinder, LinkKind};

    if let Ok(mut parsed) = url::Url::parse(input) {
        let has_username = !parsed.username().is_empty();
        let has_password = parsed.password().is_some();
        if has_username || has_password {
            if has_username {
                let _ = parsed.set_username("REDACTED_USERNAME");
            }
            if has_password {
                let _ = parsed.set_password(Some("REDACTED_PASSWORD"));
            }
            return parsed.to_string();
        }
    }

    let mut finder = LinkFinder::new();
    finder.kinds(&[LinkKind::Url]);

    let links: Vec<_> = finder.links(input).collect();

    if links.is_empty() {
        return input.to_string();
    }

    let mut result = String::with_capacity(input.len());
    let mut last_end = 0;

    for link in links {
        result.push_str(&input[last_end..link.start()]);
        result.push_str(&redact_single_url(link.as_str()));
        last_end = link.end();
    }

    result.push_str(&input[last_end..]);
    result
}

fn redact_single_url(url_str: &str) -> String {
    match url::Url::parse(url_str) {
        Ok(mut parsed_url) => {
            let has_username = !parsed_url.username().is_empty();
            let has_password = parsed_url.password().is_some();

            if has_username || has_password {
                if has_username {
                    let _ = parsed_url.set_username("REDACTED_USERNAME");
                }
                if has_password {
                    let _ = parsed_url.set_password(Some("REDACTED_PASSWORD"));
                }
                parsed_url.to_string()
            } else {
                url_str.to_string()
            }
        }
        Err(_) => url_str.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{identifier_fingerprint, redact_url_credentials};

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

    #[test]
    fn redact_url_credentials_redacts_database_url() {
        let input = "postgres://admin:secret@localhost:5432/mydb";
        let redacted = redact_url_credentials(input);
        assert!(redacted.contains("REDACTED_USERNAME"));
        assert!(redacted.contains("REDACTED_PASSWORD"));
        assert!(!redacted.contains("admin"));
        assert!(!redacted.contains("secret"));
    }

    #[test]
    fn redact_url_credentials_preserves_url_without_credentials() {
        let input = "https://graphql.anilist.co";
        assert_eq!(redact_url_credentials(input), input);
    }

    #[test]
    fn redact_url_credentials_handles_embedded_urls() {
        let input =
            "Error connecting to postgres://user:pass@localhost:5432/db: connection refused";
        let redacted = redact_url_credentials(input);
        assert!(!redacted.contains("user:pass"));
        assert!(redacted.contains("connection refused"));
    }

    #[test]
    fn redact_url_credentials_returns_plain_text_unchanged() {
        let input = "no urls here";
        assert_eq!(redact_url_credentials(input), input);
    }
}
