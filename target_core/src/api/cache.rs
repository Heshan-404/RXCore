#[cfg(test)]
mod tests {
    use crate::config::Config;
    use crate::state::{CachedJsonResponse, EngineState, UserStats};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use parking_lot::RwLock;
    use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64};
    use std::sync::Arc;
    use tower::util::ServiceExt;

    #[tokio::test]
    async fn test_dashboard_handler_initial_cache() {
        let (state, _) = EngineState::new(Config::default());
        let state_arc = Arc::new(state);

        let app = Router::new()
            .route("/api/dashboard", get(crate::api::get_dashboard))
            .with_state(state_arc);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/dashboard")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let etag = response.headers().get("ETag").unwrap().to_str().unwrap();
        assert_eq!(etag, "\"dash-0-0\"");
    }

    #[tokio::test]
    async fn test_dashboard_304_matching_etag() {
        let (state, _) = EngineState::new(Config::default());
        let state_arc = Arc::new(state);

        let app = Router::new()
            .route("/api/dashboard", get(crate::api::get_dashboard))
            .with_state(state_arc);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/dashboard")
                    .header("If-None-Match", "\"dash-0-0\"")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
        assert!(response.headers().get("ETag").is_some());
    }

    #[tokio::test]
    async fn test_dashboard_stale_header() {
        let (state, _) = EngineState::new(Config::default());
        let state_arc = Arc::new(state);

        let stale_dash = CachedJsonResponse {
            body: bytes::Bytes::from("{\"test\":true}"),
            etag: Arc::from("\"dash-1-1\""),
            generated_at: std::time::Instant::now() - std::time::Duration::from_secs(45),
            generation: 1,
        };
        state_arc.cached_dashboard.store(Arc::new(stale_dash));

        let app = Router::new()
            .route("/api/dashboard", get(crate::api::get_dashboard))
            .with_state(state_arc);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/dashboard")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("X-Dashboard-Stale")
                .unwrap()
                .to_str()
                .unwrap(),
            "true"
        );
    }

    #[test]
    fn test_user_truncation_sorting() {
        let mut users = std::collections::HashMap::new();
        for i in 1..=150 {
            let email = format!("user_{:03}@example.com", i);
            users.insert(
                [i as u8; 16],
                Arc::new(UserStats {
                    id: format!("{}", i),
                    email: RwLock::new(Some(email)),
                    limit_ip: AtomicU32::new(0),
                    total_gb: AtomicI64::new(-1),
                    expiry_time: AtomicI64::new(0),
                    speed_limit: AtomicU64::new(0),
                    remaining_bytes: AtomicI64::new(-1),
                    rx: AtomicU64::new(0),
                    tx: AtomicU64::new(0),
                    reality_profile_id: RwLock::new(None),
                    inbound_tag: RwLock::new(None),
                }),
            );
        }

        let mut users_all: Vec<_> = users.values().cloned().collect();
        users_all.sort_by(|a, b| {
            let a_email = a.email.read();
            let b_email = b.email.read();
            a_email.cmp(&b_email)
        });

        assert_eq!(users_all.len(), 150);
        let first_email = users_all[0].email.read().clone().unwrap();
        assert_eq!(first_email, "user_001@example.com");

        let truncated: Vec<_> = users_all.into_iter().take(100).collect();
        assert_eq!(truncated.len(), 100);
        let last_email = truncated[99].email.read().clone().unwrap();
        assert_eq!(last_email, "user_100@example.com");
    }
}
