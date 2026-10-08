use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::get,
    Router,
};
use std::sync::Arc;
use target_core::config::Config;
use target_core::state::{CachedJsonResponse, EngineState};
use tower::ServiceExt;

#[tokio::test]
async fn test_dashboard_integration_headers_and_304() {
    let (state, _) = EngineState::new(Config::default());
    let state_arc = Arc::new(state);

    let app = Router::new()
        .route("/api/dashboard", get(target_core::api::get_dashboard))
        .with_state(state_arc.clone());

    // 1. Initial cached response request
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/dashboard")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let cache_control = response
        .headers()
        .get("Cache-Control")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(cache_control, "private, no-cache, must-revalidate");

    let etag = response.headers().get("ETag").unwrap().to_str().unwrap();
    assert!(etag.starts_with("\"dash-"));

    let gen = response
        .headers()
        .get("X-Dashboard-Generation")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(gen, "0");

    // 2. Matching ETag should return 304 Not Modified
    let response_304 = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/dashboard")
                .header("If-None-Match", etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response_304.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(
        response_304
            .headers()
            .get("ETag")
            .unwrap()
            .to_str()
            .unwrap(),
        etag
    );

    // 3. Stale cache should return stale header
    let stale_cache = CachedJsonResponse {
        body: bytes::Bytes::from("{\"stale\":true}"),
        etag: Arc::from("\"stale-etag-123\""),
        generated_at: std::time::Instant::now() - std::time::Duration::from_secs(35),
        generation: 42,
    };
    state_arc.cached_dashboard.store(Arc::new(stale_cache));

    let response_stale = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/dashboard")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response_stale.status(), StatusCode::OK);
    assert_eq!(
        response_stale
            .headers()
            .get("X-Dashboard-Stale")
            .unwrap()
            .to_str()
            .unwrap(),
        "true"
    );
}
