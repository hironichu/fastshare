use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, Method, Request, StatusCode};
use fastshare::metrics::{Metrics, NetworkInfo};
use fastshare::security::{IpRule, SecurityConfig};
use fastshare::server::{build_router, AppState};
use http_body_util::BodyExt;
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

fn setup_custom_app(sec_cfg: SecurityConfig) -> (tempfile::TempDir, AppState, axum::Router) {
    let dir = tempfile::tempdir().unwrap();
    let sample_data: Vec<u8> = (0..256_000).map(|i| (i % 251) as u8).collect();
    std::fs::write(dir.path().join("large_sample.bin"), &sample_data).unwrap();
    std::fs::write(dir.path().join("second_file.txt"), b"Second file content").unwrap();
    std::fs::write(dir.path().join(".hidden_secret"), b"Hidden dotfile").unwrap();

    let sub = dir.path().join("subfolder");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(sub.join("hello.txt"), b"Hello 10GbE World!").unwrap();

    let net_info = NetworkInfo {
        local_ip: "127.0.0.1".to_string(),
        public_ip: Some("203.0.113.10".to_string()),
        port: 24567,
        upnp_status: "Test".to_string(),
        token: "secret123token".to_string(),
        shared_dir: dir.path().display().to_string(),
    };
    let metrics = Metrics::with_security(net_info, sec_cfg);
    let state = AppState {
        root_dir: std::fs::canonicalize(dir.path()).unwrap(),
        token: "secret123token".to_string(),
        chunk_size: 64 * 1024,
        allow_hidden: false,
        metrics: Arc::clone(&metrics),
    };
    let app = build_router(state.clone());
    (dir, state, app)
}

fn setup_test_app() -> (tempfile::TempDir, AppState, axum::Router) {
    setup_custom_app(SecurityConfig {
        password: None,
        max_downloads: None,
        max_bytes: None,
        max_concurrent: 64,
        ttl: None,
        max_auth_failures: 5,
        initial_blacklist: Vec::new(),
    })
}

fn with_ip(mut req: Request<Body>, ip_port: &str) -> Request<Body> {
    let addr: SocketAddr = ip_port.parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(addr));
    req
}

fn with_connect_info(req: Request<Body>) -> Request<Body> {
    with_ip(req, "127.0.0.1:54321")
}

#[tokio::test]
async fn test_token_protection_and_directory_listing() {
    let (_dir, _state, app) = setup_test_app();

    // 1. Invalid token should return 404 + security headers
    let req_bad = with_connect_info(
        Request::builder()
            .uri("/wrongtoken/")
            .body(Body::empty())
            .unwrap(),
    );
    let resp_bad = app.clone().oneshot(req_bad).await.unwrap();
    assert_eq!(resp_bad.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        resp_bad.headers().get(header::X_FRAME_OPTIONS).unwrap(),
        "DENY"
    );

    // 2. Hidden dotfile is blocked by default
    let req_hidden = with_connect_info(
        Request::builder()
            .uri("/secret123token/.hidden_secret")
            .body(Body::empty())
            .unwrap(),
    );
    let resp_hidden = app.clone().oneshot(req_hidden).await.unwrap();
    assert_eq!(resp_hidden.status(), StatusCode::NOT_FOUND);

    // 3. Valid token returns 200 HTML listing with files and folders (excluding dotfiles)
    let req_ok = with_connect_info(
        Request::builder()
            .uri("/secret123token/")
            .header(header::HOST, "127.0.0.1:24567")
            .body(Body::empty())
            .unwrap(),
    );
    let resp_ok = app.oneshot(req_ok).await.unwrap();
    assert_eq!(resp_ok.status(), StatusCode::OK);
    let body_bytes = resp_ok.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&body_bytes);
    assert!(html.contains("large_sample.bin"));
    assert!(html.contains("subfolder"));
    assert!(html.contains("aria2c"));
    assert!(!html.contains(".hidden_secret"));
}

#[tokio::test]
async fn test_http_range_partial_download() {
    let (_dir, _state, app) = setup_test_app();

    let req = with_connect_info(
        Request::builder()
            .uri("/secret123token/large_sample.bin")
            .header(header::RANGE, "bytes=1000-1999")
            .body(Body::empty())
            .unwrap(),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        resp.headers().get(header::CONTENT_RANGE).unwrap(),
        "bytes 1000-1999/256000"
    );
    assert_eq!(
        resp.headers().get(header::CONTENT_LENGTH).unwrap(),
        "1000"
    );

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body_bytes.len(), 1000);
    let expected: Vec<u8> = (1000..2000).map(|i| (i % 251) as u8).collect();
    assert_eq!(&body_bytes[..], &expected[..]);
}

#[tokio::test]
async fn test_streaming_tar_and_zip_archives() {
    let (_dir, _state, app) = setup_test_app();

    let req_tar = with_connect_info(
        Request::builder()
            .uri("/secret123token/?archive=tar")
            .body(Body::empty())
            .unwrap(),
    );
    let resp_tar = app.clone().oneshot(req_tar).await.unwrap();
    assert_eq!(resp_tar.status(), StatusCode::OK);
    let tar_bytes = resp_tar.into_body().collect().await.unwrap().to_bytes();
    assert!(tar_bytes.len() > 256_000);

    let req_zip = with_connect_info(
        Request::builder()
            .uri("/secret123token/subfolder?archive=zip")
            .body(Body::empty())
            .unwrap(),
    );
    let resp_zip = app.oneshot(req_zip).await.unwrap();
    assert_eq!(resp_zip.status(), StatusCode::OK);
    let zip_bytes = resp_zip.into_body().collect().await.unwrap().to_bytes();
    assert!(zip_bytes.starts_with(b"PK\x03\x04"));
    let _ = Cursor::new(zip_bytes);
}

#[tokio::test]
async fn test_password_protection_and_session_auth() {
    let (_dir, _state, app) = setup_custom_app(SecurityConfig {
        password: Some("ultra10gpass".to_string()),
        max_downloads: None,
        max_bytes: None,
        max_concurrent: 64,
        ttl: None,
        max_auth_failures: 5,
        initial_blacklist: Vec::new(),
    });

    // 1. Unauthenticated GET returns 401 Lock Screen
    let req_unauth = with_connect_info(
        Request::builder()
            .uri("/secret123token/")
            .body(Body::empty())
            .unwrap(),
    );
    let resp_unauth = app.clone().oneshot(req_unauth).await.unwrap();
    assert_eq!(resp_unauth.status(), StatusCode::UNAUTHORIZED);
    let login_html = String::from_utf8_lossy(
        &resp_unauth.into_body().collect().await.unwrap().to_bytes(),
    )
    .to_string();
    assert!(login_html.contains("Password Protected Share"));

    // 2. Wrong password POST returns 401
    let req_bad_pw = with_connect_info(
        Request::builder()
            .method(Method::POST)
            .uri("/secret123token/__auth")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from("password=wrongpass&redirect=%2Fsecret123token%2F"))
            .unwrap(),
    );
    let resp_bad_pw = app.clone().oneshot(req_bad_pw).await.unwrap();
    assert_eq!(resp_bad_pw.status(), StatusCode::UNAUTHORIZED);

    // 3. Correct password POST returns 303 redirect + Set-Cookie
    let req_good_pw = with_connect_info(
        Request::builder()
            .method(Method::POST)
            .uri("/secret123token/__auth")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(
                "password=ultra10gpass&redirect=%2Fsecret123token%2F",
            ))
            .unwrap(),
    );
    let resp_good_pw = app.clone().oneshot(req_good_pw).await.unwrap();
    assert_eq!(resp_good_pw.status(), StatusCode::SEE_OTHER);
    let set_cookie = resp_good_pw
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let session_pair = set_cookie.split(';').next().unwrap();

    // 4. Subsequent GET with session cookie succeeds (200 OK)
    let req_authed = with_connect_info(
        Request::builder()
            .uri("/secret123token/")
            .header(header::COOKIE, session_pair)
            .body(Body::empty())
            .unwrap(),
    );
    let resp_authed = app.oneshot(req_authed).await.unwrap();
    assert_eq!(resp_authed.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_download_limits_and_range_dedup() {
    let (_dir, _state, app) = setup_custom_app(SecurityConfig {
        password: None,
        max_downloads: Some(1),
        max_bytes: None,
        max_concurrent: 64,
        ttl: None,
        max_auth_failures: 5,
        initial_blacklist: Vec::new(),
    });

    // 1. Multiple Range requests for the SAME file from the SAME IP count as 1 logical download!
    for range in ["bytes=0-999", "bytes=1000-1999", "bytes=2000-2999"] {
        let req = with_connect_info(
            Request::builder()
                .uri("/secret123token/large_sample.bin")
                .header(header::RANGE, range)
                .body(Body::empty())
                .unwrap(),
        );
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        let _ = resp.into_body().collect().await.unwrap();
    }

    // 2. Requesting a SECOND distinct file exceeds max_downloads=1 and returns 410 Gone
    let req_second = with_connect_info(
        Request::builder()
            .uri("/secret123token/second_file.txt")
            .body(Body::empty())
            .unwrap(),
    );
    let resp_second = app.oneshot(req_second).await.unwrap();
    assert_eq!(resp_second.status(), StatusCode::GONE);
}

#[tokio::test]
async fn test_ip_blacklist_and_auto_bruteforce_ban() {
    let (_dir, _state, app) = setup_custom_app(SecurityConfig {
        password: None,
        max_downloads: None,
        max_bytes: None,
        max_concurrent: 64,
        ttl: None,
        max_auth_failures: 3,
        initial_blacklist: vec![IpRule::parse("198.51.100.0/24").unwrap()],
    });

    // 1. IP in blacklisted CIDR 198.51.100.0/24 gets immediate 403 Forbidden
    let req_cidr = with_ip(
        Request::builder()
            .uri("/secret123token/")
            .body(Body::empty())
            .unwrap(),
        "198.51.100.42:50000",
    );
    let resp_cidr = app.clone().oneshot(req_cidr).await.unwrap();
    assert_eq!(resp_cidr.status(), StatusCode::FORBIDDEN);

    // 2. Another external IP fails token 3 times -> gets auto-blacklisted on 4th request even with valid token!
    for _ in 0..3 {
        let req_fail = with_ip(
            Request::builder()
                .uri("/badtokenAttempt/")
                .body(Body::empty())
                .unwrap(),
            "203.0.113.99:50000",
        );
        let resp_fail = app.clone().oneshot(req_fail).await.unwrap();
        assert_eq!(resp_fail.status(), StatusCode::NOT_FOUND);
    }

    let req_after_ban = with_ip(
        Request::builder()
            .uri("/secret123token/")
            .body(Body::empty())
            .unwrap(),
        "203.0.113.99:50000",
    );
    let resp_after_ban = app.oneshot(req_after_ban).await.unwrap();
    assert_eq!(resp_after_ban.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_ttl_expiration() {
    let (_dir, _state, app) = setup_custom_app(SecurityConfig {
        password: None,
        max_downloads: None,
        max_bytes: None,
        max_concurrent: 64,
        ttl: Some(Duration::from_millis(50)),
        max_auth_failures: 5,
        initial_blacklist: Vec::new(),
    });

    tokio::time::sleep(Duration::from_millis(80)).await;

    let req = with_connect_info(
        Request::builder()
            .uri("/secret123token/")
            .body(Body::empty())
            .unwrap(),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::GONE);
}

#[tokio::test]
async fn test_lan_ip_detection_skips_cgnat() {
    let local_ip = fastshare::net::detect_local_ip();
    println!("Detected LAN IP: {}", local_ip);
    assert!(!local_ip.to_string().starts_with("100."));
}
