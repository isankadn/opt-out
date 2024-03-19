use axum::middleware::from_fn;
use axum::{
    async_trait,
    body::Body,
    extract::{ Form, Request},
    http::{header, StatusCode},
    middleware::Next,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use axum::Extension;
use dotenv::dotenv;
use log::{info, warn, error};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tokio::signal;
use std::process;
use std::{env, net::SocketAddr};
use tokio::net::TcpListener;
use tower_http::auth::RequireAuthorizationLayer;
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};
use axum::http::HeaderValue;
use axum_extra::extract::TypedHeader;
use axum_extra::extract::cookie::{ Key, CookieJar};
use cookie::{Cookie, SameSite};


async fn auth(
    Extension(pool): Extension<PgPool>,
    cookie: Option<TypedHeader<HeaderValue>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    if let Some(cookie) = cookie {
        if let Ok(cookie_str) = cookie.to_str() {
            if let Some(session_cookie) = cookie_str.strip_prefix("session=") {
                if let Ok(session) = serde_json::from_str::<Session>(session_cookie) {
                    match sqlx::query_as!(
                        StoredUser,
                        r#"
                        SELECT id, username, password_hash
                        FROM users
                        WHERE id = $1
                        "#,
                        session.user_id
                    )
                    .fetch_optional(&pool)
                    .await
                    {
                        Ok(user) => match user {
                            Some(_) => {
                                return Ok(next.run(request).await);
                            }
                            None => {
                                return Err(StatusCode::UNAUTHORIZED);
                            }
                        },
                        Err(err) => {
                            if err.to_string().contains("failed to lookup address information") {
                                warn!("Skipping user creation during Docker image build");
                                process::exit(0);
                            } else {
                                error!("Failed to create user: {:?}", err);
                                process::exit(1);
                            }
                        }
                    }
                }
            }
        }
    
        // No valid session found
    }
        Err(StatusCode::UNAUTHORIZED)
    
}

#[derive(sqlx::FromRow)]
struct StoredUser {
    id: i32,
    username: String,
    password_hash: String,
}

fn hash_password(password: &str) -> Result<String, password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2.hash_password(password.as_bytes(), &salt).map(|hash| hash.to_string())
}

fn verify_password(password_hash: &str, password: &str) -> Result<bool, password_hash::Error> {
    let parsed_hash = PasswordHash::new(password_hash)?;
    Ok(Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok())
}

#[derive(Deserialize)]
struct LoginCredentials {
    username: String,
    password: String,
}
#[derive(Debug, Serialize, Deserialize)]
struct Session {
    user_id: i32,
}

async fn login(
    Extension(pool): Extension<PgPool>,
    jar: CookieJar,
    Form(credentials): Form<LoginCredentials>,
) -> Result<(CookieJar, Redirect), (CookieJar, StatusCode)> {
    // ...

    match sqlx::query_as!(
        StoredUser,
        r#"
        SELECT id, username, password_hash
        FROM users
        WHERE username = $1
        "#,
        credentials.username
    )
    .fetch_optional(&pool)
    .await
    {
        Ok(user) => match user {
            Some(user) => {
                match verify_password(&user.password_hash, &credentials.password) {
                    Ok(valid) => {
                        if valid {
                            let session = Session { user_id: user.id };
                            let cookie = Cookie::build(("session", serde_json::to_string(&session).unwrap()))
                            .path("/")
                            .http_only(true)
                            .same_site(SameSite::Strict)
                            .finish();

                            let jar = jar.add(cookie);

                            Ok((jar, Redirect::to("/protected/opt-out-users")))
                        } else {
                            Err((jar, StatusCode::UNAUTHORIZED))
                        }
                    }
                    Err(_) => Err((jar, StatusCode::INTERNAL_SERVER_ERROR)),
                }
            }
            None => Err((jar, StatusCode::UNAUTHORIZED)),
        },
        Err(_) => Err((jar, StatusCode::INTERNAL_SERVER_ERROR)),
    }
}


async fn login_page() -> impl IntoResponse {
    match std::fs::read_to_string("templates/login.html") {
        Ok(html) => Html(html).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to read login template file",
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct OptOutForm {
    id: i32,
    user_id: String,
    school: String,
    opt_out: bool,
}


async fn opt_out_users_page(
    Extension(pool): Extension<PgPool>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let token = params.get("token").cloned().unwrap_or_default();


    match sqlx::query_as!(
        OptOutForm,
        r#"
        SELECT id, user_id, school, opt_out
        FROM opt_out
        "#
    )
    .fetch_all(&pool)
    .await
    {
        Ok(opt_out_users) => {
            let mut opt_out_users_html = String::new();
            for user in &opt_out_users {
                match std::fs::read_to_string("templates/opt_out_users.html") {
                    Ok(template) => {
                        let rendered = template
                            .replace("{{user_id}}", &user.user_id)
                            .replace("{{school}}", &user.school)
                            .replace("{{opt_out}}", &user.opt_out.to_string())
                            .replace("{{id}}", &user.id.to_string())
                            .replace("{{token}}", &token);
                        opt_out_users_html.push_str(&rendered);
                    }
                    Err(_) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Failed to read template file",
                        )
                            .into_response()
                    }
                }
            }

            match std::fs::read_to_string("templates/opt_out_users_list.html") {
                Ok(template) => {
                    let rendered = template
                        .replace("{{opt_out_users}}", &opt_out_users_html)
                        .replace("{{token}}", &token);
                    Html(rendered).into_response()
                }
                Err(_) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to read template opt_out_users_list file",
                )
                    .into_response(),
            }
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
    }
}


async fn add_opt_out_user_page(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let token = params.get("token").cloned().unwrap_or_default();

    match std::fs::read_to_string("templates/add_opt_out_user.html") {
        Ok(template) => {
            let rendered = template.replace("{{token}}", &token);
            Html(rendered).into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to read template file",
        )
            .into_response(),
    }
}


async fn edit_opt_out_user_page(
    axum::extract::Path(id): axum::extract::Path<i32>,
    Extension(pool): Extension<PgPool>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let token = params.get("token").cloned().unwrap_or_default();


    match sqlx::query_as!(
        OptOutForm,
        r#"
        SELECT id, user_id, school, opt_out
        FROM opt_out
        WHERE id = $1
        "#,
        id
    )
    .fetch_optional(&pool)
    .await
    {
        Ok(opt_out_user) => match opt_out_user {
            Some(opt_out_user) => match std::fs::read_to_string("templates/edit_opt_out_user.html")
            {
                Ok(template) => {
                    let rendered = template
                        .replace("{{id}}", &id.to_string())
                        .replace("{{token}}", &token)
                        .replace("{{user_id}}", &opt_out_user.user_id)
                        .replace("{{school}}", &opt_out_user.school)
                        .replace(
                            "{{checked}}",
                            if opt_out_user.opt_out { "checked" } else { "" },
                        );
                    Html(rendered).into_response()
                }
                Err(_) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to read template file",
                )
                    .into_response(),
            },
            None => (StatusCode::NOT_FOUND, "Opt-out user not found").into_response(),
        },
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
    }
}


async fn opt_out(
    Extension(pool): Extension<PgPool>,
    Form(form): Form<OptOutForm>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let token = params.get("token").cloned().unwrap_or_default();

    if form.user_id.is_empty() || form.school.is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            "user_id and school fields are required",
        )
            .into_response();
    }


    let result = if form.id != 0 {
  
        sqlx::query!(
            r#"
            UPDATE opt_out
            SET user_id = $1, school = $2, opt_out = $3
            WHERE id = $4
            "#,
            form.user_id,
            form.school,
            form.opt_out,
            form.id
        )
        .execute(&pool)
        .await
    } else {

        sqlx::query!(
            r#"
            INSERT INTO opt_out (user_id, school, opt_out)
            VALUES ($1, $2, $3)
            "#,
            form.user_id,
            form.school,
            form.opt_out
        )
        .execute(&pool)
        .await
    };

    match result {
        Ok(_) => {
  
            Redirect::to(&format!("/opt-out-users?token={}", token)).into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
    }
}


async fn delete_opt_out_user(
    axum::extract::Path(id): axum::extract::Path<i32>,
    Extension(pool): Extension<PgPool>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let token = params.get("token").cloned().unwrap_or_default();


    match sqlx::query!(
        r#"
        DELETE FROM opt_out
        WHERE id = $1
        "#,
        id
    )
    .execute(&pool)
    .await
    {
        Ok(_) => {
            // Redirect back to the opt-out users page
            Redirect::to(&format!("/opt-out-users?token={}", token)).into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    println!("signal received, starting graceful shutdown");
}

async fn logout(jar: CookieJar) -> impl IntoResponse {
    let jar = jar.remove(Cookie::named("session"));
    (jar, Redirect::to("/"))
}


#[tokio::main]
async fn main() {
    dotenv().ok();
    env_logger::init();

    let data_base = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = match PgPoolOptions::new()
    .max_connections(5)
    .connect(&data_base)
    .await
    {
        Ok(pool) => pool,
        Err(err) => {
            eprintln!("Failed to create database pool: {:?}", err);
            eprintln!("Proceeding without database connection...");
            std::process::exit(1);
        }
    };


    match sqlx::migrate!("./migrations").run(&pool).await {
        Ok(_) => println!("Database migrations applied successfully"),
        Err(err) => {
            eprintln!("Failed to run database migrations: {:?}", err);
            std::process::exit(1);
        }
    }
    let secret_key = Key::generate();

    let app = Router::new()
        .route("/", get(login_page).post(login))
        .route("/logout", post(logout))
        .layer(Extension(pool.clone()))
        .layer(tower_cookies::CookieManagerLayer::new())
        .nest(
            "/protected",
            Router::new()
            .route("/opt-out-users", get(opt_out_users_page))
                .route("/opt-out/add", get(add_opt_out_user_page))
                .route("/opt-out/edit/:id", get(edit_opt_out_user_page))
                .route("/opt-out/delete/:id", post(delete_opt_out_user))
                .layer(Extension(pool.clone()))
                // .layer(from_fn(auth)),
        );

    // Run the server
    let server_address = std::env::var("SERVER_ADDRESS").unwrap_or("localhost:8090".to_owned());
    let listener = match TcpListener::bind(server_address).await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("Failed to bind to address: {:?}", err);
            std::process::exit(1);
        }
    };
    
    match axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        Ok(_) => println!("Server stopped gracefully"),
        Err(err) => {
            eprintln!("Server error: {:?}", err);
            std::process::exit(1);
        }
    }
    
}