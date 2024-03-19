use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use dotenv::dotenv;
use log::{error, info, warn};
use sqlx::postgres::PgPoolOptions;
use std::io::{self, Write};
use std::process;

#[tokio::main]
async fn main() {
    dotenv().ok();

    let data_base = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
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

    print!("Enter username: ");
    io::stdout().flush().unwrap();
    let mut username = String::new();
    io::stdin().read_line(&mut username).unwrap();
    username = username.trim().to_string();

    print!("Enter password: ");
    io::stdout().flush().unwrap();
    let mut password = String::new();
    io::stdin().read_line(&mut password).unwrap();
    password = password.trim().to_string();

    print!("Is this user an admin? (true/false): ");
    io::stdout().flush().unwrap();
    let mut admin_input = String::new();
    io::stdin().read_line(&mut admin_input).unwrap();
    let admin = admin_input.trim().parse::<bool>().unwrap_or(false);

    let password_hash = hash_password(&password).unwrap();


    match sqlx::query!(
        r#"
        INSERT INTO users (username, password_hash, admin)
        VALUES ($1, $2, $3)
        "#,
        username,
        password_hash,
        admin
    )
    .execute(&pool)
    .await
    {
        Ok(_) => {
            info!("User created successfully");
            std::process::exit(0);
        }
        Err(err) => {
            if err.to_string().contains("failed to lookup address information") {
                warn!("Skipping user creation during Docker image build");
                std::process::exit(0);
            } else {
                error!("Failed to create user: {:?}", err);
                std::process::exit(1);
            }
        }
    }
}

fn hash_password(password: &str) -> Result<String, password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
}
