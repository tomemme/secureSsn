use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use chacha20poly1305::{
    aead::{Aead, AeadCore, Payload},
    ChaCha20Poly1305, KeyInit,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{FromRow, Row};
use std::env;

#[derive(Serialize, Deserialize)]
struct RegistrationRequest {
    ssn: String, // In practice, validate SSN format
}

#[derive(Serialize, Deserialize)]
struct TokenResponse {
    token: String,
}

#[derive(Serialize, Deserialize)]
struct VerificationRequest {
    token: String,
}

#[derive(FromRow)]
struct EncryptedData {
    id: i64,
    encrypted_ssn: Vec<u8>,
    nonce: Vec<u8>,
}

struct AppState {
    pool: SqlitePool,
    cipher: ChaCha20Poly1305,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load encryption key from environment (in production, use a secure key management service)
    let key: [u8; 32] = env::var("ENCRYPTION_KEY")
        .expect("ENCRYPTION_KEY must be set")
        .as_bytes()
        .try_into()
        .expect("Key must be 32 bytes");
    let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("Invalid key length");

    // Set up database
    let pool = SqlitePool::connect("sqlite:db.sqlite").await.expect("Failed to connect to database");

    // Initialize database schema
    sqlx::migrate!().run(&pool).await.expect("Failed to migrate database");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(AppState {
                pool: pool.clone(),
                cipher: cipher.clone(),
            }))
            .route("/register", web::post().to(register_ssn))
            .route("/verify", web::post().to(verify_token))
            .route("/rotate", web::post().to(rotate_token))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

async fn register_ssn(
    data: web::Data<AppState>,
    body: web::Json<RegistrationRequest>,
) -> impl Responder {
    let ssn = body.ssn.clone();

    // Generate a nonce (unique per encryption)
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);

    // Encrypt the SSN
    let encrypted = data
        .cipher
        .encrypt(&nonce.into(), ssn.as_bytes().as_ref())
        .map_err(|e| HttpResponse::InternalServerError().body(format!("Encryption error: {}", e)))?;

    // Store encrypted SSN and nonce in database
    let id = sqlx::query(
        "INSERT INTO ssn_data (encrypted_ssn, nonce) VALUES (?1, ?2) RETURNING id",
    )
    .bind(&encrypted)
    .bind(&nonce)
    .fetch_one(&data.pool)
    .await
    .map_err(|e| HttpResponse::InternalServerError().body(format!("Database error: {}", e)))?
    .get(0);

    // Generate a unique token (e.g., hash of ID + random salt)
    let token = format!("token_{}_{}", id, rand::thread_rng().next_u64());

    HttpResponse::Ok().json(TokenResponse { token })
}

async fn verify_token(
    data: web::Data<AppState>,
    body: web::Json<VerificationRequest>,
) -> impl Responder {
    let token = body.token.clone();

    // Parse token to extract ID (simplified; in practice, use secure token format)
    if let Some(id) = token.strip_prefix("token_") {
        if let Ok(id) = id.split('_').next().unwrap_or_default().parse::<i64>() {
            // Fetch encrypted data from database
            let record: EncryptedData = sqlx::query("SELECT * FROM ssn_data WHERE id = ?")
                .bind(id)
                .fetch_one(&data.pool)
                .await
                .map_err(|e| HttpResponse::NotFound().body(format!("Token not found: {}", e)))?;

            // Decrypt to verify (but don't return SSN)
            let nonce = record.nonce.as_slice();
            let ciphertext = record.encrypted_ssn.as_slice();

            data.cipher
                .decrypt(nonce.into(), ciphertext)
                .map(|_| HttpResponse::Ok().body("Valid"))
                .map_err(|e| HttpResponse::Unauthorized().body(format!("Invalid token: {}", e)))
        } else {
            HttpResponse::BadRequest().body("Invalid token format")
        }
    } else {
        HttpResponse::BadRequest().body("Invalid token format")
    }
}

async fn rotate_token(
    data: web::Data<AppState>,
    body: web::Json<VerificationRequest>,
) -> impl Responder {
    // First verify the old token
    let verification = verify_token(data.clone(), body.clone()).await;

    if verification.status().is_success() {
        // If valid, generate new token (simplified; reuse register_ssn logic)
        let old_token = body.token.clone();
        if let Some(id) = old_token.strip_prefix("token_") {
            if let Ok(id) = id.split('_').next().unwrap_or_default().parse::<i64>() {
                // Delete old entry and create new one
                sqlx::query("DELETE FROM ssn_data WHERE id = ?")
                    .bind(id)
                    .execute(&data.pool)
                    .await
                    .map_err(|e| HttpResponse::InternalServerError().body(format!("Database error: {}", e)))?;

                // Re-register (this simulates rotation)
                let mut new_body = RegistrationRequest {
                    ssn: String::new(), // In practice, user would re-provide SSN securely
                };
                // Here you would securely retrieve the original SSN, but for this example, we'll assume it's handled elsewhere
                register_ssn(data, web::Json(new_body)).await
            } else {
                HttpResponse::BadRequest().body("Invalid token format")
            }
        } else {
            HttpResponse::BadRequest().body("Invalid token format")
        }
    } else {
        verification
    }
}
