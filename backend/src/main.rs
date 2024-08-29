use actix_web::{web, App, HttpServer, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use jsonwebtoken::{encode, Header, EncodingKey};
use chrono::Utc;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct User {
    username: String,
    password: String,
}

async fn authenticate(user: web::Json<User>) -> impl Responder {
    const VALID_USERNAME: &str = "admin";
    const VALID_PASSWORD: &str = "password";
    const SECRET_KEY: &str = "your_secret_key";

    if user.username == VALID_USERNAME && user.password == VALID_PASSWORD {
        let claims = Claims {
            sub: user.username.clone(),
            exp: (Utc::now() + chrono::Duration::hours(1)).timestamp() as usize, // Token expires in 1 hour
        };

        match encode(&Header::default(), &claims, &EncodingKey::from_secret(SECRET_KEY.as_ref())) {
            Ok(token) => HttpResponse::Ok().json(token),
            Err(_) => HttpResponse::InternalServerError().finish(),
        }
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .route("/authenticate", web::post().to(authenticate))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
