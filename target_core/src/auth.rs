use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params,
};
use parking_lot::Mutex;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use std::time::{Duration, Instant};

pub static ADMIN_AUTH_CPU: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

pub struct LoginRateLimiter {
    attempts: Mutex<HashMap<IpAddr, Vec<Instant>>>,
    global_attempts: Mutex<Vec<Instant>>,
}

impl LoginRateLimiter {
    pub fn new() -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
            global_attempts: Mutex::new(Vec::new()),
        }
    }

    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(300);

        let mut global = self.global_attempts.lock();
        global.retain(|&t| now.duration_since(t) < window);
        if global.len() >= 20 {
            return false;
        }

        let mut ip_map = self.attempts.lock();
        if let Some(entry) = ip_map.get_mut(&ip) {
            entry.retain(|&t| now.duration_since(t) < window);
            if entry.len() >= 5 {
                return false;
            }
        }
        true
    }

    pub fn record_failure(&self, ip: IpAddr) {
        let now = Instant::now();
        let mut global = self.global_attempts.lock();
        global.push(now);

        let mut ip_map = self.attempts.lock();
        let entry = ip_map.entry(ip).or_insert_with(Vec::new);
        entry.push(now);
    }

    pub fn record_success(&self, ip: IpAddr) {
        let mut ip_map = self.attempts.lock();
        ip_map.remove(&ip);
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AdminCredentials {
    pub password_hash: String,
    pub session_secret: String,
    pub session_epoch: u64,
    pub created_at: i64,
    pub updated_at: i64,
    pub version: u32,
}

pub fn get_credentials_path() -> PathBuf {
    Path::new("data/admin_credentials.json").to_path_buf()
}

pub fn get_argon2_instance() -> Result<Argon2<'static>, Box<dyn std::error::Error + Send + Sync>> {
    let params = Params::new(
        32768, // 32 MB in KiB
        2,     // 2 iterations
        1,     // 1 parallelism
        None,
    )
    .map_err(|e| e.to_string())?;
    Ok(Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    ))
}

pub fn load_admin_credentials(
) -> Result<Option<AdminCredentials>, Box<dyn std::error::Error + Send + Sync>> {
    let path = get_credentials_path();
    if !path.exists() {
        return Ok(None);
    }

    let metadata = fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink() {
        return Err("Credential file path is a symbolic link, rejecting for security".into());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let file_uid = metadata.uid();
        let current_uid = nix::unistd::getuid().as_raw();
        if file_uid != current_uid && current_uid != 0 {
            return Err("Credential file is not owned by the current service user".into());
        }
        let mode = metadata.mode();
        if (mode & 0o077) != 0 {
            return Err("Credential file has unsafe permissions (should be 0600)".into());
        }
    }

    let content = fs::read_to_string(&path)?;
    let creds: AdminCredentials = serde_json::from_str(&content)?;
    Ok(Some(creds))
}

pub fn save_admin_credentials(
    creds: &AdminCredentials,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = get_credentials_path();
    let dir = path.parent().ok_or("Invalid data directory path")?;

    if !dir.exists() {
        fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
    } else {
        let dir_metadata = fs::symlink_metadata(dir)?;
        if dir_metadata.file_type().is_symlink() {
            return Err("Data directory path is a symbolic link, rejecting".into());
        }
    }

    let tmp_path = dir.join("admin_credentials.json.tmp");
    let json_bytes = serde_json::to_vec(creds)?;

    fs::write(&tmp_path, &json_bytes)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))?;
    }

    let file = File::open(&tmp_path)?;
    file.sync_all()?;
    drop(file);

    fs::rename(&tmp_path, &path)?;

    let parent_dir = File::open(dir)?;
    parent_dir.sync_all()?;

    Ok(())
}

pub fn hash_password(password: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = get_argon2_instance()?;
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| e.to_string())?
        .to_string();
    Ok(password_hash)
}

pub fn verify_password(
    hash: &str,
    password: &str,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let parsed_hash =
        PasswordHash::new(hash).map_err(|e| format!("Invalid password hash format: {}", e))?;
    let argon2 = get_argon2_instance()?;
    Ok(argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

pub fn generate_random_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes);
    hex::encode(bytes)
}

pub fn validate_password_rules(password: &str) -> Result<(), &'static str> {
    if password.trim().is_empty() {
        return Err("Password cannot be empty or whitespace-only");
    }
    if password.len() < 12 {
        return Err("Password must be at least 12 characters long");
    }
    if password.len() > 128 {
        return Err("Password must not exceed 128 characters");
    }
    Ok(())
}

pub fn prompt_password_interactive() -> io::Result<String> {
    loop {
        print!("Administrator password: ");
        io::stdout().flush()?;
        let p1 = rpassword::read_password()?;

        print!("Confirm administrator password: ");
        io::stdout().flush()?;
        let p2 = rpassword::read_password()?;

        if p1 != p2 {
            println!("Error: Passwords do not match. Please try again.\n");
            continue;
        }

        if let Err(e) = validate_password_rules(&p1) {
            println!("Error: {}\n", e);
            continue;
        }

        return Ok(p1);
    }
}

pub fn handle_admin_cli(args: &[String]) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    if args.len() < 2 || args[1] != "admin" {
        return Ok(false);
    }

    if args.len() < 3 {
        println!("Available subcommands:\n  target_core admin init [--password-file <path>]\n  target_core admin set-password\n  target_core admin reset-password --confirm-local-reset");
        return Ok(true);
    }

    let cmd = args[2].as_str();
    match cmd {
        "init" => {
            let existing = load_admin_credentials()?;
            if existing.is_some() {
                println!("Error: Administrator credentials already initialized. Use 'set-password' or 'reset-password' instead.");
                return Ok(true);
            }

            let mut password = None;
            if args.len() >= 5 && args[3] == "--password-file" {
                let file_path = Path::new(&args[4]);
                let metadata = fs::symlink_metadata(file_path)?;
                if metadata.file_type().is_symlink() {
                    return Err("Password file path is a symbolic link".into());
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    let mode = metadata.mode();
                    if (mode & 0o077) != 0 {
                        return Err(
                            "Password file has unsafe permissions (should be 0600 or 0400)".into(),
                        );
                    }
                }
                let content = fs::read_to_string(file_path)?;
                let trimmed = content.trim().to_string();
                validate_password_rules(&trimmed)?;
                password = Some(trimmed);
            }

            let pass_val = match password {
                Some(p) => p,
                None => {
                    println!("Ruve VPN Administrator Setup");
                    println!("Create a password for the administration dashboard.\n");
                    prompt_password_interactive()?
                }
            };

            let hash = hash_password(&pass_val)?;
            let secret = generate_random_secret();
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            let creds = AdminCredentials {
                password_hash: hash,
                session_secret: secret,
                session_epoch: 1,
                created_at: now,
                updated_at: now,
                version: 1,
            };

            save_admin_credentials(&creds)?;
            println!("Administrator credentials initialized successfully!");
            Ok(true)
        }
        "set-password" => {
            let existing_opt = load_admin_credentials()?;
            let mut existing = match existing_opt {
                Some(e) => e,
                None => {
                    println!("Error: Credentials are not initialized. Run 'admin init' first.");
                    return Ok(true);
                }
            };

            print!("Current administrator password: ");
            io::stdout().flush()?;
            let current = rpassword::read_password()?;

            if !verify_password(&existing.password_hash, &current)? {
                println!("Error: Incorrect current password.");
                return Ok(true);
            }

            println!("\nEnter your new password:");
            let new_pass = prompt_password_interactive()?;

            let hash = hash_password(&new_pass)?;
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            existing.password_hash = hash;
            existing.session_secret = generate_random_secret();
            existing.session_epoch += 1;
            existing.updated_at = now;

            save_admin_credentials(&existing)?;
            println!("Password updated successfully!");
            Ok(true)
        }
        "reset-password" => {
            if args.len() < 4 || args[3] != "--confirm-local-reset" {
                println!("Error: Resetting the password requires local filesystem/root access.");
                println!("Please run: target_core admin reset-password --confirm-local-reset");
                return Ok(true);
            }

            println!("Local administrator password reset initiated.");
            println!("Enter the new administrator password:");
            let new_pass = prompt_password_interactive()?;

            let hash = hash_password(&new_pass)?;
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            let creds = AdminCredentials {
                password_hash: hash,
                session_secret: generate_random_secret(),
                session_epoch: 1,
                created_at: now,
                updated_at: now,
                version: 1,
            };

            save_admin_credentials(&creds)?;
            println!("Administrator password has been successfully reset! All active sessions invalidated.");
            Ok(true)
        }
        _ => {
            println!("Unknown subcommand. Available: init, set-password, reset-password");
            Ok(true)
        }
    }
}

#[derive(Clone, Debug)]
pub struct AdminAuthRuntime {
    pub password_hash: Arc<str>,
    pub session_secret: Arc<[u8]>,
    pub session_epoch: u64,
}

#[derive(Clone, Debug)]
pub struct AdminSessionClaims {
    pub version: u8,
    pub issued_at: i64,
    pub expires_at: i64,
    pub session_epoch: u64,
    pub csrf_token: [u8; 32],
}

use base64::Engine;
use std::sync::Arc;

pub fn encode_session_cookie(
    claims: &AdminSessionClaims,
    key_bytes: &[u8],
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let mut payload = Vec::with_capacity(57);
    payload.push(claims.version);
    payload.extend_from_slice(&claims.issued_at.to_be_bytes());
    payload.extend_from_slice(&claims.expires_at.to_be_bytes());
    payload.extend_from_slice(&claims.session_epoch.to_be_bytes());
    payload.extend_from_slice(&claims.csrf_token);

    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key_bytes);
    let tag = ring::hmac::sign(&key, &payload);
    let signature = tag.as_ref();

    let mut full = Vec::with_capacity(89);
    full.extend_from_slice(&payload);
    full.extend_from_slice(signature);

    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(full))
}

pub fn decode_and_verify_session(
    cookie_val: &str,
    key_bytes: &[u8],
) -> Result<AdminSessionClaims, Box<dyn std::error::Error + Send + Sync>> {
    let full = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(cookie_val)?;
    if full.len() != 89 {
        return Err("Invalid session token length".into());
    }

    let payload = &full[..57];
    let expected_sig = &full[57..];

    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key_bytes);
    if ring::hmac::verify(&key, payload, expected_sig).is_err() {
        return Err("Session token signature verification failed".into());
    }

    let version = payload[0];
    if version != 1 {
        return Err("Unsupported session token version".into());
    }

    let mut i_bytes = [0u8; 8];
    i_bytes.copy_from_slice(&payload[1..9]);
    let issued_at = i64::from_be_bytes(i_bytes);

    let mut e_bytes = [0u8; 8];
    e_bytes.copy_from_slice(&payload[9..17]);
    let expires_at = i64::from_be_bytes(e_bytes);

    let mut ep_bytes = [0u8; 8];
    ep_bytes.copy_from_slice(&payload[17..25]);
    let session_epoch = u64::from_be_bytes(ep_bytes);

    let mut csrf_token = [0u8; 32];
    csrf_token.copy_from_slice(&payload[25..57]);

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    if now > expires_at {
        return Err("Session token expired".into());
    }

    Ok(AdminSessionClaims {
        version,
        issued_at,
        expires_at,
        session_epoch,
        csrf_token,
    })
}
