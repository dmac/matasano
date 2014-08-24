use matasano;

#[deriving(Show)]
pub struct Profile {
    email: String,
    uid: uint,
    role: String,
}

pub fn parse_profile(s: &str) -> Profile {
    let mut email = None;
    let mut uid = None;
    let mut role = None;
    for keyval in s.split('&') {
        match keyval.split('=').collect::<Vec<&str>>().as_slice() {
            [key, val] => {
                match key {
                    "email" => email = Some(val),
                    "role" => role = Some(val),
                    "uid" => {
                        match from_str::<uint>(val) {
                            Some(val) => uid = Some(val),
                            None => fail!("error parsing profile: uid not valid: {}", s)
                        }
                    }
                    _ => {}
                }
            }
            _ => fail!("error parsing profile: invalid format: {}", s)
        }
    }
    match (email, uid, role) {
        (Some(email), Some(uid), Some(role)) => {
            Profile{email: email.to_string(), uid: uid, role: role.to_string()}
        },
        _ => fail!("error parsing profile: missing fields: {}", s)
    }
}

pub fn profile_for(email: &str) -> String {
    let email_safe = email.replace("&", "%26").as_slice().replace("=", "%3D");
    format!("email={}&uid={}&role={}", email_safe, 10u, "user")
}

static secret_key: &'static str = "SECRETUNKNOWNKEY";

// Encrypt the encoded user profile under a secret key
pub fn encrypt_profile(email: &str) -> Vec<u8>{
    matasano::aes_ecb(email.as_bytes(), secret_key.as_bytes(), true)
}

// Decrypt the encoded user profile and parse it.
pub fn decrypt_profile(data: Vec<u8>) -> Profile {
    let profile_str = String::from_utf8(matasano::aes_ecb(data.as_slice(), secret_key.as_bytes(), false))
        .ok().expect("error decoding profile");
    parse_profile(profile_str.as_slice())
}
