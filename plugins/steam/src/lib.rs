// Steam Plugin for HappyView
// Uses OpenID 2.0 for authentication and Steam Web API for data

#![cfg_attr(target_arch = "wasm32", no_std)]
#![allow(static_mut_refs)]

#[cfg(target_arch = "wasm32")]
extern crate alloc;

#[cfg(target_arch = "wasm32")]
use alloc::{format, string::String, string::ToString, vec::Vec};

#[cfg(target_arch = "wasm32")]
use core::alloc::{GlobalAlloc, Layout};

use serde::{Deserialize, Serialize};

// ============================================================================
// Memory Management (WASM only)
// ============================================================================

#[cfg(target_arch = "wasm32")]
struct BumpAllocator;

#[cfg(target_arch = "wasm32")]
const HEAP_SIZE: usize = 131072; // 128KB

#[cfg(target_arch = "wasm32")]
static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

#[cfg(target_arch = "wasm32")]
static mut HEAP_POS: usize = 0;

#[cfg(target_arch = "wasm32")]
unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size();
        let align = layout.align();
        let pos = (HEAP_POS + align - 1) & !(align - 1);
        if pos + size > HEAP_SIZE {
            return core::ptr::null_mut();
        }
        HEAP_POS = pos + size;
        HEAP.as_mut_ptr().add(pos)
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // No-op for bump allocator
    }
}

#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// ============================================================================
// Host Function Imports
// ============================================================================

#[cfg(target_arch = "wasm32")]
extern "C" {
    fn host_http_request(req_ptr: i32, req_len: i32) -> i64;
    fn host_get_secret(name_ptr: i32, name_len: i32) -> i64;
}

// ============================================================================
// Memory Exports
// ============================================================================

#[no_mangle]
pub extern "C" fn alloc(size: u32) -> u32 {
    #[cfg(target_arch = "wasm32")]
    {
        let layout = Layout::from_size_align(size as usize, 1).unwrap();
        unsafe { ALLOCATOR.alloc(layout) as u32 }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = size;
        0
    }
}

#[no_mangle]
pub extern "C" fn dealloc(_ptr: u32, _size: u32) {
    // No-op for bump allocator
}

// ============================================================================
// Helper Functions
// ============================================================================

fn return_json(s: &str) -> i64 {
    let ptr = alloc(s.len() as u32);
    if ptr == 0 {
        return 0;
    }
    #[cfg(target_arch = "wasm32")]
    unsafe {
        core::ptr::copy_nonoverlapping(s.as_ptr(), ptr as *mut u8, s.len());
    }
    ((ptr as i64) << 32) | (s.len() as i64)
}

fn return_ok<T: Serialize>(value: &T) -> i64 {
    let json = serde_json::to_string(&Response::Ok(value)).unwrap_or_default();
    return_json(&json)
}

fn return_error(code: &str, message: &str, retryable: bool) -> i64 {
    let err = ErrorResponse {
        code: code.into(),
        message: message.into(),
        retryable,
    };
    let json = serde_json::to_string(&Response::<()>::Err(err)).unwrap_or_default();
    return_json(&json)
}

#[cfg(target_arch = "wasm32")]
fn read_input(ptr: u32, len: u32) -> Option<Vec<u8>> {
    if len == 0 || len > 1024 * 1024 {
        return None;
    }
    let slice = unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) };
    Some(slice.to_vec())
}

#[cfg(target_arch = "wasm32")]
fn read_host_response(packed: i64) -> Option<Vec<u8>> {
    if packed == 0 {
        return None;
    }
    let ptr = (packed >> 32) as u32;
    let len = (packed & 0xFFFFFFFF) as u32;
    if len == 0 || len > 10 * 1024 * 1024 {
        return None;
    }
    let slice = unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) };
    Some(slice.to_vec())
}

#[cfg(target_arch = "wasm32")]
fn get_secret(name: &str) -> Option<String> {
    let packed = unsafe { host_get_secret(name.as_ptr() as i32, name.len() as i32) };
    let bytes = read_host_response(packed)?;
    // Host returns JSON: {"ok": "value"} or {"error": ...}
    let resp: Response<String> = serde_json::from_slice(&bytes).ok()?;
    match resp {
        Response::Ok(val) => Some(val),
        Response::Err(_) => None,
    }
}

#[cfg(target_arch = "wasm32")]
fn http_get(url: &str) -> Result<String, String> {
    let req = HttpRequest {
        method: "GET".into(),
        url: url.into(),
        headers: alloc::vec![],
        body: None,
    };
    let req_json = serde_json::to_string(&req).map_err(|e| format!("serialize: {}", e))?;
    let packed = unsafe { host_http_request(req_json.as_ptr() as i32, req_json.len() as i32) };
    let bytes = read_host_response(packed).ok_or("no response")?;
    let resp: Response<HttpResponse> =
        serde_json::from_slice(&bytes).map_err(|e| format!("parse: {}", e))?;
    match resp {
        Response::Ok(r) => r.body.ok_or_else(|| "empty body".into()),
        Response::Err(e) => Err(e.message),
    }
}

#[cfg(target_arch = "wasm32")]
fn http_post(url: &str, body: &str, content_type: &str) -> Result<String, String> {
    let req = HttpRequest {
        method: "POST".into(),
        url: url.into(),
        headers: alloc::vec![("Content-Type".into(), content_type.into())],
        body: Some(body.into()),
    };
    let req_json = serde_json::to_string(&req).map_err(|e| format!("serialize: {}", e))?;
    let packed = unsafe { host_http_request(req_json.as_ptr() as i32, req_json.len() as i32) };
    let bytes = read_host_response(packed).ok_or("no response")?;
    let resp: Response<HttpResponse> =
        serde_json::from_slice(&bytes).map_err(|e| format!("parse: {}", e))?;
    match resp {
        Response::Ok(r) => r.body.ok_or_else(|| "empty body".into()),
        Response::Err(e) => Err(e.message),
    }
}

// ============================================================================
// Types
// ============================================================================

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum Response<T> {
    Ok(T),
    Err(ErrorResponse),
}

#[derive(Serialize, Deserialize)]
struct ErrorResponse {
    code: String,
    message: String,
    retryable: bool,
}

#[derive(Serialize, Deserialize)]
struct PluginInfo {
    id: String,
    name: String,
    version: String,
    api_version: String,
    icon_url: Option<String>,
    required_secrets: Vec<String>,
    config_schema: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize)]
struct AuthorizeInput {
    state: String,
    redirect_uri: String,
    config: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
struct CallbackInput {
    code: Option<String>,
    state: String,
    config: serde_json::Value,
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Serialize, Deserialize)]
struct TokenSet {
    access_token: String,
    token_type: String,
    expires_at: Option<String>,
    refresh_token: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct ProfileInput {
    access_token: String,
    config: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
struct ExternalProfile {
    account_id: String,
    display_name: Option<String>,
    profile_url: Option<String>,
    avatar_url: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct SyncInput {
    access_token: String,
    config: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
struct SyncRecord {
    collection: String,
    record: serde_json::Value,
    dedup_key: Option<String>,
    /// Whether HappyView should add an attestation signature
    sign: bool,
}

#[derive(Serialize, Deserialize)]
struct HttpRequest {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Option<String>,
}

// Steam API types
#[derive(Deserialize)]
struct SteamOwnedGamesResponse {
    response: SteamOwnedGames,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct SteamOwnedGames {
    game_count: Option<u32>,
    games: Option<Vec<SteamGame>>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct SteamGame {
    appid: u64,
    name: Option<String>,
    playtime_forever: Option<u64>,
    img_icon_url: Option<String>,
    playtime_2weeks: Option<u64>,
}

#[derive(Deserialize)]
struct SteamPlayerSummary {
    response: SteamPlayersResponse,
}

#[derive(Deserialize)]
struct SteamPlayersResponse {
    players: Vec<SteamPlayer>,
}

#[derive(Deserialize)]
struct SteamPlayer {
    steamid: String,
    personaname: Option<String>,
    profileurl: Option<String>,
    avatarfull: Option<String>,
}

// ============================================================================
// Steam OpenID 2.0 Constants
// ============================================================================

const STEAM_OPENID_URL: &str = "https://steamcommunity.com/openid/login";
const STEAM_API_BASE: &str = "https://api.steampowered.com";

// ============================================================================
// Plugin Exports
// ============================================================================

#[no_mangle]
pub extern "C" fn plugin_info() -> i64 {
    let info = PluginInfo {
        id: "steam".into(),
        name: "Steam".into(),
        version: "0.1.0".into(),
        api_version: "1".into(),
        icon_url: Some("https://store.steampowered.com/favicon.ico".into()),
        required_secrets: alloc::vec!["API_KEY".into()],
        config_schema: None,
    };
    return_ok(&info)
}

#[no_mangle]
pub extern "C" fn get_authorize_url(ptr: u32, len: u32) -> i64 {
    #[cfg(target_arch = "wasm32")]
    {
        let bytes = match read_input(ptr, len) {
            Some(b) => b,
            None => return return_error("INVALID_INPUT", "Failed to read input", false),
        };

        let input: AuthorizeInput = match serde_json::from_slice(&bytes) {
            Ok(i) => i,
            Err(e) => return return_error("INVALID_INPUT", &format!("Parse error: {}", e), false),
        };

        // Build OpenID 2.0 authentication URL
        // Steam uses claimed_id and identity as the same value for authentication
        let params = [
            ("openid.ns", "http://specs.openid.net/auth/2.0"),
            ("openid.mode", "checkid_setup"),
            (
                "openid.return_to",
                &format!("{}?state={}", input.redirect_uri, input.state),
            ),
            ("openid.realm", &input.redirect_uri),
            (
                "openid.identity",
                "http://specs.openid.net/auth/2.0/identifier_select",
            ),
            (
                "openid.claimed_id",
                "http://specs.openid.net/auth/2.0/identifier_select",
            ),
        ];

        let query: String = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, urlencod(v)))
            .collect::<Vec<_>>()
            .join("&");

        let url = format!("{}?{}", STEAM_OPENID_URL, query);
        return_ok(&url)
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (ptr, len);
        return_error("NOT_WASM", "Only runs in WASM", false)
    }
}

#[no_mangle]
pub extern "C" fn handle_callback(ptr: u32, len: u32) -> i64 {
    #[cfg(target_arch = "wasm32")]
    {
        let bytes = match read_input(ptr, len) {
            Some(b) => b,
            None => return return_error("INVALID_INPUT", "Failed to read input", false),
        };

        let input: CallbackInput = match serde_json::from_slice(&bytes) {
            Ok(i) => i,
            Err(e) => return return_error("INVALID_INPUT", &format!("Parse error: {}", e), false),
        };

        // Extract Steam ID from openid.claimed_id
        // Format: https://steamcommunity.com/openid/id/76561198012345678
        let claimed_id = input
            .extra
            .get("openid.claimed_id")
            .and_then(|v| v.as_str());

        let steam_id = match claimed_id {
            Some(id) => {
                if let Some(pos) = id.rfind('/') {
                    &id[pos + 1..]
                } else {
                    return return_error("INVALID_RESPONSE", "Invalid claimed_id format", false);
                }
            }
            None => {
                return return_error("INVALID_RESPONSE", "Missing openid.claimed_id", false);
            }
        };

        // Verify the OpenID response with Steam
        // Build verification request by changing mode to check_authentication
        // and POSTing all params back to Steam
        let mut verify_params: Vec<(&str, &str)> = Vec::new();
        verify_params.push(("openid.mode", "check_authentication"));

        // Add all openid.* params from the callback (except mode)
        for (key, value) in &input.extra {
            if key.starts_with("openid.") && key != "openid.mode" {
                if let Some(v) = value.as_str() {
                    verify_params.push((key.as_str(), v));
                }
            }
        }

        // Build POST body
        let verify_body: String = verify_params
            .iter()
            .map(|(k, v)| format!("{}={}", k, urlencod(v)))
            .collect::<Vec<_>>()
            .join("&");

        // POST to Steam for verification
        let verify_result = http_post(
            STEAM_OPENID_URL,
            &verify_body,
            "application/x-www-form-urlencoded",
        );

        match verify_result {
            Ok(response_body) => {
                // Steam returns key-value pairs, one per line
                // We need to find "is_valid:true"
                if !response_body.contains("is_valid:true") {
                    return return_error(
                        "VERIFICATION_FAILED",
                        "Steam OpenID verification failed",
                        false,
                    );
                }
            }
            Err(e) => {
                return return_error(
                    "VERIFICATION_ERROR",
                    &format!("Failed to verify with Steam: {}", e),
                    true,
                );
            }
        }

        // Return the Steam ID as the "access_token"
        // Since Steam uses OpenID 2.0 (not OAuth), there's no real token
        // We store the Steam ID so we can use it with our API key
        let tokens = TokenSet {
            access_token: steam_id.into(),
            token_type: "SteamID".into(),
            expires_at: None,
            refresh_token: None,
        };

        return_ok(&tokens)
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (ptr, len);
        return_error("NOT_WASM", "Only runs in WASM", false)
    }
}

#[no_mangle]
pub extern "C" fn refresh_tokens(ptr: u32, len: u32) -> i64 {
    // Steam doesn't use OAuth tokens - the Steam ID is permanent
    #[cfg(target_arch = "wasm32")]
    {
        let bytes = match read_input(ptr, len) {
            Some(b) => b,
            None => return return_error("INVALID_INPUT", "Failed to read input", false),
        };

        #[derive(Deserialize)]
        struct RefreshInput {
            refresh_token: String,
            #[allow(dead_code)]
            config: serde_json::Value,
        }

        let input: RefreshInput = match serde_json::from_slice(&bytes) {
            Ok(i) => i,
            Err(e) => return return_error("INVALID_INPUT", &format!("Parse error: {}", e), false),
        };

        // Just return the same Steam ID - it doesn't expire
        let tokens = TokenSet {
            access_token: input.refresh_token,
            token_type: "SteamID".into(),
            expires_at: None,
            refresh_token: None,
        };

        return_ok(&tokens)
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (ptr, len);
        return_error("NOT_WASM", "Only runs in WASM", false)
    }
}

#[no_mangle]
pub extern "C" fn get_profile(ptr: u32, len: u32) -> i64 {
    #[cfg(target_arch = "wasm32")]
    {
        let bytes = match read_input(ptr, len) {
            Some(b) => b,
            None => return return_error("INVALID_INPUT", "Failed to read input", false),
        };

        let input: ProfileInput = match serde_json::from_slice(&bytes) {
            Ok(i) => i,
            Err(e) => return return_error("INVALID_INPUT", &format!("Parse error: {}", e), false),
        };

        let api_key = match get_secret("API_KEY") {
            Some(k) => k,
            None => return return_error("MISSING_SECRET", "API_KEY not configured", false),
        };

        let steam_id = &input.access_token;
        let url = format!(
            "{}/ISteamUser/GetPlayerSummaries/v2/?key={}&steamids={}",
            STEAM_API_BASE, api_key, steam_id
        );

        let body = match http_get(&url) {
            Ok(b) => b,
            Err(e) => return return_error("HTTP_ERROR", &e, true),
        };

        let resp: SteamPlayerSummary = match serde_json::from_str(&body) {
            Ok(r) => r,
            Err(e) => {
                return return_error("INVALID_RESPONSE", &format!("Parse error: {}", e), false)
            }
        };

        let player = match resp.response.players.first() {
            Some(p) => p,
            None => return return_error("NOT_FOUND", "Player not found", false),
        };

        let profile = ExternalProfile {
            account_id: player.steamid.clone(),
            display_name: player.personaname.clone(),
            profile_url: player.profileurl.clone(),
            avatar_url: player.avatarfull.clone(),
        };

        return_ok(&profile)
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (ptr, len);
        return_error("NOT_WASM", "Only runs in WASM", false)
    }
}

#[no_mangle]
pub extern "C" fn sync_account(ptr: u32, len: u32) -> i64 {
    #[cfg(target_arch = "wasm32")]
    {
        let bytes = match read_input(ptr, len) {
            Some(b) => b,
            None => return return_error("INVALID_INPUT", "Failed to read input", false),
        };

        let input: SyncInput = match serde_json::from_slice(&bytes) {
            Ok(i) => i,
            Err(e) => return return_error("INVALID_INPUT", &format!("Parse error: {}", e), false),
        };

        let api_key = match get_secret("API_KEY") {
            Some(k) => k,
            None => return return_error("MISSING_SECRET", "API_KEY not configured", false),
        };

        let steam_id = &input.access_token;
        let url = format!(
            "{}/IPlayerService/GetOwnedGames/v1/?key={}&steamid={}&include_appinfo=true&include_played_free_games=true",
            STEAM_API_BASE, api_key, steam_id
        );

        let body = match http_get(&url) {
            Ok(b) => b,
            Err(e) => return return_error("HTTP_ERROR", &e, true),
        };

        let resp: SteamOwnedGamesResponse = match serde_json::from_str(&body) {
            Ok(r) => r,
            Err(e) => {
                return return_error("INVALID_RESPONSE", &format!("Parse error: {}", e), false)
            }
        };

        let games = resp.response.games.unwrap_or_default();

        let mut records: Vec<SyncRecord> = Vec::new();

        for game in games {
            let appid_str = game.appid.to_string();

            // 1. Create actor.game record (ownership)
            // HappyView will resolve game reference and add attestation signature
            let game_record = serde_json::json!({
                "$type": "games.gamesgamesgamesgames.actor.game",
                "game": {
                    "platform": "steam",
                    "externalId": &appid_str,
                },
                "platform": "steam",
                "createdAt": chrono_now(),
            });

            records.push(SyncRecord {
                collection: "games.gamesgamesgamesgames.actor.game".into(),
                record: game_record,
                dedup_key: Some(format!("steam:game:{}", game.appid)),
                sign: true,
            });

            // 2. Create actor.stats record (playtime)
            // HappyView will add attestation signature
            if let Some(playtime) = game.playtime_forever {
                if playtime > 0 {
                    let stats_record = serde_json::json!({
                        "$type": "games.gamesgamesgamesgames.actor.stats",
                        "game": {
                            "platform": "steam",
                            "externalId": &appid_str,
                        },
                        "source": "steam",
                        "playtime": playtime,
                        "createdAt": chrono_now(),
                    });

                    records.push(SyncRecord {
                        collection: "games.gamesgamesgamesgames.actor.stats".into(),
                        record: stats_record,
                        dedup_key: Some(format!("steam:stats:{}", game.appid)),
                        sign: true,
                    });
                }
            }
        }

        return_ok(&records)
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (ptr, len);
        return_error("NOT_WASM", "Only runs in WASM", false)
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

fn urlencod(s: &str) -> String {
    let mut result = String::new();
    for c in s.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => {
                result.push(c);
            }
            _ => {
                for b in c.to_string().as_bytes() {
                    result.push_str(&format!("%{:02X}", b));
                }
            }
        }
    }
    result
}

fn chrono_now() -> String {
    // Simple ISO 8601 timestamp - in real impl would use proper time
    "2024-01-01T00:00:00Z".into()
}
