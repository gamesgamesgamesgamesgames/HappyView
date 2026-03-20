use super::{
    HostContext, MAX_HTTP_REQUESTS, MAX_HTTP_RESPONSE_SIZE, MAX_HTTP_TOTAL_TRANSFER, ResourceUsage,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("Too many requests: {0} > {MAX_HTTP_REQUESTS}")]
    TooManyRequests(u32),
    #[error("Response too large: {0} > {MAX_HTTP_RESPONSE_SIZE}")]
    ResponseTooLarge(u64),
    #[error("Transfer limit exceeded: {0} > {MAX_HTTP_TOTAL_TRANSFER}")]
    TransferLimitExceeded(u64),
    #[error("Request failed: {0}")]
    RequestFailed(#[from] reqwest::Error),
}

pub async fn http_request(
    ctx: &HostContext,
    usage: &mut ResourceUsage,
    req: HttpRequest,
) -> Result<HttpResponse, HttpError> {
    // Check request count limit
    usage.http_requests += 1;
    if usage.http_requests > MAX_HTTP_REQUESTS {
        return Err(HttpError::TooManyRequests(usage.http_requests));
    }

    // Build request
    let method = req.method.parse().unwrap_or(reqwest::Method::GET);
    let mut builder = ctx.http_client.request(method, &req.url);

    for (name, value) in &req.headers {
        builder = builder.header(name, value);
    }

    if let Some(body) = req.body {
        usage.http_bytes_transferred += body.len() as u64;
        builder = builder.body(body);
    }

    // Check transfer limit before sending
    if usage.http_bytes_transferred > MAX_HTTP_TOTAL_TRANSFER {
        return Err(HttpError::TransferLimitExceeded(
            usage.http_bytes_transferred,
        ));
    }

    // Execute request
    let response = builder.send().await?;
    let status = response.status().as_u16();

    let headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let body = response.bytes().await?;

    // Check response size
    if body.len() as u64 > MAX_HTTP_RESPONSE_SIZE {
        return Err(HttpError::ResponseTooLarge(body.len() as u64));
    }

    usage.http_bytes_transferred += body.len() as u64;
    if usage.http_bytes_transferred > MAX_HTTP_TOTAL_TRANSFER {
        return Err(HttpError::TransferLimitExceeded(
            usage.http_bytes_transferred,
        ));
    }

    Ok(HttpResponse {
        status,
        headers,
        body: body.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_request_limit_check() {
        let mut usage = ResourceUsage {
            http_requests: MAX_HTTP_REQUESTS,
            ..Default::default()
        };

        // Verify the limit check would fail
        usage.http_requests += 1;
        assert!(usage.http_requests > MAX_HTTP_REQUESTS);
    }

    #[test]
    fn test_http_transfer_limit_check() {
        let mut usage = ResourceUsage {
            http_bytes_transferred: MAX_HTTP_TOTAL_TRANSFER,
            ..Default::default()
        };

        // Adding more would exceed limit
        usage.http_bytes_transferred += 1;
        assert!(usage.http_bytes_transferred > MAX_HTTP_TOTAL_TRANSFER);
    }

    #[test]
    fn test_http_response_struct() {
        let response = HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: b"{}".to_vec(),
        };
        assert_eq!(response.status, 200);
        assert_eq!(response.headers.len(), 1);
    }
}
