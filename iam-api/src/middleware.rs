use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::Response,
};

pub async fn cors_middleware(request: Request, next: Next) -> Result<Response, StatusCode> {
    let mut response = next.run(request).await;
    
    let headers = response.headers_mut();
    headers.insert("Access-Control-Allow-Origin", "*".parse().unwrap());
    headers.insert("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS".parse().unwrap());
    headers.insert("Access-Control-Allow-Headers", "Content-Type, Authorization".parse().unwrap());
    
    Ok(response)
}

pub async fn logging_middleware(request: Request, next: Next) -> Result<Response, StatusCode> {
    let method = request.method().clone();
    let uri = request.uri().clone();
    
    tracing::info!("Request: {} {}", method, uri);
    
    let response = next.run(request).await;
    
    tracing::info!("Response: {} {} -> {}", method, uri, response.status());
    
    Ok(response)
}