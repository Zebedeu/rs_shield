use aws_credential_types::Credentials;

/// Verifies the S3 connection by trying to access the bucket's metadata (HeadBucket).
/// Returns Ok(message) on success, or Err(error_message) on failure.
pub async fn verify_s3_connection(
    bucket: &str,
    region: &str,
    endpoint: &str,
    access_key: &str,
    secret_key: &str,
) -> Result<String, String> {
    // A região só é obrigatória sem endpoint personalizado (AWS); com
    // endpoint S3-compatível usa-se `DEFAULT_S3_COMPAT_REGION` se vazia.
    if bucket.is_empty()
        || access_key.is_empty()
        || secret_key.is_empty()
        || (region.trim().is_empty() && endpoint.trim().is_empty())
    {
        return Err("Required fields (Bucket, Region, Keys) not filled.".to_string());
    }

    // Fail-closed TLS: http só para loopback (MinIO local). Qualquer host
    // remoto em http transportaria `HeadBucket` + credenciais em claro.
    let ep = endpoint.trim();
    if !ep.is_empty() {
        let lower = ep.to_lowercase();
        let is_http = lower.starts_with("http://");
        // Exact host comparison on the parsed URL (not substring matching:
        // `http://localhost.evil.com` must not count as loopback).
        let is_loopback = crate::storage::is_loopback_endpoint(ep);
        if is_http && !is_loopback {
            return Err(
                "Insecure endpoint: use https:// for non-local S3 endpoints (credentials would go in cleartext over http)."
                    .to_string(),
            );
        }
        if !lower.starts_with("https://") && !lower.starts_with("http://") {
            return Err(
                "Endpoint must start with https:// (or http://localhost for tests).".to_string(),
            );
        }
    }

    let credentials = Credentials::new(access_key, secret_key, None, None, "manual_test");

    // Mesmo cliente do backend de storage: path-style com endpoint
    // personalizado, checksums só quando exigidos, região por omissão.
    let client = crate::storage::build_s3_client(
        Some(region.to_string()),
        Some(endpoint.to_string()),
        credentials,
    )
    .await;

    // Tries to get bucket metadata to validate access and existence
    match client.head_bucket().bucket(bucket).send().await {
        Ok(_) => Ok(format!(
            "✅ Connection established! Bucket '{}' accessible.",
            bucket
        )),
        Err(e) => {
            let err_msg = e.to_string();
            // Simplifies the error message for the user
            Err(format!("❌ Connection failed: {}", err_msg))
        }
    }
}
