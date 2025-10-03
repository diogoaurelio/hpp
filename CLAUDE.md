# Claude Code Guidelines for HPP Core Project

## Coding Standards

### Naming Conventions

- **Never name trait concrete implementations with "*Impl" suffix**
  - ❌ Bad: `S3ServiceImpl`, `UserServiceImpl`, `PaymentServiceImpl`
  - ✅ Good: `ProxyS3Service`, `LocalUserService`, `StripePaymentService`, `InMemoryS3Service`
  - Use descriptive names that indicate the specific implementation type or purpose (Proxy, Default, Local, InMemory, etc.)

### Architecture Patterns

- Use trait-based dependency injection for services
- Separate models/DTOs from business logic
- Keep handlers thin - delegate to service layer
- Use proper error handling with `anyhow::Result`

#### Proxy Pattern for Storage Services

- `ProxyS3Service` acts as a proxy between API handlers and storage backends
- Supports multiple S3-compatible backends (AWS S3, Hetzner Object Storage, MinIO)
- Handles response format conversion (XML/JSON) at the service layer
- Delegates actual storage operations to repository implementations

### Testing

- Write comprehensive unit tests for service layers
- Use mockall for mocking dependencies
- Test both success and error scenarios
- Validate response formats (XML/JSON) completely

### Project Structure

- `shared/` - Common models, traits, and repository patterns
- `*-core/` - Business logic and service layers
- `*-api/` - HTTP handlers and API layers

## Commands

- **Lint**: `cargo clippy --all-targets --all-features`
- **Test**: `cargo test --workspace`
- **Build**: `cargo build --workspace`

## Notes

This project implements an S3-compatible API with IAM authentication for HPP (Hetzner++) cloud infrastructure.