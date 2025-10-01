# HPP Cloud Infrastructure

A Rust-based cloud infrastructure project that provides AWS S3 and IAM compatible APIs, meant to support augmenting Hetzner Cloud (thus H++ name).

## Project Goals

- **Cloud Abstraction**: Create a cloud platform on top of Hetzner Cloud infrastructure
- **AWS Compatibility**: Provide S3 and IAM APIs that are compatible with existing AWS tools and SDKs
- **Cost Optimization**: Leverage Hetzner's competitive pricing while maintaining AWS API compatibility
- **Security**: Implement proper IAM-based authorization for all S3 operations
- **Scalability**: Design a modular architecture that can be extended with additional AWS-compatible services

## Architecture Overview

```
hpp-iam/
├── s3-core/          # S3 business logic + Hetzner Object Storage integration
├── s3-api/           # S3 HTTP server (port 8080)
├── iam-core/         # IAM business logic + policy evaluation engine  
├── iam-api/          # IAM HTTP server (port 8081)
└── shared/           # Common error types and utilities
```

### Service Flow
```
AWS S3 Client → S3 API (8080) → IAM API (8081) → Hetzner Object Storage
                    ↓                ↓
               [Authorization]  [Policy Check]
```

## Key Features

### S3 Proxy Service
- **AWS S3-compatible API**: Full compatibility with AWS S3 REST API
- **S3 Integration**: Seamless forwarding to a S3 API compatible Object Storage (AWS/Hetzner/etc)
- **Core Operations**: GET/PUT/DELETE objects, list buckets/objects
- **AWS4 Signature Support**: Handles AWS signature verification (v4)
- **XML Responses**: Proper AWS S3-compatible XML response format

### IAM Service
- **User Management**: Create, read, update, delete IAM users
- **Access Key Management**: Generate and manage AWS-compatible access keys
- **Policy Engine**: Evaluate IAM policies for authorization decisions
- **Built-in Policies**: Pre-configured S3 access policies (FullAccess, ReadOnly)
- **JSON API**: AWS IAM-compatible JSON responses

### Security & Authorization
- **Request Validation**: Parse and validate AWS4-HMAC-SHA256 signatures
- **Policy Evaluation**: Fine-grained access control using IAM policies
- **Access Key Authentication**: Secure access key and secret key validation
- **Resource-based Permissions**: Support for bucket and object-level permissions

## Next Steps

### Immediate (Phase 1)
1. **Service Integration**: Connect S3 API auth middleware to IAM `/authorize` endpoint
2. **Signature Validation**: Complete AWS4-HMAC-SHA256 signature verification implementation
3. **Error Handling**: Add comprehensive AWS-compatible error responses
4. **Testing**: Create integration tests for S3 ↔ IAM communication

### Short Term (Phase 2)
1. **Persistence Layer**: Replace in-memory storage with database (PostgreSQL/SQLite)
2. **Configuration Management**: Add environment-based configuration
3. **Logging & Monitoring**: Implement structured logging and metrics
4. **Docker Support**: Add Dockerfile and docker-compose for easy deployment

### Medium Term (Phase 3)
1. **Advanced IAM Features**: Roles, groups, and cross-account access
2. **S3 Advanced Features**: Versioning, lifecycle policies, CORS
3. **Performance Optimization**: Connection pooling, caching, async improvements
4. **Security Hardening**: Rate limiting, audit logging, encryption at rest

### Long Term (Phase 4)
1. **Additional Services**: EC2-compatible compute API, VPC networking
2. **Multi-tenancy**: Support for multiple AWS-like accounts
3. **High Availability**: Clustering and failover capabilities
4. **Compliance**: SOC2, GDPR compliance features

## Development

### Prerequisites
- Rust 1.70+ 
- Hetzner Object Storage credentials

### Environment Variables
```bash
# Hetzner Object Storage
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key  
AWS_ENDPOINT=https://fsn1.your-objectstorage.com
AWS_REGION=eu-central
```

### Running the Services

```bash
# Start IAM service (port 8988)
cargo run --package iam-api

# Start S3 service (port 8989)  
cargo run --package s3-api
```

### Local dev - API Usage

#### Step 1: Create IAM User and Access Keys

First, start both services:
```bash
# Terminal 1 - Start IAM service (port 8988)
cargo run --package iam-api

# Terminal 2 - Start S3 service (port 8989)
cargo run --package s3-api
```

Create an IAM user:
```bash
curl -X POST http://localhost:8988/ \
  -H "Content-Type: application/json" \
  -d '{"user_name": "hpp-user", "path": "/"}'
```

Create access keys for the user and extract credentials:
```bash
# Create access keys and save the response
RESPONSE=$(curl -s -X POST http://localhost:8988/users/hpp-user/access-keys)

# Extract access key and secret using jq
ACCESS_KEY=$(echo "$RESPONSE" | jq -r '.CreateAccessKeyResponse.CreateAccessKeyResult.AccessKey.access_key_id')
SECRET_KEY=$(echo "$RESPONSE" | jq -r '.CreateAccessKeyResponse.CreateAccessKeyResult.AccessKey.secret_access_key')

echo "Generated credentials:"
echo "Access Key: $ACCESS_KEY"
echo "Secret Key: $SECRET_KEY"
```

Alternative one-liner to extract both values:
```bash
curl -s -X POST http://localhost:8988/users/hpp-user/access-keys | jq -r '.CreateAccessKeyResponse.CreateAccessKeyResult.AccessKey | "Access Key: \(.access_key_id)\nSecret Key: \(.secret_access_key)"'
```

#### Step 2: Attach S3 Permissions Policy

Attach the S3FullAccess policy to allow S3 operations:
```bash
curl -X POST http://localhost:8988/users/hpp-user/attached-policies \
  -H "Content-Type: application/json" \
  -d '{"policy_arn": "arn:aws:iam::aws:policy/AmazonS3FullAccess"}'
```

Alternative: Attach ReadOnly policy for limited access:
```bash
curl -X POST http://localhost:8988/users/hpp-user/attached-policies \
  -H "Content-Type: application/json" \
  -d '{"policy_arn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"}'
```

#### Step 3: Configure AWS CLI Profile

Configure your AWS CLI profile with the extracted credentials:
```bash
# Using the variables from Step 1
aws configure set aws_access_key_id "$ACCESS_KEY" --profile hpp
aws configure set aws_secret_access_key "$SECRET_KEY" --profile hpp
aws configure set region eu-central-1 --profile hpp
aws configure set output json --profile hpp

# Verify the configuration
aws configure list --profile hpp
```

**Complete automated setup script:**
```bash
#!/bin/bash
# Complete HPP user setup script

echo "Creating IAM user..."
curl -s -X POST http://localhost:8988/ \
  -H "Content-Type: application/json" \
  -d '{"user_name": "hpp-user", "path": "/"}' | jq .

echo "Creating access keys..."
RESPONSE=$(curl -s -X POST http://localhost:8988/users/hpp-user/access-keys)
ACCESS_KEY=$(echo "$RESPONSE" | jq -r '.CreateAccessKeyResponse.CreateAccessKeyResult.AccessKey.access_key_id')
SECRET_KEY=$(echo "$RESPONSE" | jq -r '.CreateAccessKeyResponse.CreateAccessKeyResult.AccessKey.secret_access_key')

echo "Generated credentials:"
echo "Access Key: $ACCESS_KEY"
echo "Secret Key: $SECRET_KEY"

echo "Attaching S3FullAccess policy..."
curl -s -X POST http://localhost:8988/users/hpp-user/attached-policies \
  -H "Content-Type: application/json" \
  -d '{"policy_arn": "arn:aws:iam::aws:policy/AmazonS3FullAccess"}' | jq .

echo "Configuring AWS CLI profile..."
aws configure set aws_access_key_id "$ACCESS_KEY" --profile hpp
aws configure set aws_secret_access_key "$SECRET_KEY" --profile hpp
aws configure set region eu-central-1 --profile hpp
aws configure set output json --profile hpp

echo "Setup complete! Test with:"
echo "aws s3 ls --profile hpp --endpoint-url http://localhost:8989"
```

**Quick setup script:**
Use the provided setup script:
```bash
./bin/setup-hpp-user.sh
```

This script will automatically:
- Create the IAM user
- Generate and extract access keys using jq
- Attach the S3FullAccess policy
- Configure your AWS CLI profile
- Test the authorization

Make sure the script is executable:
```bash
chmod +x bin/setup-hpp-user.sh
```

#### Step 4: Test S3 Operations

```bash
# List all buckets
aws s3 ls --profile hpp --endpoint-url http://localhost:8989

# Create a bucket
aws s3 mb s3://my-bucket --profile hpp --endpoint-url http://localhost:8989

# List objects in a bucket
aws s3 ls s3://my-bucket --profile hpp --endpoint-url http://localhost:8989

# Upload a file
echo "Hello HPP!" > test.txt
aws s3 cp test.txt s3://my-bucket/test.txt --profile hpp --endpoint-url http://localhost:8989

# Download a file
aws s3 cp s3://my-bucket/test.txt downloaded.txt --profile hpp --endpoint-url http://localhost:8989

# Delete a file
aws s3 rm s3://my-bucket/test.txt --profile hpp --endpoint-url http://localhost:8989
```

#### Troubleshooting

If you get a 403 Forbidden error:
1. Verify the IAM user exists: `curl http://localhost:8988/users/hpp-user`
2. Check the access keys: `curl http://localhost:8988/users/hpp-user/access-keys`
3. Verify authorization works:
   ```bash
   curl -X POST http://localhost:8988/authorize \
     -H "Content-Type: application/json" \
     -d '{"access_key_id": "YOUR_ACCESS_KEY", "action": "s3:ListBucket", "resource": "arn:aws:s3:::my-bucket", "context": {}}'
   ```
4. Make sure both IAM and S3 services are running
5. Check the server logs for detailed error messages

## Testing with MinIO

For local development and testing, you can use MinIO as a local S3-compatible backend:

### Setup MinIO
```bash
# Start MinIO services
docker compose up -d

# Copy environment variables for MinIO
cp .env.example .env
source .env

# Start the S3 API
cargo run --package s3-api
```

### MinIO Web Console
Access MinIO console at: http://localhost:9001
- Username: `admin`
- Password: `admin123`

### AWS CLI Testing with MinIO
```bash
# Configure AWS CLI profile for MinIO
aws configure set aws_access_key_id admin --profile hpp-test
aws configure set aws_secret_access_key admin123 --profile hpp-test
aws configure set region us-east-1 --profile hpp-test
aws configure set output json --profile hpp-test

# Test direct MinIO connection
aws s3 ls --profile hpp-test --endpoint-url http://localhost:9000

# Test through your S3 API proxy
aws s3 ls --profile hpp-test --endpoint-url http://localhost:8989

# Create and test with buckets
aws s3 mb s3://my-test-bucket --profile hpp-test --endpoint-url http://localhost:9000
aws s3 ls --profile hpp-test --endpoint-url http://localhost:8989

# Upload and download files
echo "Hello World" > test.txt
aws s3 cp test.txt s3://test-bucket/test.txt --profile hpp-test --endpoint-url http://localhost:9000
aws s3 cp s3://test-bucket/test.txt downloaded.txt --profile hpp-test --endpoint-url http://localhost:8989
```

### curl Testing
```bash
# List buckets
curl -v http://localhost:8989/

# List objects in bucket
curl -v http://localhost:8989/test-bucket

# Get object
curl -v http://localhost:8989/test-bucket/test.txt
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

[MIT License](LICENSE)