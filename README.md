# HPP Cloud Infrastructure

A Rust-based cloud infrastructure project that provides AWS S3, IAM, and Bedrock compatible APIs, meant to support augmenting Hetzner Cloud (thus H++ name).

## Project Goals

- **Cloud Abstraction**: Create a cloud platform on top of Hetzner Cloud infrastructure
- **AWS Compatibility**: Provide S3, IAM, and Bedrock APIs that are compatible with existing AWS tools and SDKs
- **AI/ML Integration**: Offer vector database and embedding services compatible with AWS Bedrock
- **Cost Optimization**: Leverage Hetzner's competitive pricing while maintaining AWS API compatibility
- **Security**: Implement proper IAM-based authorization for all operations
- **Scalability**: Design a modular architecture that can be extended with additional AWS-compatible services

## Architecture Overview

```
hpp-core/
├── s3-core/          # S3 business logic + Hetzner Object Storage integration
├── s3-api/           # S3 HTTP server (port 8989)
├── iam-core/         # IAM business logic + policy evaluation engine
├── iam-api/          # IAM HTTP server (port 8988)
├── bedrock-core/     # Vector database + embedding engine
├── bedrock-api/      # Bedrock HTTP server (AWS Bedrock compatible)
└── shared/           # Common error types and utilities
```

### Service Flow
```
AWS S3 Client → S3 API (8989) → IAM API (8988) → Hetzner Object Storage
                    ↓                ↓
               [Authorization]  [Policy Check]

AWS Bedrock Client → Bedrock API → Vector Database + Embedding Engine
                         ↓              ↓
                    [Document CRUD]  [Similarity Search]
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

### Bedrock Vector Database Service
- **AWS Bedrock Compatibility**: Full compatibility with AWS Bedrock embedding and text generation APIs
- **Vector Database**: High-performance vector storage and similarity search
- **Multiple Storage Backends**: In-memory and S3-backed persistence options
- **Embedding Models**: Support for AWS Titan, Cohere, and HuggingFace models
- **Similarity Metrics**: Cosine similarity, Euclidean distance, and dot product
- **Document Management**: CRUD operations for vector documents with metadata
- **Model Registry**: AWS-to-HuggingFace model mapping with dimension compatibility
- **Comprehensive Testing**: 62+ tests covering all functionality

#### Supported Models
- **AWS Titan**: `amazon.titan-embed-text-v1` (1536 dimensions), `amazon.titan-embed-text-v2:0` (1024 dimensions)
- **Cohere**: `cohere.embed-english-v3` (1024 dimensions), `cohere.embed-multilingual-v3` (1024 dimensions)
- **HuggingFace Models**: Automatic mapping to equivalent open-source models with dimension projection

#### Vector Database Features
- **Storage Options**: In-memory for development, S3-backed for production
- **Search Capabilities**: Similarity search with configurable thresholds and limits
- **Metadata Filtering**: Filter search results by custom metadata fields
- **Pagination**: Support for large document collections with limit/offset
- **Multiple Similarity Metrics**: Choose between cosine, euclidean, or dot product similarity

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

# Bedrock Service Configuration
USE_HUGGINGFACE_EMBEDDINGS=true  # Enable HuggingFace model integration
HF_MODELS_TO_LOAD=sentence-transformers/all-MiniLM-L6-v2,sentence-transformers/all-mpnet-base-v2
HF_CACHE_DIR=./hf_cache  # Directory to cache downloaded models
BEDROCK_STORAGE_BACKEND=s3  # Options: memory, s3
BEDROCK_S3_BUCKET=bedrock-vectors  # S3 bucket for vector storage
```

### Running the Services

```bash
# Start IAM service (port 8988)
cargo run --package iam-api

# Start S3 service (port 8989)
cargo run --package s3-api

# Start Bedrock service (AWS Bedrock compatible)
cargo run --package bedrock-api
```

### Running All Services with Docker
```bash
# Start MinIO (S3-compatible storage) + all services
docker compose up -d

# Copy environment configuration
cp .env.example .env
source .env

# Run all services in parallel
cargo run --package iam-api &
cargo run --package s3-api &
cargo run --package bedrock-api &
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

## Bedrock API Usage

The Bedrock API provides AWS-compatible embedding and vector database functionality.

### Start Bedrock Service
```bash
# Start the Bedrock service
cargo run --package bedrock-api

# The service will be available at http://localhost:3000 (default)
```

### Creating Embeddings

Create embeddings using AWS Bedrock-compatible models:

```bash
# Create embedding using AWS Titan model
curl -X POST http://localhost:3000/embeddings \
  -H "Content-Type: application/json" \
  -d '{
    "model_id": "amazon.titan-embed-text-v1",
    "input_text": "Machine learning is revolutionizing technology"
  }'

# Response includes embedding vector and token count
# {
#   "embedding": [0.1234, -0.5678, ...],  // 1536 dimensions for Titan v1
#   "input_token_count": 8
# }
```

### Document Management

Create, retrieve, update, and delete vector documents:

```bash
# Create a document with automatic embedding generation
curl -X POST http://localhost:3000/documents \
  -H "Content-Type: application/json" \
  -d '{
    "id": "tech-doc-1",
    "content": "Artificial intelligence and machine learning are transforming industries",
    "metadata": {
      "category": "technology",
      "topic": "AI"
    }
  }'

# List all documents
curl http://localhost:3000/documents

# Get a specific document
curl http://localhost:3000/documents/tech-doc-1

# Update a document
curl -X PUT http://localhost:3000/documents/tech-doc-1 \
  -H "Content-Type: application/json" \
  -d '{
    "content": "Updated content about AI and ML",
    "metadata": {
      "category": "technology",
      "topic": "AI",
      "updated": "2024-01-01"
    }
  }'

# Delete a document
curl -X DELETE http://localhost:3000/documents/tech-doc-1
```

### Vector Search

Perform similarity search on your document collection:

```bash
# Search for similar documents
curl -X POST http://localhost:3000/documents/search \
  -H "Content-Type: application/json" \
  -d '{
    "query": "artificial intelligence",
    "limit": 5,
    "similarity_threshold": 0.7,
    "metadata_filter": {
      "category": "technology"
    }
  }'

# Response includes ranked results with similarity scores
# {
#   "results": [
#     {
#       "document": {
#         "id": "tech-doc-1",
#         "content": "AI content...",
#         "metadata": {...},
#         "created_at": "2024-01-01T00:00:00Z"
#       },
#       "similarity_score": 0.95
#     }
#   ],
#   "total_count": 1
# }
```

### Model Invocation (AWS Bedrock Compatible)

Invoke models directly using the AWS Bedrock API format:

```bash
# Invoke embedding model
curl -X POST http://localhost:3000/model/amazon.titan-embed-text-v1/invoke \
  -H "Content-Type: application/json" \
  -d '{
    "inputText": "Text to embed"
  }'

# Invoke text generation model (if supported)
curl -X POST http://localhost:3000/model/anthropic.claude-v2/invoke \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "What is machine learning?",
    "max_tokens_to_sample": 100
  }'
```

### Using with AWS SDK

You can use the AWS SDK with the Bedrock service by pointing it to your local endpoint:

```python
import boto3

# Configure boto3 client for local Bedrock service
bedrock = boto3.client(
    'bedrock-runtime',
    endpoint_url='http://localhost:3000',
    region_name='us-east-1',
    aws_access_key_id='dummy',  # Not validated in local mode
    aws_secret_access_key='dummy'
)

# Create embeddings
response = bedrock.invoke_model(
    modelId='amazon.titan-embed-text-v1',
    contentType='application/json',
    accept='application/json',
    body=json.dumps({
        'inputText': 'Machine learning is transforming technology'
    })
)

result = json.loads(response['body'].read())
embedding = result['embedding']
print(f"Generated embedding with {len(embedding)} dimensions")
```

### Configuration Options

Configure the Bedrock service using environment variables:

```bash
# Enable HuggingFace model integration (requires internet for model downloads)
export USE_HUGGINGFACE_EMBEDDINGS=true
export HF_MODELS_TO_LOAD="sentence-transformers/all-MiniLM-L6-v2,sentence-transformers/all-mpnet-base-v2"
export HF_CACHE_DIR="./hf_cache"

# Storage backend configuration
export BEDROCK_STORAGE_BACKEND=s3  # Options: memory, s3
export BEDROCK_S3_BUCKET=bedrock-vectors

# Service configuration
export BEDROCK_PORT=3000
export BEDROCK_HOST=0.0.0.0
```

### Testing the Complete Pipeline

Test the entire Bedrock pipeline with a complete workflow:

```bash
#!/bin/bash
# Complete Bedrock testing script

echo "1. Creating embedding..."
curl -X POST http://localhost:3000/embeddings \
  -H "Content-Type: application/json" \
  -d '{"model_id": "amazon.titan-embed-text-v1", "input_text": "AI and machine learning"}' | jq .

echo -e "\n2. Creating documents..."
curl -X POST http://localhost:3000/documents \
  -H "Content-Type: application/json" \
  -d '{"id": "doc1", "content": "Artificial intelligence is changing the world", "metadata": {"category": "AI"}}' | jq .

curl -X POST http://localhost:3000/documents \
  -H "Content-Type: application/json" \
  -d '{"id": "doc2", "content": "Machine learning algorithms for data science", "metadata": {"category": "ML"}}' | jq .

echo -e "\n3. Listing documents..."
curl http://localhost:3000/documents | jq .

echo -e "\n4. Searching for similar documents..."
curl -X POST http://localhost:3000/documents/search \
  -H "Content-Type: application/json" \
  -d '{"query": "AI and ML technologies", "limit": 5}' | jq .

echo -e "\n5. Getting specific document..."
curl http://localhost:3000/documents/doc1 | jq .

echo -e "\nBedrock API test complete!"
```

Make the script executable and run it:
```bash
chmod +x test-bedrock.sh
./test-bedrock.sh
```

## Testing

The project includes comprehensive test suites for all components.

### Running All Tests
```bash
# Run all tests across the workspace
cargo test --workspace

# Run tests for specific packages
cargo test --package bedrock-core
cargo test --package bedrock-api
cargo test --package iam-core
cargo test --package s3-core
```

### Test Coverage

#### Bedrock Core (62 tests)
- **Unit Tests**: 52 tests covering:
  - Embedding engines (in-memory and HuggingFace mock)
  - Vector stores with different similarity metrics (Cosine, Euclidean, DotProduct)
  - Model mapping and AWS-HuggingFace compatibility
  - Service layer functionality
  - Error handling and edge cases

- **Integration Tests**: 10 comprehensive tests covering:
  - Complete BedrockService workflow
  - Multi-document operations and search
  - Large document set handling (50+ documents)
  - Concurrent operations
  - Different similarity metrics validation
  - Trait compliance testing

#### Test Features
- **Mock HuggingFace Implementation**: Sophisticated deterministic embedding generation
- **AWS Model Compatibility**: Full testing of AWS-to-HuggingFace model mappings
- **Similarity Testing**: Validates all similarity metrics work correctly (-1 to 1 range)
- **Edge Case Coverage**: Empty content, special characters, very long documents
- **Performance Testing**: Large dataset operations and concurrent access

### Running Specific Test Suites
```bash
# Run only unit tests
cargo test --lib --package bedrock-core

# Run only integration tests
cargo test integration_tests --package bedrock-core

# Run HuggingFace-specific tests
cargo test huggingface --package bedrock-core

# Run with output for debugging
cargo test -- --nocapture

# Run ignored tests (require internet connection)
cargo test -- --ignored
```

### Test Environment Setup
```bash
# For HuggingFace integration tests (requires internet)
export USE_HUGGINGFACE_EMBEDDINGS=true
export HF_CACHE_DIR=./test_cache

# For S3 backend tests
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_ENDPOINT=http://localhost:9000
export AWS_REGION=us-east-1

# Run MinIO for S3 testing
docker compose up -d minio
```

### Performance Benchmarks
```bash
# Run benchmark tests (in release mode)
cargo test --release benchmark --package bedrock-core -- --ignored

# Example benchmark results:
# - 10,000 dimension projections: <1ms
# - 1,000 similarity calculations: <10ms
# - Large dataset search (50 docs): <5ms
```

### Continuous Integration
The test suite is designed to run in CI environments:
- All tests pass without external dependencies
- Mock implementations for ML models
- Deterministic test results
- No network requirements for core tests

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

[MIT License](LICENSE)