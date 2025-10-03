#!/bin/bash
# HPP User Setup Script
# This script creates an IAM user, generates access keys, attaches S3 policies,
# and configures the AWS CLI profile automatically.

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
IAM_URL="http://localhost:8988"
USER_NAME="hpp-user"
PROFILE_NAME="hpp"

echo -e "${GREEN}🚀 HPP User Setup Script${NC}"
echo "=================================="

# Check dependencies
command -v curl >/dev/null 2>&1 || { echo -e "${RED}❌ curl is required but not installed.${NC}" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo -e "${RED}❌ jq is required but not installed.${NC}" >&2; exit 1; }
command -v aws >/dev/null 2>&1 || { echo -e "${RED}❌ AWS CLI is required but not installed.${NC}" >&2; exit 1; }

# Check if IAM service is running
if ! curl -s "$IAM_URL/health" >/dev/null 2>&1; then
    echo -e "${RED}❌ IAM service is not running at $IAM_URL${NC}"
    echo "Please start the IAM service with: cargo run --package iam-api"
    exit 1
fi

echo -e "${GREEN}✅ All dependencies found${NC}"

# Step 1: Create IAM user
echo -e "\n${YELLOW}📝 Creating IAM user '$USER_NAME'...${NC}"
USER_RESPONSE=$(curl -s -X POST "$IAM_URL/" \
  -H "Content-Type: application/json" \
  -d "{\"user_name\": \"$USER_NAME\", \"path\": \"/\"}")

if echo "$USER_RESPONSE" | jq -e '.CreateUserResponse' >/dev/null 2>&1; then
    echo -e "${GREEN}✅ User created successfully${NC}"
else
    echo -e "${YELLOW}⚠️  User may already exist, continuing...${NC}"
fi

# Step 2: Create access keys
echo -e "\n${YELLOW}🔑 Creating access keys...${NC}"
KEYS_RESPONSE=$(curl -s -X POST "$IAM_URL/users/$USER_NAME/access-keys")

if ! echo "$KEYS_RESPONSE" | jq -e '.CreateAccessKeyResponse' >/dev/null 2>&1; then
    echo -e "${RED}❌ Failed to create access keys${NC}"
    echo "$KEYS_RESPONSE"
    exit 1
fi

ACCESS_KEY=$(echo "$KEYS_RESPONSE" | jq -r '.CreateAccessKeyResponse.CreateAccessKeyResult.AccessKey.access_key_id')
SECRET_KEY=$(echo "$KEYS_RESPONSE" | jq -r '.CreateAccessKeyResponse.CreateAccessKeyResult.AccessKey.secret_access_key')

echo -e "${GREEN}✅ Access keys created:${NC}"
echo "   Access Key: $ACCESS_KEY"
echo "   Secret Key: ${SECRET_KEY:0:8}..."

# Step 3: Attach S3FullAccess policy
echo -e "\n${YELLOW}🔐 Attaching S3FullAccess policy...${NC}"
POLICY_RESPONSE=$(curl -s -X POST "$IAM_URL/users/$USER_NAME/attached-policies" \
  -H "Content-Type: application/json" \
  -d '{"policy_arn": "arn:aws:iam::aws:policy/AmazonS3FullAccess"}')

if echo "$POLICY_RESPONSE" | jq -e '.AttachUserPolicyResponse' >/dev/null 2>&1; then
    echo -e "${GREEN}✅ S3FullAccess policy attached${NC}"
else
    echo -e "${RED}❌ Failed to attach policy${NC}"
    echo "$POLICY_RESPONSE"
    exit 1
fi

# Step 4: Configure AWS CLI profile
echo -e "\n${YELLOW}⚙️  Configuring AWS CLI profile '$PROFILE_NAME'...${NC}"
aws configure set aws_access_key_id "$ACCESS_KEY" --profile "$PROFILE_NAME"
aws configure set aws_secret_access_key "$SECRET_KEY" --profile "$PROFILE_NAME"
aws configure set region eu-central-1 --profile "$PROFILE_NAME"
aws configure set output json --profile "$PROFILE_NAME"

echo -e "${GREEN}✅ AWS CLI profile configured${NC}"

# Step 5: Test authorization
echo -e "\n${YELLOW}🧪 Testing authorization...${NC}"
AUTH_TEST=$(curl -s -X POST "$IAM_URL/authorize" \
  -H "Content-Type: application/json" \
  -d "{\"access_key_id\": \"$ACCESS_KEY\", \"action\": \"s3:ListBucket\", \"resource\": \"arn:aws:s3:::test-bucket\", \"context\": {}}")

if echo "$AUTH_TEST" | jq -e '.allowed == true' >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Authorization test passed${NC}"
else
    echo -e "${RED}❌ Authorization test failed${NC}"
    echo "$AUTH_TEST"
    exit 1
fi

# Summary
echo -e "\n${GREEN}🎉 Setup completed successfully!${NC}"
echo "=================================="
echo "Profile name: $PROFILE_NAME"
echo "Access Key: $ACCESS_KEY"
echo "Secret Key: ${SECRET_KEY:0:8}..."
echo ""
echo "Test your setup:"
echo "  aws s3 ls --profile $PROFILE_NAME --endpoint-url http://localhost:8989"
echo ""
echo "Create a bucket:"
echo "  aws s3 mb s3://my-bucket --profile $PROFILE_NAME --endpoint-url http://localhost:8989"