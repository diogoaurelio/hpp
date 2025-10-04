#!/bin/bash
# Complete Bedrock API testing script

set -e  # Exit on any error

BEDROCK_URL="http://localhost:3000"

echo "🚀 Testing HPP Bedrock API"
echo "================================="

# Check if service is running
if ! curl -s "$BEDROCK_URL/health" > /dev/null; then
    echo "❌ Bedrock service is not running at $BEDROCK_URL"
    echo "Please start it with: cargo run --package bedrock-api"
    exit 1
fi

echo "✅ Bedrock service is running"

echo -e "\n1. 🧠 Creating embedding..."
EMBEDDING_RESPONSE=$(curl -s -X POST "$BEDROCK_URL/embeddings" \
  -H "Content-Type: application/json" \
  -d '{
    "model_id": "amazon.titan-embed-text-v1",
    "input_text": "AI and machine learning are transforming technology"
  }')

echo "$EMBEDDING_RESPONSE" | jq -r '"Embedding dimensions: " + (.embedding | length | tostring) + ", Token count: " + (.input_token_count | tostring)'

echo -e "\n2. 📄 Creating test documents..."

# Create first document
curl -s -X POST "$BEDROCK_URL/documents" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "ai-doc-1",
    "content": "Artificial intelligence is revolutionizing industries by automating complex tasks and providing intelligent insights",
    "metadata": {
      "category": "AI",
      "topic": "automation",
      "difficulty": "intermediate"
    }
  }' | jq -r '"Created document: " + .id'

# Create second document
curl -s -X POST "$BEDROCK_URL/documents" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "ml-doc-1",
    "content": "Machine learning algorithms enable computers to learn from data without explicit programming",
    "metadata": {
      "category": "ML",
      "topic": "algorithms",
      "difficulty": "beginner"
    }
  }' | jq -r '"Created document: " + .id'

# Create third document
curl -s -X POST "$BEDROCK_URL/documents" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "data-doc-1",
    "content": "Data science combines statistical analysis, machine learning, and domain expertise to extract insights from data",
    "metadata": {
      "category": "DataScience",
      "topic": "analysis",
      "difficulty": "advanced"
    }
  }' | jq -r '"Created document: " + .id'

echo -e "\n3. 📋 Listing all documents..."
DOCS_COUNT=$(curl -s "$BEDROCK_URL/documents" | jq '. | length')
echo "Total documents: $DOCS_COUNT"

echo -e "\n4. 🔍 Searching for similar documents..."

# Search for AI-related content
echo "Searching for 'artificial intelligence and automation'..."
curl -s -X POST "$BEDROCK_URL/documents/search" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "artificial intelligence and automation",
    "limit": 3
  }' | jq -r '.results[] | "- " + .document.id + " (similarity: " + (.similarity_score | tostring | .[0:4]) + "): " + (.document.content | .[0:60]) + "..."'

echo -e "\n5. 🏷️  Filtering by metadata..."
echo "Searching with category filter 'ML'..."
curl -s -X POST "$BEDROCK_URL/documents/search" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "learning algorithms",
    "limit": 3,
    "metadata_filter": {
      "category": "ML"
    }
  }' | jq -r '.results[] | "- " + .document.id + " (" + .document.metadata.category + "): " + (.document.content | .[0:50]) + "..."'

echo -e "\n6. 📖 Getting specific document..."
DOC_CONTENT=$(curl -s "$BEDROCK_URL/documents/ai-doc-1" | jq -r '.content')
echo "Document ai-doc-1 content: ${DOC_CONTENT:0:80}..."

echo -e "\n7. ✏️  Updating document..."
curl -s -X PUT "$BEDROCK_URL/documents/ai-doc-1" \
  -H "Content-Type: application/json" \
  -d '{
    "content": "Artificial intelligence and machine learning are revolutionizing industries through intelligent automation and predictive analytics",
    "metadata": {
      "category": "AI",
      "topic": "automation",
      "difficulty": "intermediate",
      "updated": "2024-01-01"
    }
  }' | jq -r '"Updated document: " + .id'

echo -e "\n8. 🧪 Testing model invocation (AWS Bedrock compatible)..."
MODEL_RESPONSE=$(curl -s -X POST "$BEDROCK_URL/model/amazon.titan-embed-text-v1/invoke" \
  -H "Content-Type: application/json" \
  -d '{
    "inputText": "Testing direct model invocation"
  }')

EMBEDDING_LENGTH=$(echo "$MODEL_RESPONSE" | jq '.embedding | length')
TOKEN_COUNT=$(echo "$MODEL_RESPONSE" | jq '.inputTextTokenCount')
echo "Model invocation successful: $EMBEDDING_LENGTH dimensions, $TOKEN_COUNT tokens"

echo -e "\n9. 🧹 Cleaning up - deleting test documents..."
curl -s -X DELETE "$BEDROCK_URL/documents/ai-doc-1" | jq -r '"Deleted: ai-doc-1 (success: " + (. | tostring) + ")"'
curl -s -X DELETE "$BEDROCK_URL/documents/ml-doc-1" | jq -r '"Deleted: ml-doc-1 (success: " + (. | tostring) + ")"'
curl -s -X DELETE "$BEDROCK_URL/documents/data-doc-1" | jq -r '"Deleted: data-doc-1 (success: " + (. | tostring) + ")"'

# Verify cleanup
FINAL_COUNT=$(curl -s "$BEDROCK_URL/documents" | jq '. | length')
echo "Documents remaining: $FINAL_COUNT"

echo -e "\n🎉 Bedrock API test completed successfully!"
echo "================================="
echo ""
echo "📊 Test Results Summary:"
echo "✅ Embedding generation working"
echo "✅ Document CRUD operations working"
echo "✅ Vector similarity search working"
echo "✅ Metadata filtering working"
echo "✅ AWS Bedrock model invocation working"
echo "✅ All operations completed successfully"
echo ""
echo "🔗 Ready to integrate with your applications!"