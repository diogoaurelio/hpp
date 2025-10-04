use bedrock_core::{create_huggingface_engine, BedrockService, EmbeddingRequest, CreateDocumentRequest, SearchRequest};
use std::collections::HashMap;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    println!("🤗 Setting up HuggingFace Embedding Engine...");

    // Create HuggingFace engine with MiniLM model
    let models_to_load = vec!["sentence-transformers/all-MiniLM-L6-v2".to_string()];
    let hf_engine = create_huggingface_engine(models_to_load, None).await?;

    // Create Bedrock service with HuggingFace embeddings
    let mut bedrock_service = BedrockService::with_huggingface_embeddings(hf_engine);

    println!("✅ HuggingFace engine initialized!");

    // Test 1: Create embeddings directly
    println!("\n📊 Testing direct embedding creation...");
    let embedding_request = EmbeddingRequest {
        model_id: "sentence-transformers/all-MiniLM-L6-v2".to_string(),
        input_text: "The quick brown fox jumps over the lazy dog".to_string(),
    };

    let embedding_response = bedrock_service.create_embedding(embedding_request).await?;
    println!("✅ Created embedding with {} dimensions", embedding_response.embedding.len());
    println!("📝 Token count: {}", embedding_response.input_token_count);

    // Test 2: Create and store documents
    println!("\n📚 Creating and storing documents...");
    let documents = vec![
        ("Machine learning is a subset of artificial intelligence", "AI"),
        ("Rust is a systems programming language focused on safety", "Programming"),
        ("Vector databases enable semantic search capabilities", "Database"),
        ("Neural networks are inspired by biological neurons", "AI"),
        ("HTTP is the protocol that powers the World Wide Web", "Web"),
    ];

    for (content, category) in documents {
        let mut metadata = HashMap::new();
        metadata.insert("category".to_string(), category.to_string());

        let request = CreateDocumentRequest {
            id: None,
            content: content.to_string(),
            metadata: Some(metadata),
        };

        let document = bedrock_service.create_document(request).await?;
        println!("📄 Stored document: {} (ID: {})", content, document.id);
    }

    // Test 3: Semantic search
    println!("\n🔍 Performing semantic search...");
    let search_queries = vec![
        "artificial intelligence and neural networks",
        "programming languages and software development",
        "database technology and data storage",
    ];

    for query in search_queries {
        println!("\n🔎 Query: \"{}\"", query);

        let search_request = SearchRequest {
            query: query.to_string(),
            limit: Some(3),
            similarity_threshold: Some(0.1),
            metadata_filter: None,
        };

        let search_response = bedrock_service.search_documents(search_request).await?;

        for (i, result) in search_response.results.iter().enumerate() {
            println!("  {}. [Score: {:.3}] {}",
                i + 1,
                result.similarity_score,
                result.document.content
            );
        }
    }

    // Test 4: Category-filtered search
    println!("\n🏷️  Performing category-filtered search...");
    let mut ai_filter = HashMap::new();
    ai_filter.insert("category".to_string(), "AI".to_string());

    let filtered_search = SearchRequest {
        query: "learning and intelligence".to_string(),
        limit: Some(5),
        similarity_threshold: None,
        metadata_filter: Some(ai_filter),
    };

    let filtered_response = bedrock_service.search_documents(filtered_search).await?;
    println!("🎯 AI-related documents:");
    for result in filtered_response.results {
        println!("  • [Score: {:.3}] {}", result.similarity_score, result.document.content);
    }

    println!("\n🎉 HuggingFace integration demo completed successfully!");
    Ok(())
}