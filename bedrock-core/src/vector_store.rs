use crate::types::*;
use anyhow::Result;
use std::collections::HashMap;

/// Trait defining the vector store interface
#[async_trait::async_trait]
pub trait VectorStoreTrait: Send + Sync {
    async fn store_document(&mut self, document: VectorDocument) -> Result<()>;
    async fn get_document(&self, id: &str) -> Option<VectorDocument>;
    async fn delete_document(&mut self, id: &str) -> Result<bool>;
    async fn search_similar(&self, query_embedding: Vec<f32>, limit: usize, threshold: Option<f32>) -> Result<Vec<SearchResult>>;
    async fn list_documents(&self, limit: Option<usize>, offset: Option<usize>) -> Result<Vec<VectorDocument>>;
    async fn count_documents(&self) -> Result<usize>;
}

/// In-memory vector store
pub struct InMemoryVectorStore {
    documents: HashMap<String, VectorDocument>,
    similarity_metric: SimilarityMetric,
}

impl InMemoryVectorStore {
    pub fn new() -> Self {
        Self {
            documents: HashMap::new(),
            similarity_metric: SimilarityMetric::default(),
        }
    }

    pub fn with_similarity_metric(similarity_metric: SimilarityMetric) -> Self {
        Self {
            documents: HashMap::new(),
            similarity_metric,
        }
    }

    fn calculate_similarity(&self, embedding1: &[f32], embedding2: &[f32]) -> f32 {
        if embedding1.len() != embedding2.len() {
            return 0.0;
        }

        match self.similarity_metric {
            SimilarityMetric::Cosine => {
                let dot_product: f32 = embedding1.iter().zip(embedding2).map(|(a, b)| a * b).sum();
                let norm1: f32 = embedding1.iter().map(|x| x * x).sum::<f32>().sqrt();
                let norm2: f32 = embedding2.iter().map(|x| x * x).sum::<f32>().sqrt();

                if norm1 == 0.0 || norm2 == 0.0 {
                    0.0
                } else {
                    dot_product / (norm1 * norm2)
                }
            }
            SimilarityMetric::DotProduct => {
                embedding1.iter().zip(embedding2).map(|(a, b)| a * b).sum()
            }
            SimilarityMetric::Euclidean => {
                let distance: f32 = embedding1
                    .iter()
                    .zip(embedding2)
                    .map(|(a, b)| (a - b) * (a - b))
                    .sum::<f32>()
                    .sqrt();
                // Convert distance to similarity (higher is more similar)
                1.0 / (1.0 + distance)
            }
        }
    }
}

#[async_trait::async_trait]
impl VectorStoreTrait for InMemoryVectorStore {
    async fn store_document(&mut self, document: VectorDocument) -> Result<()> {
        self.documents.insert(document.id.clone(), document);
        Ok(())
    }

    async fn get_document(&self, id: &str) -> Option<VectorDocument> {
        self.documents.get(id).cloned()
    }

    async fn delete_document(&mut self, id: &str) -> Result<bool> {
        Ok(self.documents.remove(id).is_some())
    }

    async fn search_similar(&self, query_embedding: Vec<f32>, limit: usize, threshold: Option<f32>) -> Result<Vec<SearchResult>> {
        let mut results: Vec<SearchResult> = self
            .documents
            .values()
            .map(|doc| {
                let similarity = self.calculate_similarity(&query_embedding, &doc.embedding);
                SearchResult {
                    document: doc.clone(),
                    similarity_score: similarity,
                }
            })
            .collect();

        // Filter by threshold if provided
        if let Some(threshold) = threshold {
            results.retain(|result| result.similarity_score >= threshold);
        }

        // Sort by similarity (descending)
        results.sort_by(|a, b| b.similarity_score.partial_cmp(&a.similarity_score).unwrap_or(std::cmp::Ordering::Equal));

        // Limit results
        results.truncate(limit);

        Ok(results)
    }

    async fn list_documents(&self, limit: Option<usize>, offset: Option<usize>) -> Result<Vec<VectorDocument>> {
        let mut docs: Vec<VectorDocument> = self.documents.values().cloned().collect();

        // Sort by created_at for consistent ordering
        docs.sort_by(|a, b| a.created_at.cmp(&b.created_at));

        let offset = offset.unwrap_or(0);
        if offset >= docs.len() {
            return Ok(vec![]);
        }

        let docs = docs.into_iter().skip(offset);

        if let Some(limit) = limit {
            Ok(docs.take(limit).collect())
        } else {
            Ok(docs.collect())
        }
    }

    async fn count_documents(&self) -> Result<usize> {
        Ok(self.documents.len())
    }
}

/// S3-backed vector store
pub struct S3VectorStore {
    s3_client: Box<dyn shared::S3ObjectStorageRepository>,
    bucket: String,
    similarity_metric: SimilarityMetric,
    // Cache for performance
    documents_cache: tokio::sync::RwLock<Option<HashMap<String, VectorDocument>>>,
}

impl S3VectorStore {
    pub fn new(s3_client: Box<dyn shared::S3ObjectStorageRepository>, bucket: String) -> Self {
        Self {
            s3_client,
            bucket,
            similarity_metric: SimilarityMetric::default(),
            documents_cache: tokio::sync::RwLock::new(None),
        }
    }

    pub fn with_similarity_metric(
        s3_client: Box<dyn shared::S3ObjectStorageRepository>,
        bucket: String,
        similarity_metric: SimilarityMetric,
    ) -> Self {
        Self {
            s3_client,
            bucket,
            similarity_metric,
            documents_cache: tokio::sync::RwLock::new(None),
        }
    }

    async fn load_documents(&self) -> Result<HashMap<String, VectorDocument>> {
        let request = shared::GetObjectRequest {
            bucket: self.bucket.clone(),
            key: "vectors/documents.json".to_string(),
        };

        match self.s3_client.get_object(request).await {
            Ok(response) => {
                let data = String::from_utf8(response.body.to_vec())?;
                let documents: HashMap<String, VectorDocument> = serde_json::from_str(&data)?;
                Ok(documents)
            }
            Err(_) => {
                // File doesn't exist yet, return empty map
                Ok(HashMap::new())
            }
        }
    }

    async fn save_documents(&self, documents: &HashMap<String, VectorDocument>) -> Result<()> {
        let data = serde_json::to_string_pretty(documents)?;
        let request = shared::PutObjectRequest {
            bucket: self.bucket.clone(),
            key: "vectors/documents.json".to_string(),
            body: bytes::Bytes::from(data),
            content_type: Some("application/json".to_string()),
            metadata: HashMap::new(),
        };

        self.s3_client.put_object(request).await?;

        // Invalidate cache
        *self.documents_cache.write().await = None;
        Ok(())
    }

    async fn get_documents_cached(&self) -> Result<HashMap<String, VectorDocument>> {
        let cache_read = self.documents_cache.read().await;
        if let Some(ref cached_documents) = *cache_read {
            return Ok(cached_documents.clone());
        }
        drop(cache_read);

        let documents = self.load_documents().await?;
        *self.documents_cache.write().await = Some(documents.clone());
        Ok(documents)
    }

    fn calculate_similarity(&self, embedding1: &[f32], embedding2: &[f32]) -> f32 {
        if embedding1.len() != embedding2.len() {
            return 0.0;
        }

        match self.similarity_metric {
            SimilarityMetric::Cosine => {
                let dot_product: f32 = embedding1.iter().zip(embedding2).map(|(a, b)| a * b).sum();
                let norm1: f32 = embedding1.iter().map(|x| x * x).sum::<f32>().sqrt();
                let norm2: f32 = embedding2.iter().map(|x| x * x).sum::<f32>().sqrt();

                if norm1 == 0.0 || norm2 == 0.0 {
                    0.0
                } else {
                    dot_product / (norm1 * norm2)
                }
            }
            SimilarityMetric::DotProduct => {
                embedding1.iter().zip(embedding2).map(|(a, b)| a * b).sum()
            }
            SimilarityMetric::Euclidean => {
                let distance: f32 = embedding1
                    .iter()
                    .zip(embedding2)
                    .map(|(a, b)| (a - b) * (a - b))
                    .sum::<f32>()
                    .sqrt();
                // Convert distance to similarity (higher is more similar)
                1.0 / (1.0 + distance)
            }
        }
    }
}

#[async_trait::async_trait]
impl VectorStoreTrait for S3VectorStore {
    async fn store_document(&mut self, document: VectorDocument) -> Result<()> {
        let mut documents = self.get_documents_cached().await?;
        documents.insert(document.id.clone(), document);
        self.save_documents(&documents).await?;
        Ok(())
    }

    async fn get_document(&self, id: &str) -> Option<VectorDocument> {
        match self.get_documents_cached().await {
            Ok(documents) => documents.get(id).cloned(),
            Err(_) => None,
        }
    }

    async fn delete_document(&mut self, id: &str) -> Result<bool> {
        let mut documents = self.get_documents_cached().await?;
        let existed = documents.remove(id).is_some();
        if existed {
            self.save_documents(&documents).await?;
        }
        Ok(existed)
    }

    async fn search_similar(&self, query_embedding: Vec<f32>, limit: usize, threshold: Option<f32>) -> Result<Vec<SearchResult>> {
        let documents = self.get_documents_cached().await?;

        let mut results: Vec<SearchResult> = documents
            .values()
            .map(|doc| {
                let similarity = self.calculate_similarity(&query_embedding, &doc.embedding);
                SearchResult {
                    document: doc.clone(),
                    similarity_score: similarity,
                }
            })
            .collect();

        // Filter by threshold if provided
        if let Some(threshold) = threshold {
            results.retain(|result| result.similarity_score >= threshold);
        }

        // Sort by similarity (descending)
        results.sort_by(|a, b| b.similarity_score.partial_cmp(&a.similarity_score).unwrap_or(std::cmp::Ordering::Equal));

        // Limit results
        results.truncate(limit);

        Ok(results)
    }

    async fn list_documents(&self, limit: Option<usize>, offset: Option<usize>) -> Result<Vec<VectorDocument>> {
        let documents = self.get_documents_cached().await?;
        let mut docs: Vec<VectorDocument> = documents.values().cloned().collect();

        // Sort by created_at for consistent ordering
        docs.sort_by(|a, b| a.created_at.cmp(&b.created_at));

        let offset = offset.unwrap_or(0);
        if offset >= docs.len() {
            return Ok(vec![]);
        }

        let docs = docs.into_iter().skip(offset);

        if let Some(limit) = limit {
            Ok(docs.take(limit).collect())
        } else {
            Ok(docs.collect())
        }
    }

    async fn count_documents(&self) -> Result<usize> {
        let documents = self.get_documents_cached().await?;
        Ok(documents.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    #[cfg(feature = "testing")]
    use shared::MockS3ObjectStorageRepository;

    fn create_test_document(id: &str, content: &str, embedding: Vec<f32>) -> VectorDocument {
        VectorDocument {
            id: id.to_string(),
            content: content.to_string(),
            embedding,
            metadata: HashMap::new(),
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_in_memory_store_document() {
        let mut store = InMemoryVectorStore::new();
        let doc = create_test_document("doc1", "test content", vec![0.1, 0.2, 0.3]);

        let result = store.store_document(doc.clone()).await;
        assert!(result.is_ok());

        let retrieved = store.get_document("doc1").await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().content, "test content");
    }

    #[tokio::test]
    async fn test_in_memory_delete_document() {
        let mut store = InMemoryVectorStore::new();
        let doc = create_test_document("doc1", "test content", vec![0.1, 0.2, 0.3]);

        store.store_document(doc).await.unwrap();

        let deleted = store.delete_document("doc1").await.unwrap();
        assert!(deleted);

        let retrieved = store.get_document("doc1").await;
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_in_memory_search_similar() {
        let mut store = InMemoryVectorStore::new();

        // Add some test documents
        let doc1 = create_test_document("doc1", "content1", vec![1.0, 0.0, 0.0]);
        let doc2 = create_test_document("doc2", "content2", vec![0.0, 1.0, 0.0]);
        let doc3 = create_test_document("doc3", "content3", vec![0.5, 0.5, 0.0]);

        store.store_document(doc1).await.unwrap();
        store.store_document(doc2).await.unwrap();
        store.store_document(doc3).await.unwrap();

        // Search for documents similar to [1.0, 0.0, 0.0]
        let results = store.search_similar(vec![1.0, 0.0, 0.0], 2, None).await.unwrap();

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].document.id, "doc1"); // Should be most similar
        assert!(results[0].similarity_score > results[1].similarity_score);
    }

    #[tokio::test]
    async fn test_cosine_similarity_calculation() {
        let store = InMemoryVectorStore::new();

        // Test identical vectors (should be 1.0)
        let sim = store.calculate_similarity(&[1.0, 0.0, 0.0], &[1.0, 0.0, 0.0]);
        assert!((sim - 1.0).abs() < 0.001);

        // Test orthogonal vectors (should be 0.0)
        let sim = store.calculate_similarity(&[1.0, 0.0, 0.0], &[0.0, 1.0, 0.0]);
        assert!(sim.abs() < 0.001);

        // Test opposite vectors (should be -1.0)
        let sim = store.calculate_similarity(&[1.0, 0.0, 0.0], &[-1.0, 0.0, 0.0]);
        assert!((sim - (-1.0)).abs() < 0.001);
    }

    #[tokio::test]
    async fn test_list_documents_with_pagination() {
        let mut store = InMemoryVectorStore::new();

        // Add multiple documents
        for i in 0..5 {
            let doc = create_test_document(&format!("doc{}", i), &format!("content{}", i), vec![i as f32, 0.0, 0.0]);
            store.store_document(doc).await.unwrap();
        }

        // Test limit
        let docs = store.list_documents(Some(3), None).await.unwrap();
        assert_eq!(docs.len(), 3);

        // Test offset
        let docs = store.list_documents(Some(2), Some(2)).await.unwrap();
        assert_eq!(docs.len(), 2);

        // Test count
        let count = store.count_documents().await.unwrap();
        assert_eq!(count, 5);
    }

    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_s3_vector_store_basic_operations() {
        let mut mock_s3 = MockS3ObjectStorageRepository::new();

        // Mock initial load (empty store)
        mock_s3
            .expect_get_object()
            .returning(|_| Box::pin(async { Err(anyhow::anyhow!("Not found")) }));

        // Mock save operations
        mock_s3
            .expect_put_object()
            .returning(|_| Box::pin(async { Ok("etag".to_string()) }));

        let mut store = S3VectorStore::new(Box::new(mock_s3), "test-bucket".to_string());
        let doc = create_test_document("doc1", "test content", vec![0.1, 0.2, 0.3]);

        let result = store.store_document(doc).await;
        assert!(result.is_ok());
    }

    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_s3_vector_store_load_existing() {
        let mut mock_s3 = MockS3ObjectStorageRepository::new();

        let existing_docs = HashMap::from([
            ("doc1".to_string(), create_test_document("doc1", "content1", vec![0.1, 0.2, 0.3]))
        ]);
        let docs_json = serde_json::to_string(&existing_docs).unwrap();

        // Mock load existing documents
        mock_s3
            .expect_get_object()
            .returning(move |_| {
                let docs_json = docs_json.clone();
                Box::pin(async move {
                    let content_length = docs_json.len() as u64;
                    Ok(shared::GetObjectResponse {
                        body: bytes::Bytes::from(docs_json),
                        content_type: Some("application/json".to_string()),
                        content_length,
                        etag: "etag".to_string(),
                        last_modified: chrono::Utc::now(),
                        metadata: HashMap::new(),
                    })
                })
            });

        let store = S3VectorStore::new(Box::new(mock_s3), "test-bucket".to_string());

        let doc = store.get_document("doc1").await;
        assert!(doc.is_some());
        assert_eq!(doc.unwrap().content, "content1");
    }
}