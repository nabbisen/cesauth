use std::sync::Mutex;

use cesauth_core::billing::ports::SubscriptionHistoryRepository;
use cesauth_core::billing::types::SubscriptionHistoryEntry;
use cesauth_core::ports::PortResult;

#[derive(Debug, Default)]
pub struct InMemorySubscriptionHistoryRepository {
    rows: Mutex<Vec<SubscriptionHistoryEntry>>,
}

impl SubscriptionHistoryRepository for InMemorySubscriptionHistoryRepository {
    async fn append(&self, e: &SubscriptionHistoryEntry) -> PortResult<()> {
        self.rows.lock().unwrap().push(e.clone()); Ok(())
    }
    async fn list_for_subscription(&self, sub_id: &str) -> PortResult<Vec<SubscriptionHistoryEntry>> {
        Ok(self.rows.lock().unwrap().iter()
           .filter(|e| e.subscription_id == sub_id)
           .cloned().collect())
    }
}
