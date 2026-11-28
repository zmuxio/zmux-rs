use std::sync::Arc;

use zmux::{
    MemoryPrefixStore, PrefixAuth, PrefixAuthVerifier, PrefixBinding, PrefixGeneration,
    PrefixStore, PrefixTicket, PrefixWindow,
};

pub(crate) const ID: [u8; 16] = [0x72; 16];

pub(crate) fn fixture(binding: PrefixBinding) -> (PrefixAuth, Arc<PrefixAuthVerifier>) {
    let store = Arc::new(
        MemoryPrefixStore::new(
            PrefixWindow::new(30, 1, 2).unwrap(),
            vec![PrefixGeneration::new([0x17; 32], 0..=u64::MAX)],
            1024,
        )
        .unwrap(),
    );
    let ticket = PrefixTicket::new(ID, [0x47; 32], 1, 0..=u64::MAX, false);
    store.add_ticket(ticket.clone()).unwrap();
    let auth = PrefixAuth::new(ticket, store.local_schedule().0, 30, binding).unwrap();
    let verifier = Arc::new(PrefixAuthVerifier::new(store, binding).unwrap());
    (auth, verifier)
}
