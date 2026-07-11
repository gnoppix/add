//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
// Peer connection management.
//-------------------------------------------------------------------------------

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use tracing::{info, debug};

use add_protocol::envelope::WireEnvelope;

use crate::P2pError;

/// Maximum idle time before a peer is considered disconnected (seconds).
const MAX_IDLE_SECONDS: u64 = 300;

/// Maximum number of pending messages in a peer's queue.
const MAX_PENDING_MESSAGES: usize = 100;

/// Connection state for a peer.
#[derive(Debug, Clone, PartialEq)]
pub enum PeerState {
    /// WebSocket connected, handshake in progress.
    Connecting,
    /// Handshake complete, ready for messages.
    Connected,
    /// Connection lost or closed.
    Disconnected,
}

/// Information about a connected peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub peer_id: String,
    pub state: PeerState,
    pub connected_at: Instant,
    pub last_activity: Instant,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub public_key: Option<String>,
}

impl PeerInfo {
    pub fn new(peer_id: String) -> Self {
        let now = Instant::now();
        Self {
            peer_id,
            state: PeerState::Connecting,
            connected_at: now,
            last_activity: now,
            messages_sent: 0,
            messages_received: 0,
            public_key: None,
        }
    }

    pub fn is_idle(&self) -> bool {
        self.last_activity.elapsed() > Duration::from_secs(MAX_IDLE_SECONDS)
    }

    pub fn mark_sent(&mut self) {
        self.last_activity = Instant::now();
        self.messages_sent += 1;
    }

    pub fn mark_received(&mut self) {
        self.last_activity = Instant::now();
        self.messages_received += 1;
    }
}

/// Pending message in a peer's queue.
#[derive(Debug, Clone)]
pub struct PendingMessage {
    pub envelope: WireEnvelope,
    pub queued_at: Instant,
    pub retry_count: u32,
}

/// Manages multiple peer connections.
#[derive(Debug)]
pub struct PeerManager {
    peers: Arc<Mutex<HashMap<String, PeerInfo>>>,
    pending: Arc<Mutex<HashMap<String, Vec<PendingMessage>>>>,
    max_peers: usize,
}

impl PeerManager {
    pub fn new(max_peers: usize) -> Self {
        Self {
            peers: Arc::new(Mutex::new(HashMap::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
            max_peers,
        }
    }

    /// Register a new peer connection.
    pub async fn add_peer(&self, peer_id: String) -> Result<(), P2pError> {
        let mut peers = self.peers.lock().await;
        if peers.len() >= self.max_peers {
            return Err(P2pError::Peer(format!(
                "max peers reached ({})",
                self.max_peers
            )));
        }
        info!("Adding peer: {}", peer_id);
        let id = peer_id.clone();
        peers.insert(peer_id, PeerInfo::new(id));
        Ok(())
    }

    /// Remove a peer.
    pub async fn remove_peer(&self, peer_id: &str) {
        let mut peers = self.peers.lock().await;
        peers.remove(peer_id);
        let mut pending = self.pending.lock().await;
        pending.remove(peer_id);
        debug!("Removed peer: {}", peer_id);
    }

    /// Update peer state.
    pub async fn set_state(&self, peer_id: &str, state: PeerState) {
        let mut peers = self.peers.lock().await;
        if let Some(info) = peers.get_mut(peer_id) {
            info.state = state;
            info.last_activity = Instant::now();
        }
    }

    /// Set peer's public key after successful handshake.
    pub async fn set_public_key(&self, peer_id: &str, public_key: String) {
        let mut peers = self.peers.lock().await;
        if let Some(info) = peers.get_mut(peer_id) {
            info.public_key = Some(public_key);
        }
    }

    /// Get peer info.
    pub async fn get_peer(&self, peer_id: &str) -> Option<PeerInfo> {
        let peers = self.peers.lock().await;
        peers.get(peer_id).cloned()
    }

    /// List all connected peers.
    pub async fn list_peers(&self) -> Vec<PeerInfo> {
        let peers = self.peers.lock().await;
        peers.values().filter(|p| p.state == PeerState::Connected).cloned().collect()
    }

    /// Queue a message for delivery to a peer.
    pub async fn queue_message(
        &self,
        peer_id: &str,
        envelope: WireEnvelope,
    ) -> Result<(), P2pError> {
        let mut pending = self.pending.lock().await;
        let queue = pending.entry(peer_id.to_string()).or_insert_with(Vec::new);
        if queue.len() >= MAX_PENDING_MESSAGES {
            return Err(P2pError::Peer(format!(
                "message queue full for peer {}",
                peer_id
            )));
        }
        queue.push(PendingMessage {
            envelope,
            queued_at: Instant::now(),
            retry_count: 0,
        });
        Ok(())
    }

    /// Get pending messages for a peer.
    pub async fn drain_pending(&self, peer_id: &str) -> Vec<PendingMessage> {
        let mut pending = self.pending.lock().await;
        pending.get_mut(peer_id).map(|q| q.drain(..).collect()).unwrap_or_default()
    }

    /// Check if a peer is connected.
    pub async fn is_connected(&self, peer_id: &str) -> bool {
        let peers = self.peers.lock().await;
        peers
            .get(peer_id)
            .map(|p| p.state == PeerState::Connected)
            .unwrap_or(false)
    }

    /// Get count of connected peers.
    pub async fn connected_count(&self) -> usize {
        let peers = self.peers.lock().await;
        peers.values().filter(|p| p.state == PeerState::Connected).count()
    }

    /// Remove idle peers.
    pub async fn cleanup_idle(&self) -> Vec<String> {
        let mut peers = self.peers.lock().await;
        let idle_ids: Vec<String> = peers
            .iter()
            .filter(|(_, info)| info.is_idle())
            .map(|(id, _)| id.clone())
            .collect();

        for id in &idle_ids {
            info!("Removing idle peer: {}", id);
            peers.remove(id);
        }

        let mut pending = self.pending.lock().await;
        for id in &idle_ids {
            pending.remove(id);
        }

        idle_ids
    }
}

impl Clone for PeerManager {
    fn clone(&self) -> Self {
        Self {
            peers: Arc::clone(&self.peers),
            pending: Arc::clone(&self.pending),
            max_peers: self.max_peers,
        }
    }
}
