// Emergency network demonstration
use crate::*;
use std::{sync::Arc, time::Duration};
use tokio::time::sleep;
use tracing::info;
use uuid::Uuid;

type MessageId = Uuid;

/// Emergency System for coordinating crisis communication
pub struct EmergencySystem {
    silentlink: Arc<SilentLink>,
}

impl EmergencySystem {
    pub fn new(silentlink: Arc<SilentLink>) -> Self {
        Self {
            silentlink,
        }
    }

    pub async fn enable_emergency_mode(&self) -> Result<()> {
        // Configure for maximum resilience and broadcasting
        info!("Emergency mode enabled for device: {}", self.silentlink.device_id());
        Ok(())
    }

    pub async fn broadcast_emergency(&self, message: &str, location: Option<String>) -> Result<MessageId> {
        let emergency_msg = if let Some(loc) = location {
            format!("🚨 EMERGENCY 🚨\n{}\nLocation: {}", message, loc)
        } else {
            format!("🚨 EMERGENCY 🚨\n{}", message)
        };

        // Use emergency broadcast which tries all transport methods
        self.silentlink.send_emergency(emergency_msg).await
    }
}

/// Demonstration of emergency network coordination
pub async fn emergency_network_demo() -> Result<()> {
    info!("Starting emergency network demonstration");

    // Create multiple devices for emergency scenario
    let mut devices = Vec::new();
    for i in 0..3 {
        let mut config = SilentLinkConfiguration::default();
        config.device_name = format!("Emergency-Node-{}", i + 1);
        
        let device = Arc::new(SilentLink::new(Some(config)).await?);
        
        // All devices share emergency protocol
        let emergency_system = EmergencySystem::new(device.clone());
        emergency_system.enable_emergency_mode().await?;
        
        device.start().await?;
        devices.push((device, emergency_system));
    }

    info!("Emergency network with {} nodes established", devices.len());

    // Wait for network formation
    sleep(Duration::from_secs(3)).await;

    // Simulate emergency broadcast from first device
    let (_first_device, first_emergency) = &devices[0];
    let emergency_id = first_emergency
        .broadcast_emergency(
            "Natural disaster detected - coordinating evacuation",
            Some("Grid: 52.370216, 4.895168".to_string()),
        )
        .await?;

    info!("Emergency alert broadcasted: {}", emergency_id);

    // Let emergency message propagate through network
    sleep(Duration::from_secs(8)).await;

    // Show network statistics
    for (i, (device, _)) in devices.iter().enumerate() {
        let stats = device.get_network_stats().await;
        let connected = device.get_connected_devices().await;
        
        info!(
            "📊 Node {} - Connected: {}, Sent: {}, Received: {}, Forwarded: {}",
            i + 1,
            connected.len(),
            stats.messages_sent,
            stats.messages_received,
            stats.messages_forwarded
        );
    }

    // Cleanup all devices
    for (device, _) in devices {
        device.stop().await?;
    }

    info!("Emergency network demo completed");
    Ok(())
}
