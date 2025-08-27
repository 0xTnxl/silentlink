// Comprehensive demonstration of SilentLink capabilities
use crate::*;
use crate::examples::emergency::EmergencySystem;
use crate::examples::qr::QrHandshake;
use std::{sync::Arc, time::Duration};
use tokio::time::sleep;
use tracing::info;

/// Complete demonstration of all SilentLink features
pub async fn comprehensive_demo() -> Result<()> {
    info!("Starting comprehensive SilentLink demo");

    // Create two devices to simulate communication
    let device1 = Arc::new(SilentLink::new(None).await?);
    let device2 = Arc::new(SilentLink::new(None).await?);

    // Add shared secret to both devices
    let shared_passphrase = "demo_network_2025";
    device1.add_shared_secret_from_passphrase("demo".to_string(), shared_passphrase).await;
    device2.add_shared_secret_from_passphrase("demo".to_string(), shared_passphrase).await;

    // Start both systems
    device1.start().await?;
    device2.start().await?;

    info!("Both devices started");

    // Wait for discovery
    sleep(Duration::from_secs(5)).await;

    // Send messages between devices
    let msg1_id = device1.send_broadcast("Hello from Device 1!".to_string()).await?;
    info!("Device 1 sent broadcast: {}", msg1_id);

    let msg2_id = device2.send_broadcast("Hello from Device 2!".to_string()).await?;
    info!("Device 2 sent broadcast: {}", msg2_id);

    // Test direct messaging
    let direct_msg_id = device1
        .send_message("Direct message test".to_string(), Some(device2.device_id().clone()))
        .await?;
    info!("Device 1 sent direct message: {}", direct_msg_id);

    // Test emergency broadcast
    let emergency_system = EmergencySystem::new(device1.clone());
    let emergency_id = emergency_system
        .broadcast_emergency("Test emergency alert", Some("Test Location".to_string()))
        .await?;
    info!("Emergency broadcast sent: {}", emergency_id);

    // Test QR handshake
    let qr_system = QrHandshake::new(device1.clone());
    let qr_data = qr_system.generate_qr_data().await?;
    info!("Generated QR handshake data: {}", &qr_data[..100]);

    // Let messages propagate
    sleep(Duration::from_secs(10)).await;

    // Show final stats
    let stats1 = device1.get_network_stats().await;
    let stats2 = device2.get_network_stats().await;
    
    info!("Final Stats:");
    info!("Device 1 - Sent: {}, Received: {}", stats1.messages_sent, stats1.messages_received);
    info!("Device 2 - Sent: {}, Received: {}", stats2.messages_sent, stats2.messages_received);

    // Cleanup
    device1.stop().await?;
    device2.stop().await?;

    info!("Demo completed successfully");
    Ok(())
}
