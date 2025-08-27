// QR code handshake system
use crate::*;
use std::{sync::Arc, time::{SystemTime, UNIX_EPOCH}};
use tracing::info;
use uuid::Uuid;

/// QR Code Handshake System for secure device pairing
pub struct QrHandshake {
    silentlink: Arc<SilentLink>,
}

impl QrHandshake {
    pub fn new(silentlink: Arc<SilentLink>) -> Self {
        Self { silentlink }
    }

    pub async fn generate_qr_data(&self) -> Result<String> {
        let handshake_data = serde_json::json!({
            "version": "1.0",
            "device_id": self.silentlink.device_id().0.to_string(),
            "device_name": self.silentlink.device_name(),
            "public_key": hex::encode(self.silentlink.crypto_engine.get_public_key().await.as_bytes()),
            "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            "service_uuid": self.silentlink.config.bluetooth.service_uuid,
            "protocol": "silentlink"
        });

        Ok(handshake_data.to_string())
    }

    pub async fn process_qr_data(&self, qr_data: &str) -> Result<DeviceId> {
        let data: serde_json::Value = serde_json::from_str(qr_data)?;
        
        // Validate protocol
        if data["protocol"].as_str() != Some("silentlink") {
            return Err(SilentLinkError::InvalidHandshake);
        }

        // Extract device information
        let device_id_str = data["device_id"]
            .as_str()
            .ok_or(SilentLinkError::InvalidHandshake)?;
        
        let device_uuid = Uuid::parse_str(device_id_str)
            .map_err(|_| SilentLinkError::InvalidHandshake)?;
        
        let device_id = DeviceId(device_uuid);
        
        // Extract and validate public key
        if let Some(public_key_hex) = data["public_key"].as_str() {
            if let Ok(public_key_bytes) = hex::decode(public_key_hex) {
                if public_key_bytes.len() == 32 {
                    let mut key_bytes = [0u8; 32];
                    key_bytes.copy_from_slice(&public_key_bytes);
                    let peer_public_key = PublicKey::from(key_bytes);
                    
                    // Perform key exchange
                    self.silentlink
                        .crypto_engine
                        .perform_key_exchange(&device_id, &peer_public_key)
                        .await?;
                }
            }
        }

        // Attempt connection via transport manager
        self.silentlink
            .transport_manager
            .connect_to_device(device_id.clone())
            .await?;

        info!("QR handshake successful with device: {}", device_id);
        Ok(device_id)
    }

    pub async fn save_qr_image(&self, path: &std::path::Path) -> Result<()> {
        let qr_data = self.generate_qr_data().await?;
        
        // For now, just save as text file since QR image rendering has dependency issues
        std::fs::write(path, qr_data)?;
        
        info!("QR code data saved to: {:?}", path);
        Ok(())
    }
}

/// Demonstration of QR code handshake system
pub async fn qr_code_demo() -> Result<()> {
    info!("Starting QR code handshake demonstration");

    // Create two devices
    let mut config1 = SilentLinkConfiguration::default();
    config1.device_name = "QR-Device-1".to_string();
    let device1 = Arc::new(SilentLink::new(Some(config1)).await?);
    
    let mut config2 = SilentLinkConfiguration::default();
    config2.device_name = "QR-Device-2".to_string();
    let device2 = Arc::new(SilentLink::new(Some(config2)).await?);

    // Start devices
    device1.start().await?;
    device2.start().await?;

    // Create QR handshake systems
    let qr1 = QrHandshake::new(device1.clone());
    let qr2 = QrHandshake::new(device2.clone());

    // Device 1 generates QR code
    let qr_data = qr1.generate_qr_data().await?;
    info!("Device 1 generated QR code: {}", &qr_data[..100]);

    // Device 2 processes the QR code
    let connected_device = qr2.process_qr_data(&qr_data).await?;
    info!("Device 2 connected to device: {}", connected_device);

    // Test message exchange after QR handshake
    let msg_id = device1.send_message(
        "Hello via QR handshake!".to_string(),
        Some(device2.device_id().clone())
    ).await?;
    info!("Message sent after QR handshake: {}", msg_id);

    // Cleanup
    device1.stop().await?;
    device2.stop().await?;

    info!("QR code demo completed successfully");
    Ok(())
}
