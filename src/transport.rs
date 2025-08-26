use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::{RwLock, mpsc};
use tokio::time::{interval, Duration};
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{info, warn, debug};
use serde::{Serialize, Deserialize};

use crate::{DeviceId, EncryptedMessage, Result, SilentLinkError};
use crate::bluetooth::{BluetoothManager, BluetoothConfig};
use crate::wifi::{WiFiManager, WiFiConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportType {
    Bluetooth,
    WiFi,
    Hybrid, // Use both simultaneously
}

impl std::fmt::Display for TransportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportType::Bluetooth => write!(f, "Bluetooth"),
            TransportType::WiFi => write!(f, "WiFi"),
            TransportType::Hybrid => write!(f, "Hybrid"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportPreference {
    PreferBluetooth,
    PreferWiFi,
    Automatic, // Choose based on availability and performance
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    pub bluetooth: BluetoothConfig,
    pub wifi: WiFiConfig,
    pub preference: TransportPreference,
    pub fallback_enabled: bool,
    pub hybrid_mode: bool,
    pub switch_threshold_ms: u64, // Time before switching transports
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            bluetooth: BluetoothConfig::default(),
            wifi: WiFiConfig::default(),
            preference: TransportPreference::Automatic,
            fallback_enabled: true,
            hybrid_mode: false,
            switch_threshold_ms: 10000, // 10 seconds
        }
    }
}

impl TransportConfig {
    pub fn get_default_transport(&self) -> TransportType {
        match self.preference {
            TransportPreference::PreferBluetooth => TransportType::Bluetooth,
            TransportPreference::PreferWiFi => TransportType::WiFi,
            TransportPreference::Automatic => {
                if self.hybrid_mode {
                    TransportType::Hybrid
                } else {
                    TransportType::WiFi // Default to WiFi as it typically has better range/throughput
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct TransportStats {
    pub bluetooth_connections: usize,
    pub wifi_connections: usize,
    pub bluetooth_discovered: usize,
    pub wifi_discovered: usize,
    pub active_transport: TransportType,
    pub last_switch: Option<SystemTime>,
    pub connection_quality: f32, // 0.0 to 1.0
}

#[derive(Debug, Clone)]
pub struct ConnectedDevice {
    pub device_id: DeviceId,
    pub transport: TransportType,
    pub connected_at: SystemTime,
    pub last_activity: SystemTime,
    pub signal_strength: Option<i32>,
    pub connection_quality: f32,
}

pub struct TransportManager {
    config: TransportConfig,
    device_id: DeviceId,
    device_name: String,
    
    bluetooth_manager: Arc<RwLock<Option<BluetoothManager>>>,
    wifi_manager: Arc<RwLock<Option<WiFiManager>>>,
    
    connected_devices: Arc<RwLock<HashMap<DeviceId, ConnectedDevice>>>,
    active_transport: Arc<RwLock<TransportType>>,
    is_running: Arc<AtomicBool>,
    
    // Event channels
    device_tx: Arc<RwLock<Option<mpsc::UnboundedSender<DeviceId>>>>,
    message_tx: Arc<RwLock<Option<mpsc::UnboundedSender<EncryptedMessage>>>>,
}impl TransportManager {
    pub fn new(config: TransportConfig, device_id: DeviceId, device_name: String) -> Self {
        let default_transport = config.get_default_transport();
        Self {
            config,
            device_id,
            device_name,
            bluetooth_manager: Arc::new(RwLock::new(None)),
            wifi_manager: Arc::new(RwLock::new(None)),
            connected_devices: Arc::new(RwLock::new(HashMap::new())),
            active_transport: Arc::new(RwLock::new(default_transport)),
            is_running: Arc::new(AtomicBool::new(false)),
            device_tx: Arc::new(RwLock::new(None)),
            message_tx: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn initialize_transports(&self) -> Result<()> {
        let mut available_transports = Vec::new();

        // Try to initialize Bluetooth
        match BluetoothManager::new(self.config.bluetooth.clone(), self.device_id.clone()).await {
            Ok(bt_manager) => {
                info!("📶 Bluetooth transport initialized");
                *self.bluetooth_manager.write().await = Some(bt_manager);
                available_transports.push(TransportType::Bluetooth);
            }
            Err(e) => {
                warn!("⚠️  Bluetooth initialization failed: {}", e);
            }
        }

        // Try to initialize WiFi
        match WiFiManager::new(self.config.wifi.clone(), self.device_id.clone(), self.device_name.clone()).await {
            Ok(wifi_manager) => {
                info!("📡 WiFi transport initialized for device: {}", self.device_name);
                *self.wifi_manager.write().await = Some(wifi_manager);
                available_transports.push(TransportType::WiFi);
            }
            Err(e) => {
                warn!("⚠️  WiFi initialization failed: {}", e);
            }
        }

        if available_transports.is_empty() {
            return Err(SilentLinkError::System("No transport methods available".to_string()));
        }

        // Set initial active transport based on preference and availability
        let initial_transport = self.choose_initial_transport(&available_transports).await;
        *self.active_transport.write().await = initial_transport;

        info!("✅ Transport manager initialized with {:?} transports", available_transports);
        info!("🎯 Active transport: {:?}", initial_transport);

        Ok(())
    }

    pub async fn choose_initial_transport(&self, available: &[TransportType]) -> TransportType {
        // Check if WiFi manager suggests preferring WiFi
        if available.contains(&TransportType::WiFi) {
            if let Some(ref wifi_manager) = *self.wifi_manager.read().await {
                if wifi_manager.should_prefer_wifi().await {
                    return TransportType::WiFi;
                }
            }
        }

        match self.config.preference {
            TransportPreference::PreferBluetooth => {
                if available.contains(&TransportType::Bluetooth) {
                    TransportType::Bluetooth
                } else if available.contains(&TransportType::WiFi) {
                    TransportType::WiFi
                } else {
                    available[0] // Fallback to first available
                }
            }
            TransportPreference::PreferWiFi => {
                if available.contains(&TransportType::WiFi) {
                    TransportType::WiFi
                } else if available.contains(&TransportType::Bluetooth) {
                    TransportType::Bluetooth
                } else {
                    available[0]
                }
            }
            TransportPreference::Automatic => {
                // Choose based on capability - WiFi generally has better range/throughput
                if available.contains(&TransportType::WiFi) {
                    TransportType::WiFi
                } else {
                    available[0]
                }
            }
        }
    }

    pub async fn start(&self) -> Result<(mpsc::UnboundedReceiver<DeviceId>, mpsc::UnboundedReceiver<EncryptedMessage>)> {
        if self.is_running.load(Ordering::Acquire) {
            return Err(SilentLinkError::System("Transport manager already running".to_string()));
        }

        info!("🚀 Starting Transport Manager for device: {}", self.device_name);

        // Initialize transports if not already done
        self.initialize_transports().await?;

        // Create unified event channels
        let (device_tx, device_rx) = mpsc::unbounded_channel();
        let (message_tx, message_rx) = mpsc::unbounded_channel();

        *self.device_tx.write().await = Some(device_tx.clone());
        *self.message_tx.write().await = Some(message_tx.clone());

        self.is_running.store(true, Ordering::Release);

        // Start active transport
        self.start_active_transport().await?;

        // Start transport monitoring and switching
        if self.config.fallback_enabled || self.config.hybrid_mode {
            self.start_transport_monitor().await?;
        }

        // Start device aggregation
        self.start_device_aggregator().await?;

        info!("✅ Transport Manager started successfully");
        Ok((device_rx, message_rx))
    }

    async fn start_active_transport(&self) -> Result<()> {
        let active = *self.active_transport.read().await;
        
        match active {
            TransportType::Bluetooth => {
                if let Some(bt_manager) = self.bluetooth_manager.write().await.as_mut() {
                    let (bt_device_rx, bt_message_rx) = bt_manager.start().await?;
                    self.forward_bluetooth_events(bt_device_rx, bt_message_rx).await;
                    info!("🔵 Bluetooth transport started");
                }
            }
            TransportType::WiFi => {
                if let Some(wifi_manager) = self.wifi_manager.write().await.as_mut() {
                    let (wifi_device_rx, wifi_message_rx) = wifi_manager.start().await?;
                    self.forward_wifi_events(wifi_device_rx, wifi_message_rx).await;
                    info!("🟢 WiFi transport started");
                }
            }
            TransportType::Hybrid => {
                // Start both transports
                if let Some(bt_manager) = self.bluetooth_manager.write().await.as_mut() {
                    let (bt_device_rx, bt_message_rx) = bt_manager.start().await?;
                    self.forward_bluetooth_events(bt_device_rx, bt_message_rx).await;
                    info!("🔵 Bluetooth transport started (hybrid mode)");
                }
                if let Some(wifi_manager) = self.wifi_manager.write().await.as_mut() {
                    let (wifi_device_rx, wifi_message_rx) = wifi_manager.start().await?;
                    self.forward_wifi_events(wifi_device_rx, wifi_message_rx).await;
                    info!("🟢 WiFi transport started (hybrid mode)");
                }
            }
        }

        Ok(())
    }

    async fn forward_bluetooth_events(
        &self,
        mut device_rx: mpsc::UnboundedReceiver<DeviceId>,
        mut message_rx: mpsc::UnboundedReceiver<EncryptedMessage>,
    ) {
        let device_tx = self.device_tx.clone();
        let message_tx = self.message_tx.clone();
        let connected_devices = self.connected_devices.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    device = device_rx.recv() => {
                        if let Some(device_id) = device {
                            // Add to connected devices
                            let device = ConnectedDevice {
                                device_id: device_id.clone(),
                                transport: TransportType::Bluetooth,
                                connected_at: SystemTime::now(),
                                last_activity: SystemTime::now(),
                                signal_strength: None,
                                connection_quality: 0.8, // Default BLE quality
                            };
                            connected_devices.write().await.insert(device_id.clone(), device);
                            
                            if let Some(ref tx) = *device_tx.read().await {
                                let _ = tx.send(device_id);
                            }
                        } else {
                            break;
                        }
                    }
                    message = message_rx.recv() => {
                        if let Some(msg) = message {
                            if let Some(ref tx) = *message_tx.read().await {
                                let _ = tx.send(msg);
                            }
                        } else {
                            break;
                        }
                    }
                }
            }
        });
    }

    async fn forward_wifi_events(
        &self,
        mut device_rx: mpsc::UnboundedReceiver<DeviceId>,
        mut message_rx: mpsc::UnboundedReceiver<EncryptedMessage>,
    ) {
        let device_tx = self.device_tx.clone();
        let message_tx = self.message_tx.clone();
        let connected_devices = self.connected_devices.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    device = device_rx.recv() => {
                        if let Some(device_id) = device {
                            // Add to connected devices
                            let device = ConnectedDevice {
                                device_id: device_id.clone(),
                                transport: TransportType::WiFi,
                                connected_at: SystemTime::now(),
                                last_activity: SystemTime::now(),
                                signal_strength: None,
                                connection_quality: 0.9, // WiFi generally better quality
                            };
                            connected_devices.write().await.insert(device_id.clone(), device);
                            
                            if let Some(ref tx) = *device_tx.read().await {
                                let _ = tx.send(device_id);
                            }
                        } else {
                            break;
                        }
                    }
                    message = message_rx.recv() => {
                        if let Some(msg) = message {
                            if let Some(ref tx) = *message_tx.read().await {
                                let _ = tx.send(msg);
                            }
                        } else {
                            break;
                        }
                    }
                }
            }
        });
    }

    async fn start_transport_monitor(&self) -> Result<()> {
        let bluetooth_manager = self.bluetooth_manager.clone();
        let wifi_manager = self.wifi_manager.clone();
        let active_transport = self.active_transport.clone();
        let is_running = self.is_running.clone();
        let _switch_threshold = self.config.switch_threshold_ms;
        let hybrid_mode = self.config.hybrid_mode;

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(5));

            while is_running.load(Ordering::Acquire) {
                interval.tick().await;

                if hybrid_mode {
                    // In hybrid mode, don't switch - use both
                    continue;
                }

                let current_transport = *active_transport.read().await;
                
                // Simple monitoring logic - in a real implementation, this would be more sophisticated
                let should_switch = match current_transport {
                    TransportType::Bluetooth => {
                        // Switch to WiFi if Bluetooth is having issues and WiFi is available
                        wifi_manager.read().await.is_some() && Self::should_switch_from_bluetooth().await
                    }
                    TransportType::WiFi => {
                        // Switch to Bluetooth if WiFi is having issues and Bluetooth is available
                        bluetooth_manager.read().await.is_some() && Self::should_switch_from_wifi().await
                    }
                    TransportType::Hybrid => false, // Already using both
                };

                if should_switch {
                    let new_transport = match current_transport {
                        TransportType::Bluetooth => TransportType::WiFi,
                        TransportType::WiFi => TransportType::Bluetooth,
                        TransportType::Hybrid => current_transport,
                    };

                    info!("🔄 Switching transport from {:?} to {:?}", current_transport, new_transport);
                    *active_transport.write().await = new_transport;
                    
                    // TODO: Implement actual transport switching logic
                    // This would involve stopping the current transport and starting the new one
                }
            }
        });

        Ok(())
    }

    async fn should_switch_from_bluetooth() -> bool {
        // Implement logic to detect Bluetooth issues
        // For example: low connection count, high latency, connection failures
        false // Placeholder
    }

    async fn should_switch_from_wifi() -> bool {
        // Implement logic to detect WiFi issues
        // For example: poor signal strength, high packet loss, authentication failures
        false // Placeholder
    }

    async fn start_device_aggregator(&self) -> Result<()> {
        let connected_devices = self.connected_devices.clone();
        let is_running = self.is_running.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30));

            while is_running.load(Ordering::Acquire) {
                interval.tick().await;

                // Clean up stale connections
                let mut devices = connected_devices.write().await;
                let cutoff = SystemTime::now() - Duration::from_secs(300); // 5 minutes

                devices.retain(|device_id, device| {
                    if device.last_activity < cutoff {
                        debug!("🧹 Removing stale device: {} ({})", device_id, device.transport);
                        false
                    } else {
                        true
                    }
                });
            }
        });

        Ok(())
    }

    pub async fn send_message(&self, target_device_id: &DeviceId, message: &EncryptedMessage) -> Result<()> {
        // Find which transport the device is connected via
        let connected_devices = self.connected_devices.read().await;
        
        if let Some(device) = connected_devices.get(target_device_id) {
            match device.transport {
                TransportType::Bluetooth => {
                    if let Some(ref bt_manager) = *self.bluetooth_manager.read().await {
                        bt_manager.send_message(target_device_id, message).await
                    } else {
                        Err(SilentLinkError::System("Bluetooth transport not available".to_string()))
                    }
                }
                TransportType::WiFi => {
                    if let Some(ref wifi_manager) = *self.wifi_manager.read().await {
                        wifi_manager.send_message(target_device_id, message).await
                    } else {
                        Err(SilentLinkError::System("WiFi transport not available".to_string()))
                    }
                }
                TransportType::Hybrid => {
                    // Try both transports, prefer WiFi for higher throughput
                    if let Some(ref wifi_manager) = *self.wifi_manager.read().await {
                        if wifi_manager.send_message(target_device_id, message).await.is_ok() {
                            return Ok(());
                        }
                    }
                    if let Some(ref bt_manager) = *self.bluetooth_manager.read().await {
                        bt_manager.send_message(target_device_id, message).await
                    } else {
                        Err(SilentLinkError::System("No transport available".to_string()))
                    }
                }
            }
        } else {
            Err(SilentLinkError::DeviceNotFound(target_device_id.to_string()))
        }
    }

    pub async fn connect_to_device(&self, target_device_id: DeviceId) -> Result<()> {
        let active = *self.active_transport.read().await;

        match active {
            TransportType::Bluetooth => {
                if let Some(ref bt_manager) = *self.bluetooth_manager.read().await {
                    bt_manager.connect_to_device(target_device_id).await
                } else {
                    Err(SilentLinkError::System("Bluetooth transport not available".to_string()))
                }
            }
            TransportType::WiFi => {
                if let Some(ref wifi_manager) = *self.wifi_manager.read().await {
                    wifi_manager.connect_to_device(target_device_id).await
                } else {
                    Err(SilentLinkError::System("WiFi transport not available".to_string()))
                }
            }
            TransportType::Hybrid => {
                // Try both transports
                let mut wifi_result = None;
                let mut bt_result = None;

                if let Some(ref wifi_manager) = *self.wifi_manager.read().await {
                    wifi_result = Some(wifi_manager.connect_to_device(target_device_id.clone()).await);
                }
                if let Some(ref bt_manager) = *self.bluetooth_manager.read().await {
                    bt_result = Some(bt_manager.connect_to_device(target_device_id.clone()).await);
                }

                // Return success if either transport connects
                match (wifi_result, bt_result) {
                    (Some(Ok(())), _) | (_, Some(Ok(()))) => Ok(()),
                    (Some(Err(e)), None) | (None, Some(Err(e))) => Err(e),
                    (Some(Err(_)), Some(Err(e))) => Err(e), // Return last error
                    (None, None) => Err(SilentLinkError::System("No transport available".to_string())),
                }
            }
        }
    }

    pub async fn get_transport_stats(&self) -> TransportStats {
        let connected_devices = self.connected_devices.read().await;
        let bluetooth_connections = connected_devices.values()
            .filter(|d| matches!(d.transport, TransportType::Bluetooth))
            .count();
        let wifi_connections = connected_devices.values()
            .filter(|d| matches!(d.transport, TransportType::WiFi))
            .count();

        let bluetooth_discovered = if let Some(ref bt_manager) = *self.bluetooth_manager.read().await {
            bt_manager.get_connected_devices().await.len()
        } else {
            0
        };

        let wifi_discovered = if let Some(ref wifi_manager) = *self.wifi_manager.read().await {
            wifi_manager.get_discovered_peers().await.len()
        } else {
            0
        };

        let active_transport = *self.active_transport.read().await;
        
        // Calculate overall connection quality
        let connection_quality = if connected_devices.is_empty() {
            0.0
        } else {
            connected_devices.values()
                .map(|d| d.connection_quality)
                .sum::<f32>() / connected_devices.len() as f32
        };

        TransportStats {
            bluetooth_connections,
            wifi_connections,
            bluetooth_discovered,
            wifi_discovered,
            active_transport,
            last_switch: None, // TODO: Track this
            connection_quality,
        }
    }

    pub async fn get_connected_devices(&self) -> Vec<ConnectedDevice> {
        self.connected_devices.read().await.values().cloned().collect()
    }

    pub async fn force_transport_switch(&self, transport: TransportType) -> Result<()> {
        let current = *self.active_transport.read().await;
        if current == transport {
            return Ok(());
        }

        info!("🔄 Forcing transport switch to {:?}", transport);
        *self.active_transport.write().await = transport;
        
        // TODO: Implement actual transport switching
        // This would involve stopping current transport and starting new one

        Ok(())
    }

    pub async fn stop(&self) {
        info!("🛑 Stopping Transport Manager");
        self.is_running.store(false, Ordering::Release);

        if let Some(ref bt_manager) = *self.bluetooth_manager.read().await {
            bt_manager.stop().await;
        }

        if let Some(ref wifi_manager) = *self.wifi_manager.read().await {
            wifi_manager.stop().await;
        }

        self.connected_devices.write().await.clear();
        info!("✅ Transport Manager stopped");
    }

    pub async fn get_wifi_connection_info(&self, device_id: &DeviceId) -> Option<(std::net::SocketAddr, std::time::SystemTime)> {
        if let Some(ref wifi_manager) = *self.wifi_manager.read().await {
            wifi_manager.get_connection_info(device_id).await
        } else {
            None
        }
    }

    pub async fn get_wifi_connected_devices(&self) -> Vec<DeviceId> {
        if let Some(ref wifi_manager) = *self.wifi_manager.read().await {
            wifi_manager.get_connected_devices().await
        } else {
            Vec::new()
        }
    }
}

impl std::fmt::Display for TransportManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TransportManager(device={}, preference={:?})", 
               self.device_id, self.config.preference)
    }
}
