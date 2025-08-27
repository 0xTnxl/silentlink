use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{RwLock, mpsc};
use tokio::time::interval;
use std::sync::atomic::{AtomicBool, Ordering};
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde::{Serialize, Deserialize};
use tracing::{info, warn, error, debug};

use crate::{DeviceId, EncryptedMessage, Result, SilentLinkError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WiFiConfig {
    pub p2p_port: u16,
    pub discovery_port: u16,
    pub group_name_prefix: String,
    pub connection_timeout_ms: u64,
    pub max_connections: usize,
    pub beacon_interval_ms: u64,
    pub network_interface: Option<String>,
}

impl Default for WiFiConfig {
    fn default() -> Self {
        Self {
            p2p_port: 8888,
            discovery_port: 8889,
            group_name_prefix: "SilentLink".to_string(),
            connection_timeout_ms: 10000,
            max_connections: 20,
            beacon_interval_ms: 3000,
            network_interface: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WiFiConnection {
    pub device_id: DeviceId,
    pub socket_addr: SocketAddr,
    pub connected_at: SystemTime,
    pub last_activity: Arc<RwLock<SystemTime>>,
    pub is_active: Arc<AtomicBool>,
}#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WiFiBeacon {
    pub device_id: DeviceId,
    pub device_name: String,
    pub service_port: u16,
    pub timestamp: u64,
    pub capabilities: Vec<String>,
    pub signal_strength: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WiFiHandshake {
    pub device_id: DeviceId,
    pub protocol_version: String,
    pub supported_features: Vec<String>,
    pub timestamp: u64,
}

pub struct WiFiManager {
    config: WiFiConfig,
    device_id: DeviceId,
    device_name: String,
    active_connections: Arc<RwLock<HashMap<DeviceId, WiFiConnection>>>,
    discovered_peers: Arc<RwLock<HashMap<DeviceId, WiFiBeacon>>>,
    is_running: Arc<AtomicBool>,
    tcp_listener: Option<TcpListener>,
}

impl WiFiManager {
    pub async fn new(config: WiFiConfig, device_id: DeviceId, device_name: String) -> Result<Self> {
        info!("🔧 Initializing WiFi Direct manager");
        
        // Check if WiFi is available
        if !Self::check_wifi_availability().await {
            return Err(SilentLinkError::System("WiFi interface not available".to_string()));
        }

        Ok(Self {
            config,
            device_id,
            device_name,
            active_connections: Arc::new(RwLock::new(HashMap::new())),
            discovered_peers: Arc::new(RwLock::new(HashMap::new())),
            is_running: Arc::new(AtomicBool::new(false)),
            tcp_listener: None,
        })
    }

    /// Check if WiFi interface is available
    pub async fn check_wifi_availability() -> bool {
        // Try to get network interfaces
        #[cfg(target_os = "linux")]
        {
            // Check for wireless interfaces
            if let Ok(output) = tokio::process::Command::new("iwconfig")
                .output()
                .await
            {
                let output_str = String::from_utf8_lossy(&output.stdout);
                return output_str.contains("IEEE 802.11");
            }
        }

        #[cfg(target_os = "windows")]
        {
            // Check Windows WiFi interfaces
            if let Ok(output) = tokio::process::Command::new("netsh")
                .args(["wlan", "show", "interfaces"])
                .output()
                .await
            {
                let output_str = String::from_utf8_lossy(&output.stdout);
                return output_str.contains("State") && output_str.contains("connected");
            }
        }

        #[cfg(target_os = "macos")]
        {
            // Check macOS WiFi
            if let Ok(output) = tokio::process::Command::new("networksetup")
                .args(["-getairportnetwork", "en0"])
                .output()
                .await
            {
                return output.status.success();
            }
        }

        // Fallback: assume WiFi is available
        true
    }

    pub async fn start(&mut self) -> Result<(mpsc::UnboundedReceiver<DeviceId>, mpsc::UnboundedReceiver<EncryptedMessage>)> {
        if self.is_running.load(Ordering::Acquire) {
            return Err(SilentLinkError::System("WiFi manager already running".to_string()));
        }

        info!("🚀 Starting WiFi Direct manager");

        // Create channels for events
        let (device_tx, device_rx) = mpsc::unbounded_channel();
        let (message_tx, message_rx) = mpsc::unbounded_channel();

        // Try to bind to the configured port, with fallback ports if needed
        let mut port_to_try = self.config.p2p_port;
        let mut listener = None;
        
        for attempt in 0..5 {
            let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port_to_try);
            match TcpListener::bind(bind_addr).await {
                Ok(tcp_listener) => {
                    info!("🔊 WiFi listener started on port {}", port_to_try);
                    if port_to_try != self.config.p2p_port {
                        warn!("Using fallback port {} instead of configured port {}", 
                              port_to_try, self.config.p2p_port);
                        // Update config to reflect actual port
                        self.config.p2p_port = port_to_try;
                    }
                    listener = Some(tcp_listener);
                    break;
                }
                Err(e) => {
                    if attempt < 4 {
                        warn!("Port {} in use, trying port {} (attempt {}/5)", 
                              port_to_try, port_to_try + 1, attempt + 1);
                        port_to_try += 1;
                    } else {
                        return Err(SilentLinkError::Network(format!(
                            "Failed to bind to any port after {} attempts. Last error: {}", 
                            attempt + 1, e
                        )));
                    }
                }
            }
        }

        self.tcp_listener = listener;
        self.is_running.store(true, Ordering::Release);

        // Start connection acceptor task
        if let Some(listener) = self.tcp_listener.take() {
            let device_id = self.device_id.clone();
            let device_name = self.device_name.clone();
            let active_connections = self.active_connections.clone();
            let is_running = self.is_running.clone();
            let device_tx_clone = device_tx.clone();
            let message_tx_clone = message_tx.clone();

            tokio::spawn(async move {
                Self::accept_connections(
                    listener,
                    device_id,
                    device_name,
                    active_connections,
                    is_running,
                    device_tx_clone,
                    message_tx_clone,
                ).await;
            });
        }

        // Start discovery beacon
        self.start_discovery_beacon().await?;

        // Start peer discovery
        self.start_peer_discovery(device_tx.clone()).await?;

        // Start connection cleanup task
        self.start_cleanup_task().await?;

        info!("✅ WiFi Direct manager started successfully");
        Ok((device_rx, message_rx))
    }

    async fn accept_connections(
        listener: TcpListener,
        device_id: DeviceId,
        device_name: String,
        active_connections: Arc<RwLock<HashMap<DeviceId, WiFiConnection>>>,
        is_running: Arc<AtomicBool>,
        device_tx: mpsc::UnboundedSender<DeviceId>,
        message_tx: mpsc::UnboundedSender<EncryptedMessage>,
    ) {
        while is_running.load(Ordering::Acquire) {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    debug!("📱 Incoming WiFi connection from {}", addr);
                    
                    let device_id_clone = device_id.clone();
                    let device_name_clone = device_name.clone();
                    let connections_clone = active_connections.clone();
                    let device_tx_clone = device_tx.clone();
                    let message_tx_clone = message_tx.clone();

                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(
                            stream,
                            addr,
                            device_id_clone,
                            device_name_clone,
                            connections_clone,
                            device_tx_clone,
                            message_tx_clone,
                        ).await {
                            warn!("Error handling WiFi connection from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept WiFi connection: {}", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    async fn handle_connection(
        mut stream: TcpStream,
        addr: SocketAddr,
        device_id: DeviceId,
        _device_name: String,
        active_connections: Arc<RwLock<HashMap<DeviceId, WiFiConnection>>>,
        device_tx: mpsc::UnboundedSender<DeviceId>,
        message_tx: mpsc::UnboundedSender<EncryptedMessage>,
    ) -> Result<()> {
        // Send handshake
        let handshake = WiFiHandshake {
            device_id: device_id.clone(),
            protocol_version: "1.0".to_string(),
            supported_features: vec!["encryption".to_string(), "mesh".to_string()],
            timestamp: SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let handshake_data = serde_json::to_vec(&handshake)?;
        let handshake_len = handshake_data.len() as u32;
        
        stream.write_all(&handshake_len.to_be_bytes()).await?;
        stream.write_all(&handshake_data).await?;

        // Read peer handshake
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let peer_handshake_len = u32::from_be_bytes(len_buf) as usize;
        
        if peer_handshake_len > 1024 * 1024 { // 1MB limit
            return Err(SilentLinkError::System("Handshake too large".to_string()));
        }

        let mut peer_handshake_data = vec![0u8; peer_handshake_len];
        stream.read_exact(&mut peer_handshake_data).await?;
        
        let peer_handshake: WiFiHandshake = serde_json::from_slice(&peer_handshake_data)?;
        let peer_device_id = peer_handshake.device_id.clone();

        info!("🤝 WiFi handshake completed with device: {} at {}", peer_device_id, addr);

        // Store connection
        let connection = WiFiConnection {
            device_id: peer_device_id.clone(),
            socket_addr: addr,
            connected_at: SystemTime::now(),
            last_activity: Arc::new(RwLock::new(SystemTime::now())),
            is_active: Arc::new(AtomicBool::new(true)),
        };

        let connection_activity = connection.last_activity.clone();
        let connection_active = connection.is_active.clone();
        active_connections.write().await.insert(peer_device_id.clone(), connection);
        
        // Notify about new device
        let _ = device_tx.send(peer_device_id.clone());

        // Handle messages
        let mut buffer = vec![0u8; 8192];
        while connection_active.load(Ordering::Acquire) {
            match stream.read(&mut buffer).await {
                Ok(0) => {
                    debug!("WiFi connection to {} closed", peer_device_id);
                    break;
                }
                Ok(n) => {
                    *connection_activity.write().await = SystemTime::now();
                    
                    // Try to parse as encrypted message
                    if let Ok(message) = serde_json::from_slice::<EncryptedMessage>(&buffer[..n]) {
                        let _ = message_tx.send(message);
                    }
                }
                Err(e) => {
                    warn!("Error reading from WiFi connection {}: {}", peer_device_id, e);
                    break;
                }
            }
        }

        // Cleanup connection
        connection_active.store(false, Ordering::Release);
        active_connections.write().await.remove(&peer_device_id);
        
        Ok(())
    }

    async fn start_discovery_beacon(&self) -> Result<()> {
        let beacon = WiFiBeacon {
            device_id: self.device_id.clone(),
            device_name: self.device_name.clone(),
            service_port: self.config.p2p_port,
            timestamp: SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            capabilities: vec!["mesh".to_string(), "encryption".to_string()],
            signal_strength: None,
        };

        let beacon_data = serde_json::to_vec(&beacon)?;
        let beacon_interval = self.config.beacon_interval_ms;
        let discovery_port = self.config.discovery_port;
        let is_running = self.is_running.clone();

        tokio::spawn(async move {
            let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to create UDP socket for beacon: {}", e);
                    return;
                }
            };

            if let Err(e) = socket.set_broadcast(true) {
                error!("Failed to enable broadcast: {}", e);
                return;
            }

            let mut interval = interval(Duration::from_millis(beacon_interval));
            let broadcast_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), discovery_port);

            while is_running.load(Ordering::Acquire) {
                interval.tick().await;
                
                if let Err(e) = socket.send_to(&beacon_data, broadcast_addr).await {
                    warn!("Failed to send WiFi beacon: {}", e);
                }
            }
        });

        info!("📡 WiFi discovery beacon started");
        Ok(())
    }

    async fn start_peer_discovery(&self, device_tx: mpsc::UnboundedSender<DeviceId>) -> Result<()> {
        let mut discovery_port = self.config.discovery_port;
        let original_discovery_port = self.config.discovery_port;
        let discovered_peers = self.discovered_peers.clone();
        let is_running = self.is_running.clone();
        let own_device_id = self.device_id.clone();

        tokio::spawn(async move {
            let mut socket = None;
            
            // Try to bind to discovery port with fallback
            for attempt in 0..5 {
                match tokio::net::UdpSocket::bind(format!("0.0.0.0:{}", discovery_port)).await {
                    Ok(s) => {
                        info!("👂 WiFi peer discovery listening on port {}", discovery_port);
                        if discovery_port != original_discovery_port {
                            warn!("Using fallback discovery port {} instead of configured port {}", 
                                  discovery_port, original_discovery_port);
                        }
                        socket = Some(s);
                        break;
                    }
                    Err(e) => {
                        if attempt < 4 {
                            warn!("Discovery port {} in use, trying port {} (attempt {}/5)", 
                                  discovery_port, discovery_port + 1, attempt + 1);
                            discovery_port += 1;
                        } else {
                            error!("Failed to bind discovery socket after {} attempts. Last error: {}", 
                                   attempt + 1, e);
                            return;
                        }
                    }
                }
            }

            let socket = match socket {
                Some(s) => s,
                None => {
                    error!("Failed to create discovery socket");
                    return;
                }
            };

            let mut buffer = vec![0u8; 1024];

            while is_running.load(Ordering::Acquire) {
                match socket.recv_from(&mut buffer).await {
                    Ok((n, addr)) => {
                        if let Ok(beacon) = serde_json::from_slice::<WiFiBeacon>(&buffer[..n]) {
                            // Ignore our own beacons
                            if beacon.device_id == own_device_id {
                                continue;
                            }

                            debug!("📡 Discovered WiFi peer: {} at {}", beacon.device_id, addr);
                            
                            let is_new = {
                                let peers = discovered_peers.read().await;
                                !peers.contains_key(&beacon.device_id)
                            };

                            if is_new {
                                let _ = device_tx.send(beacon.device_id.clone());
                            }

                            discovered_peers.write().await.insert(beacon.device_id.clone(), beacon);
                        }
                    }
                    Err(e) => {
                        warn!("Error receiving discovery beacon: {}", e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });

        info!("👂 WiFi peer discovery started");
        Ok(())
    }

    async fn start_cleanup_task(&self) -> Result<()> {
        let active_connections = self.active_connections.clone();
        let discovered_peers = self.discovered_peers.clone();
        let is_running = self.is_running.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30));

            while is_running.load(Ordering::Acquire) {
                interval.tick().await;

                // Cleanup stale connections
                let mut connections = active_connections.write().await;
                let cutoff = SystemTime::now() - Duration::from_secs(300); // 5 minutes
                
                connections.retain(|device_id, connection| {
                    let last_activity = *connection.last_activity.blocking_read();
                    if last_activity < cutoff {
                        info!("🧹 Cleaning up stale WiFi connection to {}", device_id);
                        connection.is_active.store(false, Ordering::Release);
                        false
                    } else {
                        true
                    }
                });

                // Cleanup old peer discoveries
                let mut peers = discovered_peers.write().await;
                let peer_cutoff = SystemTime::now() - Duration::from_secs(600); // 10 minutes
                
                peers.retain(|_, beacon| {
                    let beacon_time = std::time::UNIX_EPOCH + Duration::from_secs(beacon.timestamp);
                    beacon_time > peer_cutoff
                });
            }
        });

        Ok(())
    }

    pub async fn connect_to_device(&self, target_device_id: DeviceId) -> Result<()> {
        // Check if already connected
        {
            let connections = self.active_connections.read().await;
            if connections.contains_key(&target_device_id) {
                return Ok(());
            }
        }

        // Find peer in discovered devices
        let beacon = {
            let peers = self.discovered_peers.read().await;
            peers.get(&target_device_id).cloned()
        };

        if let Some(beacon) = beacon {
            // Extract IP from service port (this is simplified - real WiFi Direct would use proper discovery)
            let target_addr = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), // Placeholder - would be from beacon
                beacon.service_port
            );

            info!("📱 Attempting WiFi connection to {} at {}", target_device_id, target_addr);

            match tokio::time::timeout(
                Duration::from_millis(self.config.connection_timeout_ms),
                TcpStream::connect(target_addr)
            ).await {
                Ok(Ok(_stream)) => {
                    info!("✅ WiFi connection established to {}", target_device_id);
                    // Connection handling will be done by the peer's accept loop
                    Ok(())
                }
                Ok(Err(e)) => Err(SilentLinkError::System(format!("WiFi connection failed: {}", e))),
                Err(_) => Err(SilentLinkError::System("WiFi connection timeout".to_string())),
            }
        } else {
            Err(SilentLinkError::DeviceNotFound(target_device_id.to_string()))
        }
    }

    pub async fn send_message(&self, target_device_id: &DeviceId, message: &EncryptedMessage) -> Result<()> {
        let connections = self.active_connections.read().await;
        
        if let Some(connection) = connections.get(target_device_id) {
            if !connection.is_active.load(Ordering::Acquire) {
                return Err(SilentLinkError::System("Connection not active".to_string()));
            }

            let message_data = serde_json::to_vec(message)?;
            
            // In a real implementation, we'd maintain the TcpStream for each connection
            // For now, we'll simulate message sending
            debug!("📤 Sending WiFi message to {} ({} bytes)", target_device_id, message_data.len());
            
            *connection.last_activity.write().await = SystemTime::now();
            Ok(())
        } else {
            Err(SilentLinkError::DeviceNotFound(target_device_id.to_string()))
        }
    }

    pub async fn get_connected_devices(&self) -> Vec<DeviceId> {
        self.active_connections.read().await.keys().cloned().collect()
    }

    pub async fn get_connection_info(&self, device_id: &DeviceId) -> Option<(SocketAddr, SystemTime)> {
        let connections = self.active_connections.read().await;
        connections.get(device_id).map(|conn| (conn.socket_addr, conn.connected_at))
    }

    pub async fn get_discovered_peers(&self) -> Vec<WiFiBeacon> {
        self.discovered_peers.read().await.values().cloned().collect()
    }

    pub async fn stop(&self) {
        info!("🛑 Stopping WiFi Direct manager");
        self.is_running.store(false, Ordering::Release);
        
        // Close all connections
        let mut connections = self.active_connections.write().await;
        for (_, connection) in connections.drain() {
            connection.is_active.store(false, Ordering::Release);
            debug!("Disconnected from WiFi device: {} (connected since {})", 
                   connection.device_id, 
                   connection.connected_at.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs());
        }

        info!("✅ WiFi Direct manager stopped");
    }

    /// Check if WiFi is preferred over Bluetooth based on conditions
    pub async fn should_prefer_wifi(&self) -> bool {
        // Prefer WiFi if:
        // 1. More peers discovered via WiFi
        // 2. Better connection quality
        // 3. Bluetooth is unavailable
        
        let wifi_peers = self.discovered_peers.read().await.len();
        let wifi_connections = self.active_connections.read().await.len();
        
        // Simple heuristic: prefer WiFi if we have more WiFi connections
        wifi_peers > 2 || wifi_connections > 1
    }

    /// Establish direct connection to a discovered peer
    pub async fn connect_to_peer(&self, target_device_id: &DeviceId) -> Result<()> {
        info!("🔗 Attempting WiFi connection to {}", target_device_id);
        
        // Check if already connected
        if self.active_connections.read().await.contains_key(target_device_id) {
            info!("✅ Already connected to {} via WiFi", target_device_id);
            return Ok(());
        }

        // Look up discovered peer
        let discovered_peers = self.discovered_peers.read().await;
        let peer = discovered_peers.get(target_device_id)
            .ok_or_else(|| SilentLinkError::DeviceNotFound(format!("Device {} not discovered", target_device_id)))?;
        
        // Get connection details from beacon
        let peer_port = peer.service_port;
        drop(discovered_peers); // Release the read lock
        
        // Try connecting to peer's service port
        let _target_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), peer_port);
        
        // In a real implementation, you'd need to discover the actual IP of the peer
        // For now, try common local network addresses
        let potential_ips = vec![
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 101), 
            Ipv4Addr::new(192, 168, 1, 102),
            Ipv4Addr::new(10, 0, 0, 100),
            Ipv4Addr::new(10, 0, 0, 101),
        ];

        for ip in potential_ips {
            let target_addr = SocketAddr::new(IpAddr::V4(ip), peer_port);
            
            match tokio::time::timeout(
                Duration::from_millis(self.config.connection_timeout_ms),
                TcpStream::connect(target_addr)
            ).await {
                Ok(Ok(mut stream)) => {
                    info!("🎯 Connected to peer {} at {}", target_device_id, target_addr);
                    
                    // Send handshake
                    let handshake = WiFiHandshake {
                        device_id: self.device_id.clone(),
                        protocol_version: "1.0".to_string(),
                        supported_features: vec!["messaging".to_string(), "file_transfer".to_string()],
                        timestamp: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
                    };
                    
                    let handshake_json = serde_json::to_string(&handshake)?;
                    stream.write_all(handshake_json.as_bytes()).await
                        .map_err(|e| SilentLinkError::Network(e.to_string()))?;
                    stream.write_all(b"\n").await
                        .map_err(|e| SilentLinkError::Network(e.to_string()))?;
                    
                    // Create connection record
                    let connection = WiFiConnection {
                        device_id: target_device_id.clone(),
                        socket_addr: target_addr,
                        connected_at: SystemTime::now(),
                        last_activity: Arc::new(RwLock::new(SystemTime::now())),
                        is_active: Arc::new(AtomicBool::new(true)),
                    };
                    
                    // Store connection
                    self.active_connections.write().await.insert(target_device_id.clone(), connection);
                    
                    // Start connection handler (similar to existing accept handler)
                    let device_id = target_device_id.clone();
                    let active_connections = self.active_connections.clone();
                    
                    tokio::spawn(async move {
                        let mut buffer = vec![0u8; 8192];
                        
                        loop {
                            match stream.read(&mut buffer).await {
                                Ok(0) => {
                                    debug!("WiFi connection to {} closed", device_id);
                                    break;
                                }
                                Ok(n) => {
                                    debug!("Received {} bytes from WiFi connection {}", n, device_id);
                                    // Update last activity
                                    if let Some(conn) = active_connections.read().await.get(&device_id) {
                                        *conn.last_activity.write().await = SystemTime::now();
                                    }
                                    // Message handling would go here
                                }
                                Err(e) => {
                                    warn!("Error reading from WiFi connection {}: {}", device_id, e);
                                    break;
                                }
                            }
                        }
                        
                        // Clean up connection
                        active_connections.write().await.remove(&device_id);
                    });
                    
                    return Ok(());
                }
                Ok(Err(e)) => {
                    debug!("Failed to connect to {} at {}: {}", target_device_id, target_addr, e);
                    continue;
                }
                Err(_) => {
                    debug!("Connection timeout to {} at {}", target_device_id, target_addr);
                    continue;
                }
            }
        }

        Err(SilentLinkError::Network(format!("Could not establish WiFi connection to {}", target_device_id)))
    }

    pub async fn cleanup_stale_connections(&self) {
        let mut connections = self.active_connections.write().await;
        let cutoff = SystemTime::now() - Duration::from_secs(300); // 5 minutes
        
        let stale_devices: Vec<DeviceId> = connections
            .iter()
            .filter_map(|(id, conn)| {
                if conn.connected_at < cutoff && !conn.is_active.load(Ordering::Acquire) {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();

        for device_id in stale_devices {
            if let Some(connection) = connections.remove(&device_id) {
                connection.is_active.store(false, Ordering::Release);
                info!("Cleaned up stale WiFi connection to: {}", device_id);
            }
        }
    }
}

impl std::fmt::Display for WiFiManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WiFiManager(device={}, port={})", self.device_id, self.config.p2p_port)
    }
}
