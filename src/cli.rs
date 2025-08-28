#![allow(unused_variables)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use uuid::Uuid;
use clap::{Parser, Subcommand};
use config::{Config, File};
use tracing::info;

use crate::{
    SilentLink, SilentLinkConfiguration, SilentLinkError, Result, DeviceId
};
use crate::examples::qr::QrHandshake;
use crate::examples::{emergency_network_demo, qr_code_demo};

#[derive(Parser)]
#[command(name = "silentlink")]
#[command(about = "SilentLink Mesh Communication System")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    #[arg(long, help = "Configuration file path")]
    pub config: Option<PathBuf>,
    
    #[arg(short, long, help = "Enable verbose logging")]
    pub verbose: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the SilentLink daemon
    Start {
        #[arg(long, help = "Device name")]
        name: Option<String>,
        
        #[arg(long, help = "Shared secret passphrase")]
        passphrase: Option<String>,
    },
    
    /// Send a message
    Send {
        #[arg(help = "Message content")]
        message: String,
        
        #[arg(long, help = "Target device ID")]
        target: Option<String>,
        
        #[arg(long, help = "Broadcast message")]
        broadcast: bool,
        
        #[arg(long, help = "Emergency message")]
        emergency: bool,
    },
    
    /// Generate QR code for handshake
    QrCode {
        #[arg(long, help = "Output file path")]
        output: Option<PathBuf>,
    },
    
    /// Show network status
    Status,
    
    /// Ping a device
    Ping {
        #[arg(help = "Target device ID")]
        target: String,
    },
    
    /// Covert reconnaissance mode
    Recon,
    
    /// Target mobile device with payload injection
    TargetPhone {
        #[arg(help = "Payload to inject")]
        payload: String,
        
        #[arg(long, help = "Target device ID or IP address")]
        target: Option<String>,
        
        #[arg(long, help = "Target specific apps (comma-separated)")]
        apps: Option<String>,
        
        #[arg(long, help = "Force privileged mode")]
        privileged: bool,
        
        #[arg(long, help = "Platform: android, ios, or auto-detect", default_value = "android")]
        platform: String,
    },
    
    /// Emergency broadcast via all vectors
    Emergency {
        #[arg(help = "Emergency message")]
        message: String,
    },
    
    /// Run emergency network demonstration
    EmergencyDemo,
    
    /// Run QR code handshake demonstration
    QrDemo,
}

pub async fn run_cli() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize logging with safe environment handling
    let log_level = if cli.verbose { "debug" } else { "info" };
    
    // Use tracing_subscriber builder to avoid unsafe env modification
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| format!("silentlink={}", log_level))
        )
        .finish();
    
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| SilentLinkError::System(format!("Failed to set logger: {}", e)))?;

    // Load configuration
    let mut config = SilentLinkConfiguration::default();
    if let Some(config_path) = &cli.config {
        let settings = Config::builder()
            .add_source(File::from(config_path.as_path()))
            .build()?;
        config = settings.try_deserialize()?;
    }

    match cli.command {
        Commands::Start { name, passphrase } => {
            if let Some(device_name) = name {
                config.device_name = device_name;
            }

            let silentlink = Arc::new(SilentLink::new(Some(config)).await?);
            
            if let Some(passphrase) = passphrase {
                silentlink.add_shared_secret_from_passphrase("default".to_string(), &passphrase).await;
            }

            silentlink.start().await?;
            
            info!("SilentLink started. Press Ctrl+C to stop.");
            
            // Wait for Ctrl+C
            tokio::signal::ctrl_c().await.map_err(|e| SilentLinkError::System(e.to_string()))?;
            
            silentlink.stop().await?;
        }

        Commands::Send { message, target, broadcast, emergency } => {
            let silentlink = Arc::new(SilentLink::new(Some(config)).await?);
            silentlink.start().await?;

            let message_id = if emergency {
                silentlink.send_emergency(message).await?
            } else if broadcast {
                silentlink.send_broadcast(message).await?
            } else if let Some(target_str) = target {
                let target_uuid = Uuid::parse_str(&target_str)
                    .map_err(|_| SilentLinkError::System("Invalid target device ID".to_string()))?;
                let target_device = DeviceId(target_uuid);
                silentlink.send_message(message, Some(target_device)).await?
            } else {
                return Err(SilentLinkError::System("Must specify target, broadcast, or emergency".to_string()));
            };

            info!("Message sent with ID: {}", message_id);
            
            // Wait a bit for delivery
            sleep(Duration::from_secs(5)).await;
            silentlink.stop().await?;
        }

        Commands::QrCode { output } => {
            let silentlink = Arc::new(SilentLink::new(Some(config)).await?);
            let qr_system = QrHandshake::new(silentlink);
            
            let qr_data = qr_system.generate_qr_data().await?;
            
            if let Some(path) = output {
                qr_system.save_qr_image(&path).await?;
                println!("QR code saved to: {:?}", path);
            } else {
                println!("QR Code Data:\n{}", qr_data);
            }
        }

        Commands::Status => {
            let silentlink = Arc::new(SilentLink::new(Some(config)).await?);
            silentlink.start().await?;
            
            // Wait a moment for connections to establish
            sleep(Duration::from_secs(3)).await;
            
            let connected_devices = silentlink.get_connected_devices().await;
            let stats = silentlink.get_network_stats().await;
            
            println!("SilentLink Status:");
            println!("Device ID: {}", silentlink.device_id());
            println!("Device Name: {}", silentlink.device_name());
            println!("Connected Devices: {}", connected_devices.len());
            for device in connected_devices {
                println!("  - {}", device);
            }
            println!("Messages Sent: {}", stats.messages_sent);
            println!("Messages Received: {}", stats.messages_received);
            println!("Messages Forwarded: {}", stats.messages_forwarded);
            println!("Active Neighbors: {}", stats.active_neighbors);
            
            // Show system information
            let _ = silentlink.get_system_info().await;
            
            silentlink.stop().await?;
        }

        Commands::Ping { target } => {
            let target_uuid = Uuid::parse_str(&target)
                .map_err(|_| SilentLinkError::System("Invalid target device ID".to_string()))?;
            let target_device = DeviceId(target_uuid);

            let silentlink = Arc::new(SilentLink::new(Some(config)).await?);
            silentlink.start().await?;
            
            // Wait for connections
            sleep(Duration::from_secs(2)).await;
            
            let ping_id = silentlink.ping_device(target_device.clone()).await?;
            info!("Ping sent to {} (ID: {})", target_device, ping_id);
            
            // Wait for response
            sleep(Duration::from_secs(5)).await;
            silentlink.stop().await?;
        }
        
        Commands::Recon => {
            let silentlink = Arc::new(SilentLink::new(Some(config)).await?);
            silentlink.start().await?;
            
            info!("Starting covert reconnaissance...");
            silentlink.reconnaissance_mode().await?;
            
            sleep(Duration::from_secs(3)).await;
            silentlink.stop().await?;
        }
        
        Commands::TargetPhone { payload, target, apps: _, privileged, platform } => {
            info!("Targeting mobile device with payload injection");
            
            // Create config with privileged mode if requested
            let mut target_config = config.clone();
            target_config.enable_privileged_mode = privileged;
            
            let silentlink = Arc::new(SilentLink::new(Some(target_config)).await?);
            silentlink.start().await?;
            
            // Wait for ultrasonic discovery and transport initialization
            info!("Initializing discovery systems...");
            sleep(Duration::from_secs(3)).await;
            
            if let Some(target_str) = target {
                // Try to parse as device ID first
                let target_device = if let Ok(target_uuid) = Uuid::parse_str(&target_str) {
                    Some(DeviceId(target_uuid))
                } else {
                    info!("Target appears to be IP address or name: {}", target_str);
                    // In real implementation, would resolve IP to device ID via network discovery
                    None
                };
                
                // Use the enhanced delivery system (discovery -> escalation -> injection)
                let message_id = silentlink.send_message(payload, target_device).await?;
                info!("Payload delivery attempted via enhanced flow - message ID: {}", message_id);
                
            } else {
                // No specific target - inject payload into local vulnerable apps
                info!("No target specified - attempting local payload injection");
                let injection_results = silentlink.inject_payload_to_apps(payload.as_bytes()).await?;
                
                println!("Injection Results:");
                for result in &injection_results {
                    let status = if result.success { "SUCCESS" } else { "FAILED" };
                    println!("  {} - {}: {} ({})", status, result.app_name, result.exploit_used, result.message);
                }
                
                let successful_injections = injection_results.iter().filter(|r| r.success).count();
                println!("\n🎯 Summary: {}/{} injections successful", successful_injections, injection_results.len());
                
                if successful_injections == 0 {
                    println!("💡 Try running with --privileged flag for enhanced capabilities");
                    println!("💡 Or specify --target <DEVICE_ID> to target a remote device");
                }
            }
            
            sleep(Duration::from_secs(2)).await;
            silentlink.stop().await?;
        }
        
        Commands::Emergency { message } => {
            let silentlink = Arc::new(SilentLink::new(Some(config)).await?);
            silentlink.start().await?;
            
            info!("Initiating emergency broadcast via all vectors...");
            let message_ids = silentlink.emergency_broadcast_covert(message).await?;
            info!("Emergency broadcast sent via {} vectors: {:?}", message_ids.len(), message_ids);
            
            sleep(Duration::from_secs(5)).await;
            silentlink.stop().await?;
        }
        
        Commands::EmergencyDemo => {
            info!("Starting emergency network demonstration...");
            emergency_network_demo().await?;
        }
        
        Commands::QrDemo => {
            info!("Starting QR code handshake demonstration...");
            qr_code_demo().await?;
        }
    }

    Ok(())
}
