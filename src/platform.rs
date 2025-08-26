use crate::{Result, SilentLinkError};
use async_trait::async_trait;

/// Platform-specific operations trait
#[async_trait]
pub trait PlatformAdapter {
    /// Get list of installed applications
    async fn get_installed_apps(&self) -> Result<Vec<AppMetadata>>;
    
    /// Send an intent to a specific component
    async fn send_intent(&self, component: &str, data: &[u8]) -> Result<()>;
    
    /// Create a notification that appears to be from the specified app
    async fn create_notification(&self, app_package: &str, content: &str) -> Result<()>;
    
    /// Access shared preferences for an app (if possible)
    async fn access_shared_preferences(&self, app_package: &str, key: &str, value: &str) -> Result<()>;
    
    /// Check if the platform supports a specific operation
    fn supports_operation(&self, operation: PlatformOperation) -> bool;
}

#[derive(Debug, Clone)]
pub struct AppMetadata {
    pub package_name: String,
    pub version: String,
    pub permissions: Vec<String>,
    pub exported_components: Vec<String>,
    pub target_sdk: u32,
}

#[derive(Debug, Clone, Copy)]
pub enum PlatformOperation {
    IntentInjection,
    NotificationSpoofing,
    SharedPreferencesAccess,
    DeepLinkManipulation,
}

/// Android platform implementation
pub struct AndroidAdapter;

#[async_trait]
impl PlatformAdapter for AndroidAdapter {
    async fn get_installed_apps(&self) -> Result<Vec<AppMetadata>> {
        // In a real implementation, this would use JNI to call Android PackageManager
        // For now, return simulated data
        Ok(vec![
            AppMetadata {
                package_name: "com.whatsapp".to_string(),
                version: "2.23.15.75".to_string(),
                permissions: vec![
                    "android.permission.RECEIVE_SMS".to_string(),
                    "android.permission.POST_NOTIFICATIONS".to_string(),
                ],
                exported_components: vec![
                    "com.whatsapp.notification.NotificationDismissReceiver".to_string(),
                ],
                target_sdk: 33,
            },
            AppMetadata {
                package_name: "com.android.chrome".to_string(),
                version: "117.0.5938.154".to_string(),
                permissions: vec![
                    "android.permission.INTERNET".to_string(),
                ],
                exported_components: vec![],
                target_sdk: 34,
            },
        ])
    }

    async fn send_intent(&self, component: &str, data: &[u8]) -> Result<()> {
        // Platform-specific implementation would go here
        println!("🤖 [Android] Sending intent to {} with {} bytes", component, data.len());
        
        // Simulate success for demo
        Ok(())
    }

    async fn create_notification(&self, app_package: &str, content: &str) -> Result<()> {
        println!("🤖 [Android] Creating notification for {}: {}", app_package, content);
        Ok(())
    }

    async fn access_shared_preferences(&self, app_package: &str, key: &str, value: &str) -> Result<()> {
        println!("🤖 [Android] Accessing SharedPreferences for {}: {} = {}", app_package, key, value);
        Ok(())
    }

    fn supports_operation(&self, operation: PlatformOperation) -> bool {
        match operation {
            PlatformOperation::IntentInjection => true,
            PlatformOperation::NotificationSpoofing => true,
            PlatformOperation::SharedPreferencesAccess => true,
            PlatformOperation::DeepLinkManipulation => true,
        }
    }
}

/// iOS platform implementation
pub struct IOSAdapter;

#[async_trait]
impl PlatformAdapter for IOSAdapter {
    async fn get_installed_apps(&self) -> Result<Vec<AppMetadata>> {
        // iOS has more restricted app discovery
        // Would require jailbreak or private APIs
        Ok(vec![
            AppMetadata {
                package_name: "com.apple.mobilemail".to_string(),
                version: "16.0".to_string(),
                permissions: vec![],
                exported_components: vec![],
                target_sdk: 16,
            },
        ])
    }

    async fn send_intent(&self, _component: &str, _data: &[u8]) -> Result<()> {
        // iOS doesn't have Android-style intents
        Err(SilentLinkError::System("Intent injection not supported on iOS".to_string()))
    }

    async fn create_notification(&self, app_package: &str, content: &str) -> Result<()> {
        println!("🍎 [iOS] Creating notification for {} (limited): {}", app_package, content);
        Ok(())
    }

    async fn access_shared_preferences(&self, _app_package: &str, _key: &str, _value: &str) -> Result<()> {
        Err(SilentLinkError::System("Shared preferences not accessible on iOS".to_string()))
    }

    fn supports_operation(&self, operation: PlatformOperation) -> bool {
        match operation {
            PlatformOperation::IntentInjection => false,
            PlatformOperation::NotificationSpoofing => true, // Limited
            PlatformOperation::SharedPreferencesAccess => false,
            PlatformOperation::DeepLinkManipulation => true,
        }
    }
}

/// Desktop/Linux platform implementation
pub struct DesktopAdapter;

#[async_trait]
impl PlatformAdapter for DesktopAdapter {
    async fn get_installed_apps(&self) -> Result<Vec<AppMetadata>> {
        // On desktop, we could scan for .desktop files, snap packages, etc.
        Ok(vec![
            AppMetadata {
                package_name: "firefox".to_string(),
                version: "119.0".to_string(),
                permissions: vec![],
                exported_components: vec![],
                target_sdk: 0,
            },
        ])
    }

    async fn send_intent(&self, _component: &str, _data: &[u8]) -> Result<()> {
        Err(SilentLinkError::System("Intent injection not supported on desktop".to_string()))
    }

    async fn create_notification(&self, app_package: &str, content: &str) -> Result<()> {
        println!("🖥️ [Desktop] Creating D-Bus notification for {}: {}", app_package, content);
        Ok(())
    }

    async fn access_shared_preferences(&self, _app_package: &str, _key: &str, _value: &str) -> Result<()> {
        Err(SilentLinkError::System("Shared preferences not supported on desktop".to_string()))
    }

    fn supports_operation(&self, operation: PlatformOperation) -> bool {
        match operation {
            PlatformOperation::IntentInjection => false,
            PlatformOperation::NotificationSpoofing => true,
            PlatformOperation::SharedPreferencesAccess => false,
            PlatformOperation::DeepLinkManipulation => false,
        }
    }
}

/// Platform detection and adapter creation
pub fn create_platform_adapter() -> Box<dyn PlatformAdapter + Send + Sync> {
    #[cfg(target_os = "android")]
    return Box::new(AndroidAdapter);
    
    #[cfg(target_os = "ios")]
    return Box::new(IOSAdapter);
    
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    return Box::new(DesktopAdapter);
    
    #[cfg(not(any(target_os = "android", target_os = "ios", target_os = "linux", target_os = "windows", target_os = "macos")))]
    return Box::new(DesktopAdapter); // Fallback
}

/// Configuration management with proper error handling
pub struct ConfigManager {
    config_path: Option<std::path::PathBuf>,
}

impl ConfigManager {
    pub fn new(config_path: Option<std::path::PathBuf>) -> Self {
        Self { config_path }
    }

    pub fn load_config(&self) -> Result<crate::SilentLinkConfiguration> {
        if let Some(path) = &self.config_path {
            if path.exists() {
                let config_str = std::fs::read_to_string(path)
                    .map_err(|e| SilentLinkError::System(format!("Failed to read config file: {}", e)))?;
                
                let config: crate::SilentLinkConfiguration = toml::from_str(&config_str)
                    .map_err(|e| SilentLinkError::System(format!("Failed to parse config: {}", e)))?;
                
                return Ok(config);
            }
        }
        
        // Return default config if no file found
        Ok(crate::SilentLinkConfiguration::default())
    }

    pub fn save_config(&self, config: &crate::SilentLinkConfiguration) -> Result<()> {
        if let Some(path) = &self.config_path {
            let config_str = toml::to_string_pretty(config)
                .map_err(|e| SilentLinkError::System(format!("Failed to serialize config: {}", e)))?;
            
            // Create parent directories if they don't exist
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| SilentLinkError::System(format!("Failed to create config directory: {}", e)))?;
            }
            
            std::fs::write(path, config_str)
                .map_err(|e| SilentLinkError::System(format!("Failed to write config file: {}", e)))?;
        }
        
        Ok(())
    }
}

/// Audio error handling improvements
#[derive(Debug, thiserror::Error)]
pub enum AudioError {
    #[error("No audio device available")]
    NoDevice,
    #[error("Unsupported audio format")]
    UnsupportedFormat,
    #[error("Audio stream error: {0}")]
    StreamError(String),
    #[error("Audio permission denied")]
    PermissionDenied,
}

impl From<AudioError> for crate::SilentLinkError {
    fn from(err: AudioError) -> Self {
        crate::SilentLinkError::Audio(err.to_string())
    }
}

/// Safe audio stream management
pub struct AudioStreamManager {
    _input_stream: Option<cpal::Stream>,
    _output_stream: Option<cpal::Stream>,
}

impl AudioStreamManager {
    pub fn new() -> Self {
        Self {
            _input_stream: None,
            _output_stream: None,
        }
    }

    pub fn set_streams(&mut self, input: cpal::Stream, output: cpal::Stream) {
        self._input_stream = Some(input);
        self._output_stream = Some(output);
    }

    pub fn stop_streams(&mut self) {
        self._input_stream = None;
        self._output_stream = None;
    }
}

impl Drop for AudioStreamManager {
    fn drop(&mut self) {
        self.stop_streams();
    }
}
