# SilentLink - Covert Mesh Communication System

SilentLink is a sophisticated peer-to-peer communication protocol that leverages ultrasonic audio for device discovery and handshake, followed by encrypted Bluetooth-based payload transfer. The system supports offline messaging and includes adaptive exploit capabilities for covert message delivery through vulnerable applications.

## 🎯 Core Concept

SilentLink implements a **stealth-first, infrastructure-free** communication system that operates in three phases:

1. **🔊 Ultrasonic Discovery**: Inaudible audio beacons for proximity-based device discovery
2. **📡 Bluetooth Encryption**: Encrypted mesh networking for secure data transfer  
3. **🕷️ Trojan Injection**: Adaptive exploitation of vulnerable apps for covert message delivery

## 🛠️ System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  SilentLink Core                        │
├─────────────────────────────────────────────────────────┤
│  Message Router  │  Exploit Engine  │  Event Loop      │
├─────────────────────────────────────────────────────────┤
│ Ultrasonic Engine │ Bluetooth Manager │ Crypto Engine   │
├─────────────────────────────────────────────────────────┤
│    Audio I/O     │    BLE Stack      │   X25519+AES    │
└─────────────────────────────────────────────────────────┘
```

## 🚀 Key Features

### ✅ **Stealth Communication**
- **Ultrasonic Discovery**: 18-22kHz inaudible frequency beacons
- **Encrypted Mesh**: X25519 key exchange + AES-GCM encryption
- **Zero Infrastructure**: No internet, cell towers, or WiFi required
- **Ephemeral**: Messages auto-expire with configurable TTL

### ✅ **Adaptive Exploitation**
- **Device Reconnaissance**: Scans for vulnerable apps automatically
- **Dynamic Exploit Selection**: Chooses best attack vector based on stealth rating
- **Multiple Injection Methods**: Intent hijacking, notification spoofing, storage injection
- **Trojan-Style Relay**: Uses compromised apps for indirect message delivery

### ✅ **Mesh Networking**
- **Multi-hop Routing**: Messages propagate through intermediate devices  
- **Emergency Broadcasting**: High-priority flooding with extended TTL
- **Neighbor Discovery**: Automatic topology mapping
- **Connection Management**: Handles device mobility and intermittent connectivity

## 📱 Usage Examples

### Basic Commands

```bash
# Start SilentLink daemon
cargo run start --name "Agent-007" --passphrase "secret_network_key"

# Send direct message
cargo run send "Hello World" --target <device-id>

# Broadcast to all nearby devices
cargo run send "General announcement" --broadcast

# Emergency broadcast (maximum propagation)
cargo run emergency "Emergency evacuation - proceed to exit Alpha"
```

### Advanced (Covert) Operations

```bash
# Device reconnaissance
cargo run recon

# Trojan-style message injection
cargo run trojan "Covert message delivery" --target <device-id>

# Emergency broadcast via all vectors (BLE + trojans)
cargo run emergency "Critical alert - all channels"

# Generate QR code for device handshake
cargo run qr-code --output handshake.png

# Network status
cargo run status
```

## 🔧 Configuration

Create `config.toml`:

```toml
[audio]
sample_rate = 48000
channels = 1
ultrasonic_freq_start = 18000.0
ultrasonic_freq_end = 22000.0
beacon_interval_ms = 5000
detection_threshold = 0.1

[bluetooth]
service_uuid = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
scan_timeout_ms = 30000
connection_timeout_ms = 10000
max_connections = 10

[crypto]
key_rotation_interval_hours = 24
message_ttl_seconds = 300
max_hops = 5

[mesh]
routing_update_interval_ms = 3000
neighbour_timeout_seconds = 120
max_cached_messages = 1000
```

## 🕵️ How the Trojan System Works

### 1. **Device Reconnaissance**
```rust
// Scan for installed apps
let apps = scanner.scan_device().await?;

// Analyze vulnerabilities
let vulnerable_apps = scanner.analyze_vulnerabilities(&apps);
```

### 2. **Exploit Vector Selection**
The system evaluates apps based on:
- **Exposed components** (Activities, Services, Receivers)
- **Dangerous permissions** (RECEIVE_SMS, POST_NOTIFICATIONS)
- **Known vulnerabilities** (SDK version, package-specific exploits)
- **Stealth rating** (how covert the injection method is)

### 3. **Payload Injection Methods**

#### Intent Hijacking
```rust
// Target exported components
for component in &app.exposed_components {
    if component.exported {
        // Inject via Android Intent system
        send_intent(&component.name, &payload)?;
    }
}
```

#### Notification Spoofing
```rust
// Create fake notification that appears to be from target app
create_fake_notification(&app.package_name, &message)?;
```

#### Shared Preferences Injection
```rust
// Inject data into app's local storage
inject_shared_preferences(&app.package_name, &payload)?;
```

## 🔒 Security Model

### **Threat Model**
- **Adversary**: Network surveillance, traffic analysis, device seizure
- **Goals**: Covert communication, message deniability, forward secrecy
- **Assumptions**: Physical proximity required, audio channels available

### **Cryptographic Guarantees**
- **Confidentiality**: AES-256-GCM encryption
- **Authenticity**: X25519 key exchange with device signatures
- **Forward Secrecy**: Ephemeral session keys rotated regularly
- **Deniability**: No persistent key material or message logs

### **Operational Security**
- **Traffic Analysis Resistance**: Variable beacon timing, encrypted mesh routing
- **Device Fingerprinting Resistance**: Randomized device identifiers
- **Detection Avoidance**: Ultrasonic frequencies below human hearing threshold

## 🎛️ Advanced Configuration

### **Stealth Mode Configuration**
```rust
// Ultra-low profile settings
audio.beacon_interval_ms = 30000;  // 30 second intervals
audio.detection_threshold = 0.05;  // Lower sensitivity
bluetooth.scan_timeout_ms = 10000; // Shorter scans
```

### **High-Throughput Mode**
```rust
// Maximum performance settings  
audio.beacon_interval_ms = 1000;   // 1 second intervals
bluetooth.max_connections = 50;    // More concurrent connections
mesh.routing_update_interval_ms = 1000; // Faster topology updates
```

### **Emergency Mode**
```rust
// Maximum propagation settings
crypto.message_ttl_seconds = 3600; // 1 hour TTL
crypto.max_hops = 20;              // Extended range
mesh.max_cached_messages = 10000;  // Larger message cache
```

## 🛡️ Countermeasures & Detection

### **For Defenders**
- **Audio monitoring**: Detect ultrasonic transmissions with spectrum analysis
- **Bluetooth scanning**: Monitor for SilentLink service UUIDs
- **App behavior analysis**: Detect unusual inter-app communication patterns
- **Network traffic analysis**: Look for encrypted mesh patterns

### **For Attackers (Operational Security)**
- **Frequency hopping**: Randomize ultrasonic frequencies
- **Timing variation**: Jitter beacon intervals to avoid patterns
- **UUID rotation**: Change service identifiers regularly  
- **Payload obfuscation**: Disguise trojan injections as legitimate app data

## 📊 Performance Characteristics

| Metric | Value | Notes |
|--------|-------|--------|
| **Discovery Range** | 5-10 meters | Ultrasonic audio range |
| **BLE Range** | 10-100 meters | Device dependent |
| **Message Latency** | 1-5 seconds | Single hop |
| **Throughput** | ~1KB/s | Per connection |
| **Battery Impact** | Medium | Audio processing intensive |
| **Detection Risk** | Low | Sub-audible frequencies |

## 🔬 Research Applications

SilentLink enables research in:
- **Covert Communication Protocols**
- **Mesh Network Resilience** 
- **Mobile Device Security**
- **Audio Steganography**
- **Proximity-Based Systems**
- **Emergency Communication Networks**

## ⚖️ Legal & Ethical Considerations

**⚠️ WARNING**: This software is for educational and research purposes only.

- **Penetration Testing**: Only test on systems you own or have explicit permission
- **Malware Distribution**: Do not use for malicious payload delivery
- **Privacy Laws**: Respect local laws regarding device monitoring and communication interception
- **Responsible Disclosure**: Report vulnerabilities through proper channels

## 🛠️ Development & Contributing

### **Building from Source**
```bash
git clone https://github.com/yourusername/silentlink
cd silentlink
cargo build --release
```

### **Dependencies**
- **Rust 1.70+**
- **Audio**: `cpal` for cross-platform audio I/O
- **Bluetooth**: `btleplug` for BLE communication
- **Crypto**: `x25519-dalek`, `aes-gcm` for encryption
- **FFT**: `rustfft` for signal processing

### **Platform Support**
- ✅ **Linux** (full support)
- ✅ **macOS** (full support) 
- ⚠️ **Windows** (limited BLE support)
- ⚠️ **Android** (requires NDK, limited permissions)
- ❌ **iOS** (requires jailbreak for full functionality)

## 📚 Related Work

- **BadBluetooth**: BLE vulnerability research
- **AirHopper**: Air-gap bridging via electromagnetic emissions
- **DiskFiltration**: Data exfiltration via hard drive acoustics
- **PowerHammer**: Power line communication attacks
- **USBee**: RF emissions from USB cables

## 🔮 Future Roadmap

- [ ] **Frequency Hopping**: Dynamic ultrasonic frequency selection
- [ ] **Protocol Agnostic Injection**: Support for more communication apps
- [ ] **AI-Powered Exploit Discovery**: Machine learning for vulnerability detection
- [ ] **Quantum-Resistant Crypto**: Post-quantum cryptographic algorithms
- [ ] **Hardware Acceleration**: FPGA/GPU acceleration for signal processing
- [ ] **Mobile App**: Android/iOS companion applications

---

**Disclaimer**: SilentLink is experimental software. Use responsibly and in compliance with applicable laws and regulations.
