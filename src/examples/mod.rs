// Examples module - demonstrations and sample code
// This module contains example implementations of the silentlink system

pub mod emergency;
pub mod qr;
pub mod demo;

// Re-export commonly used examples
pub use demo::comprehensive_demo;
pub use emergency::emergency_network_demo;
pub use qr::qr_code_demo;
