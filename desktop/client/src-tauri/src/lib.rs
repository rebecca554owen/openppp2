pub mod config;
mod desktop;
pub mod lifecycle;
pub mod pinger;
pub mod preferences;
pub mod process;
pub mod stats;
pub mod subscription;
pub mod telemetry;

pub use desktop::run;
