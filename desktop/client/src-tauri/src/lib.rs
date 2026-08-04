pub mod config;
mod desktop;
pub mod launch_options;
pub mod lifecycle;
pub mod manual_nodes;
pub mod pinger;
pub mod preferences;
pub mod process;
pub mod stats;
pub mod subscription;
pub mod telemetry;

pub use desktop::run;

/// Atomically replaces `path` with `temporary` on Windows.
///
/// Uses `ReplaceFileW` so the swap is atomic: a crash between the write of
/// `temporary` and the swap can never leave `path` missing or truncated.
#[cfg(windows)]
pub(crate) fn replace_file_windows(temporary: &std::path::Path, path: &std::path::Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;

    let tmp_wide: Vec<u16> = temporary.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let dst_wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();

    // ReplaceFileW fails with ERROR_FILE_NOT_FOUND when the destination does
    // not exist; fall back to a plain rename in that case.
    let ok = unsafe {
        ReplaceFileW(dst_wide.as_ptr(), tmp_wide.as_ptr(), std::ptr::null(), 0, std::ptr::null_mut(), std::ptr::null_mut())
    };
    if ok != 0 {
        Ok(())
    } else {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(2) || err.raw_os_error() == Some(3) {
            std::fs::rename(temporary, path)
        } else {
            Err(err)
        }
    }
}
