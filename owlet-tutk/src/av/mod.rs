pub mod frame;
pub mod ioctrl;
pub mod login;
pub mod packet;
pub const VERSION: u16 = 12;
pub(crate) mod resend;

/// Receivers must not require the peer to run the same AV version. The real Owlet camera
/// (firmware 4.2.146) sends version 0x0b; the vendor 4.3.8 client sends 0x0c.
/// Evidence: evidence/real_camera.md.
pub fn version_ok(v: u16) -> bool {
    (1..=0x00ff).contains(&v)
}
