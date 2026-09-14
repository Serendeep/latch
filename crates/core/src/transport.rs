//! Length-prefixed, secret-free local request transport.

use crate::protocol::{MAX_FRAME_BYTES, RunRequest, RunResponse};
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::path::PathBuf;

/// Local transport failure without endpoint or payload details.
#[derive(Debug)]
pub struct TransportError;

/// Resolve the private Linux runtime endpoint shared by the desktop and CLI.
#[cfg(target_os = "linux")]
pub fn socket_path() -> Result<PathBuf, TransportError> {
    use std::os::unix::fs::MetadataExt;
    let directory = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .ok_or(TransportError)?;
    let metadata = directory.symlink_metadata().map_err(|_| TransportError)?;
    if !directory.is_absolute()
        || metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(TransportError);
    }
    Ok(directory.join("latch-development.sock"))
}

/// Send one request and read one final response from the owner-only endpoint.
#[cfg(target_os = "linux")]
pub fn exchange(request: &RunRequest) -> Result<RunResponse, TransportError> {
    use std::os::unix::{
        fs::{FileTypeExt, MetadataExt},
        net::UnixStream,
    };
    let path = socket_path()?;
    let metadata = path.symlink_metadata().map_err(|_| TransportError)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(TransportError);
    }
    let mut stream = UnixStream::connect(path).map_err(|_| TransportError)?;
    write_message(&mut stream, request)?;
    read_response(&mut stream)
}

/// Read one bounded frame. Unknown fields are rejected by the DTO parser.
pub fn read_message(reader: &mut impl Read) -> Result<RunRequest, TransportError> {
    let bytes = read_frame(reader)?;
    RunRequest::from_json(&bytes).map_err(|_| TransportError)
}

/// Write one bounded response frame.
pub fn write_response(
    writer: &mut impl Write,
    response: &RunResponse,
) -> Result<(), TransportError> {
    write_message(writer, response)
}

fn write_message(
    writer: &mut impl Write,
    value: &impl serde::Serialize,
) -> Result<(), TransportError> {
    let bytes = serde_json::to_vec(value).map_err(|_| TransportError)?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(TransportError);
    }
    writer
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .and_then(|_| writer.write_all(&bytes))
        .map_err(|_| TransportError)
}

fn read_frame(reader: &mut impl Read) -> Result<Vec<u8>, TransportError> {
    let mut length = [0; 4];
    reader.read_exact(&mut length).map_err(|_| TransportError)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(TransportError);
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes).map_err(|_| TransportError)?;
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn read_response(reader: &mut impl Read) -> Result<RunResponse, TransportError> {
    let bytes = read_frame(reader)?;
    serde_json::from_slice(&bytes).map_err(|_| TransportError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_oversized_and_truncated_frames() {
        for bytes in [
            0u32.to_be_bytes().to_vec(),
            ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes().to_vec(),
            [4u32.to_be_bytes().as_slice(), b"{}"].concat(),
        ] {
            assert!(read_message(&mut bytes.as_slice()).is_err());
        }
    }
}
