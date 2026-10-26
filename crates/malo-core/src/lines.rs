//! Line reading with a length limit, for anything a peer sends: an endless "line" can't make us
//! buffer without bound.

use tokio::io::{AsyncBufRead, AsyncBufReadExt};

/// Reads one line (up to and including LF) of at most `max` bytes. None at end of stream; an
/// `InvalidData` error for a longer line.
pub async fn read_line<R: AsyncBufRead + Unpin>(
    r: &mut R,
    max: usize,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let buf = r.fill_buf().await?;
        if buf.is_empty() {
            return Ok((!line.is_empty()).then_some(line));
        }
        let (chunk, done) = match buf.iter().position(|b| *b == b'\n') {
            Some(i) => (&buf[..=i], true),
            None => (buf, false),
        };
        if line.len() + chunk.len() > max {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "line too long",
            ));
        }
        line.extend_from_slice(chunk);
        let n = chunk.len();
        r.consume(n);
        if done {
            return Ok(Some(line));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn lines_are_bounded() {
        let mut r: &[u8] = b"a\r\nbc\r\nlast";
        assert_eq!(read_line(&mut r, 8).await.unwrap().unwrap(), b"a\r\n");
        assert_eq!(read_line(&mut r, 8).await.unwrap().unwrap(), b"bc\r\n");
        assert_eq!(read_line(&mut r, 8).await.unwrap().unwrap(), b"last");
        assert!(read_line(&mut r, 8).await.unwrap().is_none());
        let long = [b'x'; 100];
        let mut r = tokio::io::BufReader::with_capacity(16, &long[..]);
        let e = read_line(&mut r, 50).await.unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
    }
}
