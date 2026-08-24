//! Detection of color scheme (DEC private mode 2031) escape sequences in PTY output.
//!
//! Applications that support mode 2031 query the terminal's current color scheme with
//! `CSI ? 996 n` and may subscribe to change notifications with `CSI ? 2031 h`. The
//! [`ColorSchemeSequenceScanner`] observes the raw byte stream flowing from the PTY to the
//! terminal emulator and reports occurrences of these sequences without modifying the stream.

/// Escape sequence requesting the terminal's current color scheme (`CSI ? 996 n`).
pub const COLOR_SCHEME_QUERY: &[u8] = b"\x1b[?996n";

/// Escape sequence enabling color palette change notifications (DECSET 2031).
pub const COLOR_SCHEME_NOTIFICATIONS_SET: &[u8] = b"\x1b[?2031h";

/// Escape sequence disabling color palette change notifications (DECRST 2031).
pub const COLOR_SCHEME_NOTIFICATIONS_RESET: &[u8] = b"\x1b[?2031l";

/// The longest sequence recognized by [`ColorSchemeSequenceScanner`].
const MAX_SEQUENCE_LEN: usize = COLOR_SCHEME_NOTIFICATIONS_SET.len();

/// A color scheme related escape sequence found in the PTY output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorSchemeSequence {
    /// The application requested the current color scheme (`CSI ? 996 n`).
    Query,
    /// The application enabled color palette change notifications (DECSET 2031).
    NotificationsSet,
    /// The application disabled color palette change notifications (DECRST 2031).
    NotificationsReset,
}

/// Scans chunks of PTY output for color scheme escape sequences.
///
/// Sequences may be split across chunk boundaries; the scanner keeps a small tail of the
/// previously scanned bytes so such sequences are still detected exactly once.
#[derive(Debug, Default)]
pub struct ColorSchemeSequenceScanner {
    /// Last up-to-`MAX_SEQUENCE_LEN - 1` bytes of the scanned stream.
    tail: [u8; MAX_SEQUENCE_LEN - 1],
    tail_len: usize,
}

impl ColorSchemeSequenceScanner {
    /// Scans `new_bytes` and invokes `on_match` for every detected sequence.
    pub fn scan(&mut self, new_bytes: &[u8], mut on_match: impl FnMut(ColorSchemeSequence)) {
        if new_bytes.is_empty() {
            return;
        }

        // Scan a window overlapping the previous chunk so sequences split across reads are
        // detected. Only matches starting within the tail are reported here; matches starting
        // in `new_bytes` are found by the full scan below.
        let overlap = self.tail_len.min(MAX_SEQUENCE_LEN - 1);
        let mut scratch = [0u8; 2 * (MAX_SEQUENCE_LEN - 1)];
        scratch[..overlap].copy_from_slice(&self.tail[..overlap]);
        let prefix = (MAX_SEQUENCE_LEN - 1).min(new_bytes.len());
        scratch[overlap..overlap + prefix].copy_from_slice(&new_bytes[..prefix]);
        let window = &scratch[..overlap + prefix];
        for pattern in [
            (COLOR_SCHEME_QUERY, ColorSchemeSequence::Query),
            (
                COLOR_SCHEME_NOTIFICATIONS_SET,
                ColorSchemeSequence::NotificationsSet,
            ),
            (
                COLOR_SCHEME_NOTIFICATIONS_RESET,
                ColorSchemeSequence::NotificationsReset,
            ),
        ] {
            let mut start = 0;
            while let Some(index) = find(&window[start..], pattern.0) {
                let position = start + index;
                if position >= overlap {
                    break;
                }
                // Matches entirely inside the tail were reported when their data was new;
                // only report matches consuming at least one byte of `new_bytes`.
                if position + pattern.0.len() > overlap {
                    on_match(pattern.1);
                }
                start = position + 1;
            }
        }

        // Scan the whole new chunk.
        for pattern in [
            (COLOR_SCHEME_QUERY, ColorSchemeSequence::Query),
            (
                COLOR_SCHEME_NOTIFICATIONS_SET,
                ColorSchemeSequence::NotificationsSet,
            ),
            (
                COLOR_SCHEME_NOTIFICATIONS_RESET,
                ColorSchemeSequence::NotificationsReset,
            ),
        ] {
            let mut start = 0;
            while let Some(index) = find(&new_bytes[start..], pattern.0) {
                on_match(pattern.1);
                let position = start + index;
                start = position + pattern.0.len();
            }
        }

        self.update_tail(new_bytes);
    }

    /// Retains the last up-to-`MAX_SEQUENCE_LEN - 1` bytes of the stream.
    fn update_tail(&mut self, new_bytes: &[u8]) {
        let keep = MAX_SEQUENCE_LEN - 1;
        if new_bytes.len() >= keep {
            self.tail
                .copy_from_slice(&new_bytes[new_bytes.len() - keep..]);
            self.tail_len = keep;
        } else {
            let drop = (self.tail_len + new_bytes.len()).saturating_sub(keep);
            if drop > 0 {
                self.tail.copy_within(drop..self.tail_len, 0);
                self.tail_len -= drop;
            }
            self.tail[self.tail_len..self.tail_len + new_bytes.len()].copy_from_slice(new_bytes);
            self.tail_len += new_bytes.len();
        }
    }
}

/// Finds the first occurrence of `pattern` in `data`.
fn find(data: &[u8], pattern: &[u8]) -> Option<usize> {
    if pattern.is_empty() || data.len() < pattern.len() {
        return None;
    }
    (0..=data.len() - pattern.len()).find(|&index| &data[index..index + pattern.len()] == pattern)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_query_in_single_chunk() {
        let mut scanner = ColorSchemeSequenceScanner::default();
        let mut matches = Vec::new();
        scanner.scan(b"hello\x1b[?996nworld", |sequence| matches.push(sequence));
        assert_eq!(matches, vec![ColorSchemeSequence::Query]);
    }

    #[test]
    fn detects_notifications_set_and_reset() {
        let mut scanner = ColorSchemeSequenceScanner::default();
        let mut matches = Vec::new();
        scanner.scan(b"\x1b[?2031h\x1b[?2031l", |sequence| matches.push(sequence));
        assert_eq!(
            matches,
            vec![
                ColorSchemeSequence::NotificationsSet,
                ColorSchemeSequence::NotificationsReset,
            ]
        );
    }

    #[test]
    fn detects_sequence_split_across_chunks() {
        let sequence = b"\x1b[?996n";
        for split in 1..sequence.len() {
            let mut scanner = ColorSchemeSequenceScanner::default();
            let mut matches = Vec::new();
            scanner.scan(&sequence[..split], |sequence| matches.push(sequence));
            scanner.scan(&sequence[split..], |sequence| matches.push(sequence));
            assert_eq!(
                matches,
                vec![ColorSchemeSequence::Query],
                "split at {split}"
            );
        }
    }

    #[test]
    fn detects_longest_sequence_split_across_chunks() {
        let sequence = b"\x1b[?2031h";
        for split in 1..sequence.len() {
            let mut scanner = ColorSchemeSequenceScanner::default();
            let mut matches = Vec::new();
            scanner.scan(&sequence[..split], |sequence| matches.push(sequence));
            scanner.scan(&sequence[split..], |sequence| matches.push(sequence));
            assert_eq!(
                matches,
                vec![ColorSchemeSequence::NotificationsSet],
                "split at {split}"
            );
        }
    }

    #[test]
    fn detects_sequences_split_across_many_small_chunks() {
        let input: &[u8] = b"\x1b[?996nfoo\x1b[?2031hbar\x1b[?2031l";
        let expected = vec![
            ColorSchemeSequence::Query,
            ColorSchemeSequence::NotificationsSet,
            ColorSchemeSequence::NotificationsReset,
        ];
        for chunk_size in 1..=input.len() {
            let mut scanner = ColorSchemeSequenceScanner::default();
            let mut matches = Vec::new();
            for chunk in input.chunks(chunk_size) {
                scanner.scan(chunk, |sequence| matches.push(sequence));
            }
            assert_eq!(matches, expected, "chunk size {chunk_size}");
        }
    }

    #[test]
    fn does_not_report_partial_matches() {
        let mut scanner = ColorSchemeSequenceScanner::default();
        let mut matches = Vec::new();
        scanner.scan(b"\x1b[?996", |sequence| matches.push(sequence));
        scanner.scan(b"x\x1b[?996n", |sequence| matches.push(sequence));
        assert_eq!(matches, vec![ColorSchemeSequence::Query]);
    }

    #[test]
    fn does_not_rereport_completed_sequence() {
        let mut scanner = ColorSchemeSequenceScanner::default();
        let mut matches = Vec::new();
        // Feed the sequence followed by trailing bytes; the completed sequence must be
        // reported exactly once, even though it remains visible in the tail window.
        for chunk in [&b"\x1b[?9"[..], b"96n", b"foo", b"bar"] {
            scanner.scan(chunk, |sequence| matches.push(sequence));
        }
        assert_eq!(matches, vec![ColorSchemeSequence::Query]);
    }

    #[test]
    fn ignores_similar_sequences() {
        let mut scanner = ColorSchemeSequenceScanner::default();
        let mut matches = Vec::new();
        scanner.scan(
            b"\x1b[?5n\x1b[?997n\x1b[?996;n\x1b[?2032h\x1b[?996 ",
            |sequence| matches.push(sequence),
        );
        assert!(matches.is_empty());
    }

    #[test]
    fn handles_empty_chunks() {
        let mut scanner = ColorSchemeSequenceScanner::default();
        let mut matches = Vec::new();
        scanner.scan(b"", |sequence| matches.push(sequence));
        scanner.scan(b"\x1b", |sequence| matches.push(sequence));
        scanner.scan(b"", |sequence| matches.push(sequence));
        scanner.scan(b"[?996n", |sequence| matches.push(sequence));
        assert_eq!(matches, vec![ColorSchemeSequence::Query]);
    }
}
