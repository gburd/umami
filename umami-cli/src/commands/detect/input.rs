//! Bounded input chunks and optional indentation-based event assembly.

use std::io::{self, Read};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

pub(super) const MAX_EVENT_BYTES: usize = 1024 * 1024;
pub(super) const WAKE: Duration = Duration::from_millis(50);

pub(super) enum InputEvent {
    Event(String),
    Wake,
    Eof,
}

pub(super) struct Input {
    receiver: Receiver<io::Result<Vec<u8>>>,
    chunk: Vec<u8>,
    cursor: usize,
    line: Vec<u8>,
    event: Vec<u8>,
    multiline: bool,
    pending: bool,
    eof: bool,
    last_byte: Instant,
}

impl Input {
    /// Starts a reader with at most two queued 8 KiB chunks, even without newlines.
    pub fn stdin(multiline: bool) -> Self {
        let (sender, receiver) = mpsc::sync_channel(2);
        std::thread::spawn(move || {
            let mut stdin = io::stdin().lock();
            loop {
                let mut bytes = vec![0; 8192];
                match stdin.read(&mut bytes) {
                    Ok(0) => break,
                    Ok(n) => {
                        bytes.truncate(n);
                        if sender.send(Ok(bytes)).is_err() {
                            break;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        let _ = sender.send(Err(e));
                        break;
                    }
                }
            }
        });
        Self {
            receiver,
            chunk: Vec::new(),
            cursor: 0,
            line: Vec::new(),
            event: Vec::new(),
            multiline,
            pending: false,
            eof: false,
            last_byte: Instant::now(),
        }
    }

    /// Returns within one chunk or one wake interval so busy input cannot starve checkpoints.
    pub fn next(&mut self) -> io::Result<InputEvent> {
        if self.eof {
            return self.finish();
        }
        if self.cursor == self.chunk.len() {
            match self.receiver.recv_timeout(WAKE) {
                Ok(bytes) => {
                    self.chunk = bytes?;
                    self.cursor = 0;
                    self.last_byte = Instant::now();
                }
                Err(RecvTimeoutError::Timeout) => {
                    if self.multiline && self.last_byte.elapsed() >= Duration::from_secs(1) {
                        return self.flush_pending();
                    }
                    return Ok(InputEvent::Wake);
                }
                Err(RecvTimeoutError::Disconnected) => {
                    self.eof = true;
                    return self.finish();
                }
            }
        }
        while self.cursor < self.chunk.len() {
            let byte = self.chunk[self.cursor];
            self.cursor += 1;
            if byte == b'\n' {
                if let Some(event) = self.physical_line()? {
                    return Ok(InputEvent::Event(event));
                }
            } else {
                let continuation = self.line.first().is_some_and(|b| *b == b' ' || *b == b'\t')
                    || (self.line.is_empty() && (byte == b' ' || byte == b'\t'));
                let buffered = if self.multiline && self.pending && continuation {
                    self.event.len() + 1
                } else {
                    0
                };
                if buffered + self.line.len() >= MAX_EVENT_BYTES {
                    return Err(too_large());
                }
                self.line.push(byte);
            }
        }
        Ok(InputEvent::Wake)
    }

    fn physical_line(&mut self) -> io::Result<Option<String>> {
        if self.line.last() == Some(&b'\r') {
            self.line.pop();
        }
        let line = std::mem::take(&mut self.line);
        if !self.multiline {
            return Ok(Some(String::from_utf8_lossy(&line).into_owned()));
        }
        let continuation = line.first().is_some_and(|b| *b == b' ' || *b == b'\t');
        let previous = if !continuation && self.pending {
            Some(self.take_event())
        } else {
            None
        };
        let separator = usize::from(self.pending);
        if self.event.len() + separator + line.len() > MAX_EVENT_BYTES {
            return Err(too_large());
        }
        if separator != 0 {
            self.event.push(b'\n');
        }
        self.event.extend(line);
        self.pending = true;
        Ok(previous)
    }

    fn finish(&mut self) -> io::Result<InputEvent> {
        if !self.line.is_empty() {
            if let Some(event) = self.physical_line()? {
                return Ok(InputEvent::Event(event));
            }
        }
        if self.pending {
            return Ok(InputEvent::Event(self.take_event()));
        }
        Ok(InputEvent::Eof)
    }

    fn flush_pending(&mut self) -> io::Result<InputEvent> {
        match self.finish()? {
            InputEvent::Eof => Ok(InputEvent::Wake),
            event => Ok(event),
        }
    }

    fn take_event(&mut self) -> String {
        self.pending = false;
        String::from_utf8_lossy(&std::mem::take(&mut self.event)).into_owned()
    }
}

fn too_large() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("event exceeds {MAX_EVENT_BYTES} bytes"),
    )
}
