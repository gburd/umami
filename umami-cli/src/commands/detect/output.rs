//! Bounded output with checkpoints still serviced while a consumer stops reading.

use std::io::{self, Write};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};

pub(super) struct Output {
    sender: SyncSender<Vec<u8>>,
    finished: Receiver<io::Result<()>>,
    ready: Receiver<()>,
}

impl Output {
    /// The writer may block in the OS, but never owns detector state or its lock.
    pub fn stdout() -> Self {
        let (sender, receiver) = mpsc::sync_channel::<Vec<u8>>(2);
        let (done, finished) = mpsc::sync_channel(1);
        let (notify, ready) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut stdout = io::stdout().lock();
            let result = (|| {
                for bytes in receiver {
                    let _ = notify.try_send(());
                    stdout.write_all(&bytes)?;
                    stdout.flush()?;
                }
                Ok(())
            })();
            let _ = done.send(result);
        });
        Self {
            sender,
            finished,
            ready,
        }
    }

    /// Waits for queue space without suppressing shutdown or checkpoint deadlines.
    pub fn send(
        &self,
        mut bytes: Vec<u8>,
        mut tick: impl FnMut() -> io::Result<bool>,
    ) -> io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        loop {
            if tick()? {
                return Ok(());
            }
            match self.sender.try_send(bytes) {
                Ok(()) => return Ok(()),
                Err(TrySendError::Full(returned)) => bytes = returned,
                Err(TrySendError::Disconnected(_)) => {
                    return self
                        .finished
                        .recv()
                        .unwrap_or_else(|_| Err(io::Error::other("output worker stopped")));
                }
            }
            let _ = self.ready.recv_timeout(super::input::WAKE);
        }
    }

    /// Drains on normal EOF; shutdown can discard queued output after state is saved.
    pub fn finish(self, mut tick: impl FnMut() -> io::Result<bool>) -> io::Result<()> {
        drop(self.sender);
        loop {
            if tick()? {
                return Ok(());
            }
            match self.finished.recv_timeout(super::input::WAKE) {
                Ok(result) => return result,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::other("output worker stopped"))
                }
            }
        }
    }
}
