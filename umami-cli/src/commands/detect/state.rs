//! Locked ownership and atomic persistence of a detector checkpoint.

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use umami::{Detector, ProfileStore};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Settings {
    pub tokenizer: String,
    pub multiline: bool,
    #[serde(deserialize_with = "required_time_format")]
    pub time_format: Option<String>,
    pub tagged: bool,
    pub system: String,
    pub parameters: bool,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum Clock {
    Wall,
    Event,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    #[serde(deserialize_with = "state_format")]
    format: u64,
    tokenizer: String,
    clock: Clock,
    settings: Settings,
    anchors: BTreeMap<String, i64>,
    store: ProfileStore,
}

pub(super) struct State {
    path: PathBuf,
    // The sidecar inode must survive atomic replacement of the checkpoint.
    _lock: File,
    settings: Settings,
}

impl State {
    /// Locks a canonical destination for this process's entire lifetime.
    pub fn open(path: &Path, settings: Settings) -> Result<Self, Box<dyn Error>> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = parent
            .canonicalize()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let path = parent.join(path.file_name().ok_or("state path needs a file name")?);
        if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(format!("{}: state must not be a symlink", path.display()).into());
        }
        let mut lock_path = path.as_os_str().to_owned();
        lock_path.push(".lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)
            .map_err(|e| format!("{}: lock: {e}", path.display()))?;
        lock.try_lock_exclusive()
            .map_err(|e| format!("{}: state lock: {e}", path.display()))?;
        Ok(Self {
            path,
            _lock: lock,
            settings,
        })
    }

    /// Rejects incompatible or malformed input without replacing the file.
    pub fn load(&self) -> Result<(ProfileStore, BTreeMap<String, i64>), Box<dyn Error>> {
        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok((ProfileStore::new(), BTreeMap::new()));
            }
            Err(e) => return Err(format!("{}: {e}", self.path.display()).into()),
        };
        let envelope: Envelope = serde_json::from_reader(BufReader::new(file))
            .map_err(|e| format!("{}: invalid state: {e}", self.path.display()))?;
        let fail = |why: &str| format!("{}: {why}", self.path.display());
        if envelope.tokenizer != self.settings.tokenizer {
            return Err(fail("saved with --tokenizer different from this run").into());
        }
        if envelope.settings != self.settings {
            return Err(fail("state preprocessing settings differ from this run").into());
        }
        if matches!(envelope.clock, Clock::Wall) != envelope.anchors.is_empty() {
            return Err(fail("state clock and anchors disagree").into());
        }
        if envelope
            .anchors
            .values()
            .any(|&t| t > super::wall_clock().saturating_add(86_400))
        {
            return Err(fail("state contains a future timestamp").into());
        }
        Ok((envelope.store, envelope.anchors))
    }

    /// Syncs a unique same-directory temporary file before atomically replacing state.
    pub fn save(&self, det: &Detector, anchors: &BTreeMap<String, i64>) -> io::Result<()> {
        self.save_inner(det, anchors)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", self.path.display())))
    }

    fn save_inner(&self, det: &Detector, anchors: &BTreeMap<String, i64>) -> io::Result<()> {
        let parent = self.path.parent().expect("canonical parent");
        let mut temp = tempfile::NamedTempFile::new_in(parent)?;
        let mut writer = BufWriter::new(temp.as_file_mut());
        serde_json::to_writer(
            &mut writer,
            &serde_json::json!({
                "format": 2,
                "tokenizer": self.settings.tokenizer,
                "clock": if anchors.is_empty() { "wall" } else { "event" },
                "settings": self.settings,
                "anchors": anchors,
                "store": det.store(),
            }),
        )?;
        writer.flush()?;
        drop(writer);
        temp.as_file().sync_all()?;
        temp.persist(&self.path).map_err(|e| e.error)?;
        File::open(parent)?.sync_all()
    }
}

/// Missing optional settings still indicate an incompatible envelope.
fn required_time_format<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    Option::deserialize(deserializer)
}

/// Validate during deserialization so old envelopes receive a migration diagnostic.
fn state_format<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    let version = u64::deserialize(deserializer)?;
    if version != 2 {
        return Err(serde::de::Error::custom(
            "state format must be 2; start with a new state file",
        ));
    }
    Ok(version)
}
