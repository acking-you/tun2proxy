use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Write},
    net::IpAddr,
    path::{Path, PathBuf},
};

const CACHE_VERSION: u8 = 1;
const COMPACT_STALE_RECORDS: usize = 1024;

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum OwnedCacheRecord {
    Header {
        version: u8,
        network_addr: IpAddr,
        broadcast_addr: IpAddr,
        allocation_cursor: IpAddr,
    },
    Mapping {
        ip: IpAddr,
        name: String,
    },
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum BorrowedCacheRecord<'a> {
    Header {
        version: u8,
        network_addr: IpAddr,
        broadcast_addr: IpAddr,
        allocation_cursor: IpAddr,
    },
    Mapping {
        ip: IpAddr,
        name: &'a str,
    },
}

pub(super) enum LoadResult {
    Missing,
    Incompatible,
    Loaded {
        allocation_cursor: IpAddr,
        mappings: Vec<(IpAddr, String)>,
        repair_needed: bool,
    },
}

pub(super) struct PersistentCache {
    path: PathBuf,
    journal_records: usize,
    dirty: bool,
}

impl PersistentCache {
    pub(super) fn new(path: PathBuf) -> Self {
        Self {
            path,
            journal_records: 0,
            dirty: false,
        }
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn load(&mut self, network_addr: IpAddr, broadcast_addr: IpAddr) -> Result<LoadResult> {
        self.journal_records = 0;
        self.dirty = false;
        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(LoadResult::Missing),
            Err(error) => return Err(error.into()),
        };
        let mut lines = BufReader::new(file).lines();
        let allocation_cursor = match lines.next() {
            Some(Ok(line)) => match serde_json::from_str::<OwnedCacheRecord>(&line) {
                Ok(OwnedCacheRecord::Header {
                    version,
                    network_addr: cached_network,
                    broadcast_addr: cached_broadcast,
                    allocation_cursor,
                }) if version == CACHE_VERSION
                    && cached_network == network_addr
                    && cached_broadcast == broadcast_addr
                    && address_in_pool(allocation_cursor, network_addr, broadcast_addr) =>
                {
                    allocation_cursor
                }
                _ => return Ok(LoadResult::Incompatible),
            },
            _ => return Ok(LoadResult::Incompatible),
        };

        let mut mappings = Vec::new();
        let mut repair_needed = false;
        for line in lines {
            let line = match line {
                Ok(line) => line,
                Err(_) => {
                    repair_needed = true;
                    break;
                }
            };
            if line.is_empty() {
                repair_needed = true;
                continue;
            }
            match serde_json::from_str::<OwnedCacheRecord>(&line) {
                Ok(OwnedCacheRecord::Mapping { ip, name }) => {
                    self.journal_records = self.journal_records.saturating_add(1);
                    mappings.push((ip, name));
                }
                _ => repair_needed = true,
            }
        }
        Ok(LoadResult::Loaded {
            allocation_cursor,
            mappings,
            repair_needed,
        })
    }

    pub(super) fn needs_rewrite(&self) -> Result<bool> {
        if self.dirty {
            return Ok(true);
        }
        match self.path.metadata() {
            Ok(metadata) => Ok(metadata.len() == 0),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error.into()),
        }
    }

    pub(super) fn append_mapping(&mut self, ip: IpAddr, name: &str) -> Result<()> {
        let mut file = OpenOptions::new().create(true).append(true).open(&self.path)?;
        write_cache_record(&mut file, &BorrowedCacheRecord::Mapping { ip, name })?;
        file.flush()?;
        self.journal_records = self.journal_records.saturating_add(1);
        self.dirty = false;
        Ok(())
    }

    pub(super) fn should_compact(&self, live_mappings: usize) -> bool {
        let stale_records = self.journal_records.saturating_sub(live_mappings);
        stale_records >= COMPACT_STALE_RECORDS && self.journal_records >= live_mappings.saturating_mul(2)
    }

    pub(super) fn rewrite<'a>(
        &mut self,
        network_addr: IpAddr,
        broadcast_addr: IpAddr,
        allocation_cursor: IpAddr,
        mappings: impl IntoIterator<Item = (IpAddr, &'a str)>,
    ) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temporary = temporary_path(&self.path);
        let file = File::create(&temporary)?;
        let mut writer = BufWriter::new(file);
        write_cache_record(
            &mut writer,
            &BorrowedCacheRecord::Header {
                version: CACHE_VERSION,
                network_addr,
                broadcast_addr,
                allocation_cursor,
            },
        )?;
        let mut records = 0_usize;
        for (ip, name) in mappings {
            write_cache_record(&mut writer, &BorrowedCacheRecord::Mapping { ip, name })?;
            records = records.saturating_add(1);
        }
        writer.flush()?;
        drop(writer);
        replace_file(&temporary, &self.path)?;
        self.journal_records = records;
        self.dirty = false;
        Ok(())
    }

    pub(super) fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub(super) fn mark_dirty(&mut self) {
        self.dirty = true;
    }
}

fn address_in_pool(ip: IpAddr, network_addr: IpAddr, broadcast_addr: IpAddr) -> bool {
    ip.is_ipv4() == network_addr.is_ipv4() && ip >= network_addr && ip <= broadcast_addr
}

fn write_cache_record(writer: &mut impl Write, record: &BorrowedCacheRecord<'_>) -> Result<()> {
    serde_json::to_writer(&mut *writer, record).map_err(|error| error.to_string())?;
    writer.write_all(b"\n")?;
    Ok(())
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_owned();
    value.push(".tmp");
    PathBuf::from(value)
}

fn replace_file(temporary: &Path, destination: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    if destination.exists() {
        fs::remove_file(destination)?;
    }
    fs::rename(temporary, destination)
}
