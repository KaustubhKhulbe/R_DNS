use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::{fs, io, thread};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::utils::query_type::QueryType;
use crate::utils::record::DnsRecord;
use crate::recursive_lookup;
use crate::utils::byte_buffer::ByteBuffer;
use crate::utils::packet::DnsPacket;

use log::{info, warn};
use toml::Value;
use crate::io::Result;

#[derive(Clone, Debug, PartialEq)]
pub struct DnsCacheEntry {
    pub response: [u8; 512],
    pub expiry: u64,
    pub ttl: u32,
}

impl DnsCacheEntry {
    pub fn new(response: [u8; 512], expiry: u64, ttl: u64) -> DnsCacheEntry {
        DnsCacheEntry {
            response,
            expiry,
            ttl: ttl as u32,
        }
    }

    pub fn from_packet(packet: &DnsPacket, ttl: u32) -> Result<DnsCacheEntry> {
        let mut buffer = ByteBuffer::new();
        packet.write(&mut buffer).unwrap();
        Ok(DnsCacheEntry {
            response: buffer.buffer,
            expiry: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + ttl as u64,
            ttl,
        })
    }

    pub fn is_expired(&self) -> bool {
        self.expiry < SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    pub fn update(&mut self, packet: &DnsPacket, ttl: u32) -> Result<()>{
        let mut buffer = ByteBuffer::new();
        packet.write(&mut buffer).unwrap();
        self.response = buffer.buffer;
        self.expiry = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + ttl as u64;
        Ok(())
    }

    pub fn get_packet(&self) -> Result<DnsPacket> {
        let mut buffer = ByteBuffer::from_buffer(&self.response);
        DnsPacket::from_buffer(&mut buffer)
    }

    pub fn to_toml(&self) -> Value {
        let mut map = toml::map::Map::new();
        
        // Convert `[u8; 512]` to an array of integers (u32) for TOML serialization
        let response_array = self.response.iter().map(|&x| Value::Integer(x as i64)).collect();
        
        map.insert("response".into(), Value::Array(response_array));
        map.insert("expiry".into(), Value::Integer(self.expiry as i64));
        map.insert("ttl".into(), Value::Integer(self.ttl as i64));
        
        Value::Table(map)
    }

    pub fn from_toml(value: &toml::Value) -> Option<DnsCacheEntry> {
        if let Some(table) = value.as_table() {
            let response: Vec<u8> = table
                .get("response")?
                .as_array()?
                .iter()
                .map(|v| v.as_integer().and_then(|x| x.try_into().ok()).unwrap_or(0))
                .collect();
    
            if response.len() != 512 {
                return None; // Handle error if response size doesn't match expected length
            }
    
            let expiry = table.get("expiry")?.as_integer()?.try_into().ok()?;
            let ttl = table.get("ttl")?.as_integer()?.try_into().ok()?;
    
            let mut response_array: [u8; 512] = [0; 512];
            response_array.copy_from_slice(&response);
    
            Some(DnsCacheEntry {
                response: response_array,
                expiry,
                ttl,
            })
        } else {
            None
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct DnsCache {
    pub cache: HashMap<String, DnsCacheEntry>,
    pub order: VecDeque<String>,
    max_size: usize,
}

impl DnsCache {
    pub fn new(max_size: usize) -> DnsCache {
        DnsCache {
            cache: HashMap::new(),
            order: VecDeque::new(),
            max_size,
        }
    }

    pub fn insert(&mut self, key: String, entry: DnsCacheEntry) -> Result<()>{
        if (self.cache.get(key.as_str())).is_some() {
            return Ok(()); // Already exists
        }

        if self.cache.len() >= self.max_size {
            let oldest = self.order.pop_front().unwrap();
            self.cache.remove(&oldest);
            warn!("Evicting oldest entry: {}", oldest)
        }
        self.cache.insert(key.clone(), entry);
        self.order.push_back(key);

        Ok(())
    }
    
    pub fn get(&mut self, key: &str) -> Option<&DnsCacheEntry> {
        // First, perform an immutable lookup to check if the entry exists
        if let Some(entry) = self.cache.get(key) {
            if entry.is_expired() {
                // If the entry is expired, perform mutable operations to remove it
                self.cache.remove(key);
                self.order.retain(|x| x != key);
                return None;
            }
            // If the entry is valid, convert to a mutable reference
            let entry_ptr = self.cache.get_mut(key).unwrap();
            return Some(entry_ptr);
        }
        None
    }


    pub fn update(&mut self, key: &str, packet: &DnsPacket, ttl: u32) -> Result<()>{
        if let Some(entry) = self.cache.get_mut(key) {
            entry.update(packet, ttl)?;
        }
        Ok(())
    }

    pub fn update_expired(&mut self) -> Result<()> {
        let mut expired_keys = Vec::new();
    
        // First collect all keys with expired entries to avoid mutating the cache while iterating
        for (key, entry) in self.cache.iter() {
            if entry.is_expired() {
                expired_keys.push(key.clone());
            }
        }
    
        // Update each expired entry
        for key in expired_keys {
            if let Some(entry) = self.cache.get_mut(&key) {

                let name = key.split("-").next().unwrap();
                let qtype = QueryType::from_num(key.split("-").last().unwrap().parse::<u16>().unwrap());
                let res_packet = match recursive_lookup(&name, qtype) {
                    Ok(packet) => packet,
                    Err(_) => continue, // Skip if the recursive lookup fails
                };
    
                if res_packet.answers.is_empty() {
                    continue;
                }
    
                let ttl = match res_packet.answers.get(0).unwrap() {
                    DnsRecord::A { ttl, .. } => *ttl,
                    DnsRecord::AAAA { ttl, .. } => *ttl,
                    DnsRecord::CNAME { ttl, .. } => *ttl,
                    DnsRecord::NS { ttl, .. } => *ttl,
                    DnsRecord::MX { ttl, .. } => *ttl,
                    DnsRecord::UNKNOWN { ttl, .. } => *ttl,
                };
    
                entry.update(&res_packet, ttl)?;
            }
        }
    
        Ok(())
    }

    pub fn to_toml(&self) -> Value {
        let mut map = toml::map::Map::new();

        // Convert cache entries to TOML format
        let entries: toml::map::Map<String, Value> = self.cache.iter()
            .map(|(key, entry)| (key.clone(), entry.to_toml()))
            .collect();

        map.insert("cache".to_string(), Value::Table(entries));

        // Convert order to TOML format
        let order_array: Vec<Value> = self.order.iter().map(|s| Value::String(s.clone())).collect();
        map.insert("order".to_string(), Value::Array(order_array));

        // Insert max_size
        map.insert("max_size".to_string(), Value::Integer(self.max_size as i64));

        Value::Table(map)
    }

    pub fn save_to_toml(&self, path: impl AsRef<Path>) -> Result<()> {
        let toml_content = self.to_toml();
        let toml_string = toml::to_string(&toml_content).unwrap();

        fs::write(path, toml_string)?;

        Ok(())
    }

    pub fn from_toml(value: &Value) -> Option<DnsCache> {
        if let Some(table) = value.as_table() {
            let cache_table = table.get("cache")?.as_table()?;
            let cache = cache_table.iter().filter_map(|(key, value)| {
                DnsCacheEntry::from_toml(value).map(|entry| (key.clone(), entry))
            }).collect::<HashMap<String, DnsCacheEntry>>();
            let order = table.get("order")?.as_array()?.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect::<VecDeque<String>>();
            let max_size = table.get("max_size")?.as_integer()?.try_into().ok()?;
            Some(DnsCache { cache, order, max_size })
        } else {
            None
        }
    }

    pub fn load_from_toml(path: impl AsRef<Path>) -> Result<DnsCache> {
        let toml_string = fs::read_to_string(path)?;
        let value = toml::from_str(&toml_string)?;
        DnsCache::from_toml(&value).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid TOML format"))
        
    }
    
}

// Thread-safe DnsCache with automatic expiration update thread
#[derive(Clone)]
pub struct ThreadSafeDnsCache {
    pub cache: Arc<Mutex<DnsCache>>,
}

impl ThreadSafeDnsCache {
    pub fn new(max_size: usize, update_interval: Duration, cache_store_interval: Duration, path: impl AsRef<Path>) -> ThreadSafeDnsCache {
        let cache = Arc::new(Mutex::new(match DnsCache::load_from_toml(path) {
            Ok(cache) => {
                println!("Cache loaded from file");
                cache
            },
            Err(_) => DnsCache::new(max_size),
        }));

        cache.lock().unwrap().max_size = max_size;

        let cache_clone = Arc::clone(&cache);

        let cache_clone_2 = Arc::clone(&cache);
        // Spawn a thread to periodically update expired entries
        thread::spawn(move || {
            println!("Starting cache update thread");
            loop {
                {
                    let mut cache = cache_clone.lock().unwrap();
                    if let Err(e) = cache.update_expired() {
                        eprintln!("Failed to update expired entries: {:?}", e);
                    }
                }
                thread::sleep(update_interval);
            }
        });

        thread::spawn(move || {
            loop {
                {
                    let cache = cache_clone_2.lock().unwrap();
                    info!("Saving cache to file");
                    if let Err(e) = cache.save_to_toml("dns_cache.toml") {
                        eprintln!("Failed to save cache to file: {:?}", e);
                    }
                }
                thread::sleep(cache_store_interval);
            }
        });

        let res = ThreadSafeDnsCache { cache };
        info!("Cache successfully initialized with max size: {} and update interval: {:?}", max_size, update_interval);

        res
    }

    pub fn insert(&self, key: String, entry: DnsCacheEntry) -> Result<()> {
        let mut cache = self.cache.lock().unwrap();
        cache.insert(key, entry)
    }

    pub fn get(&self, key: &str) -> Option<DnsCacheEntry> {
        let mut cache = self.cache.lock().unwrap();
        cache.get(key).cloned()
    }

    pub fn update(&self, key: &str, packet: &DnsPacket, ttl: u32) -> Result<()> {
        let mut cache = self.cache.lock().unwrap();
        cache.update(key, packet, ttl)
    }
}

impl Drop for ThreadSafeDnsCache {
    fn drop(&mut self) {
        info!("Saving cache to file");
        self.cache.lock().unwrap().save_to_toml("dns_cache.toml").unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::{packet::DnsPacket, query_type::QueryType, question::DnsQuestion};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn create_test_packet() -> DnsPacket {
        // Create a mock DNS packet for testing
        DnsPacket {
            header: Default::default(),
            questions: vec![DnsQuestion {
                name: "google.com".to_string(),
                qtype: QueryType::A,
            }],
            answers: vec![],
            authorities: vec![],
            resources: vec![],
        }
    }

    fn create_test_entry(ttl: u32) -> DnsCacheEntry {
        let packet = create_test_packet();
        DnsCacheEntry::from_packet(&packet, ttl).unwrap()
    }

    #[test]
    fn test_create_entry() {
        let ttl = 60;
        let entry = create_test_entry(ttl);

        assert_eq!(entry.response.len(), 512);
        assert_eq!(entry.expiry, SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + ttl as u64);
    }

    #[test]
    fn test_insert_and_get() {
        let mut cache = DnsCache::new(2);
        let ttl = 60;
        let entry = create_test_entry(ttl);

        cache.insert("example.com".to_string(), entry.clone()).unwrap();

        let cached_entry = cache.get("example.com").unwrap();
        assert_eq!(cached_entry, &entry);
    }

    #[test]
    fn test_expired_entry() {
        let mut cache = DnsCache::new(2);
        let ttl = 1; // 1 second TTL for quick expiry
        let entry = create_test_entry(ttl);

        cache.insert("example.com".to_string(), entry.clone()).unwrap();

        std::thread::sleep(Duration::from_secs(2)); // Wait for entry to expire

        assert!(cache.get("example.com").is_none());
    }

    #[test]
    fn test_update_entry() {
        let mut cache = DnsCache::new(2);
        let ttl = 60;
        let entry = create_test_entry(ttl);
        let mut packet = create_test_packet();
        packet.answers.push(DnsRecord::A { domain: "example.com".to_string(), addr: [127, 0, 0, 1].into(), ttl });

        cache.insert("example.com".to_string(), entry.clone()).unwrap();
        cache.update("example.com", &packet, ttl).unwrap();

        let cached_entry = cache.get("example.com").unwrap();
        assert_eq!(cached_entry.response[..], packet.write_to_bytes().unwrap()[..]);
    }

    #[test]
    fn test_eviction_policy() {
        let mut cache = DnsCache::new(2);
        let ttl = 60;
        let entry1 = create_test_entry(ttl);
        let entry2 = create_test_entry(ttl);
        let entry3 = create_test_entry(ttl);

        cache.insert("example1.com".to_string(), entry1).unwrap();
        cache.insert("example2.com".to_string(), entry2).unwrap();
        cache.insert("example3.com".to_string(), entry3).unwrap(); // This should evict the oldest entry (example1.com)

        assert!(cache.get("example1.com").is_none());
        assert!(cache.get("example2.com").is_some());
        assert!(cache.get("example3.com").is_some());
    }

    // todo: test update_expired
    #[test]
    fn test_update_expired() {
        let mut cache = DnsCache::new(2);
        let ttl = 1; // 1 second TTL for quick expiry
        let entry = create_test_entry(ttl);

        cache.insert("google.com".to_string(), entry.clone()).unwrap();
        assert!(cache.get("google.com").is_some());

        std::thread::sleep(Duration::from_secs(2)); // Wait for entry to expire

        cache.update_expired().unwrap();
    }
}
