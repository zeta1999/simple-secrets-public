use secure_memory::LockedBuffer;
use std::collections::HashMap;

pub struct RamStore {
    entries: HashMap<String, LockedBuffer>,
}

impl Default for RamStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RamStore {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn set(&mut self, name: &str, value: LockedBuffer) {
        self.entries.insert(name.to_string(), value);
    }

    pub fn get(&self, name: &str) -> Option<&LockedBuffer> {
        self.entries.get(name)
    }

    pub fn delete(&mut self, name: &str) {
        self.entries.remove(name);
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}
