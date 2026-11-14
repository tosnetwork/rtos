// Copyright 2017-2020 Telegram Systems LLP
// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Indexed four-ary timer heap, preserving td::KHeap's equality ordering.
use std::collections::BTreeMap;

#[derive(Clone)]
struct Timer<K> {
    deadline: f64,
    key: K,
}

pub(crate) struct TimerHeap<K: Ord + Clone> {
    entries: Vec<Timer<K>>,
    positions: BTreeMap<K, usize>,
}
impl<K: Ord + Clone> Default for TimerHeap<K> {
    fn default() -> Self {
        Self { entries: Vec::new(), positions: BTreeMap::new() }
    }
}
impl<K: Ord + Clone> TimerHeap<K> {
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn insert(&mut self, key: K, deadline: f64) -> bool {
        if !deadline.is_finite() || deadline <= 0.0 || self.positions.contains_key(&key) {
            return false;
        }
        let pos = self.entries.len();
        self.entries.push(Timer { deadline, key });
        self.fix_up(pos);
        true
    }
    pub fn peek(&self) -> Option<(f64, &K)> {
        self.entries.first().map(|timer| (timer.deadline, &timer.key))
    }
    pub fn erase(&mut self, key: &K) -> Option<f64> {
        let pos = self.positions.remove(key)?;
        let removed = self.entries.swap_remove(pos);
        if pos < self.entries.len() {
            // KHeap restores at this original position in both directions,
            // including after fix_down moved the replacement farther down.
            self.fix_down(pos);
            self.fix_up(pos);
        }
        Some(removed.deadline)
    }
    pub fn pop_due(&mut self, now: f64) -> Option<(K, f64)> {
        let (deadline, key) = self.peek()?;
        if deadline > now {
            return None;
        }
        let key = key.clone();
        self.erase(&key);
        Some((key, deadline))
    }
    fn put(&mut self, pos: usize, item: Timer<K>) {
        self.positions.insert(item.key.clone(), pos);
        self.entries[pos] = item;
    }
    fn fix_up(&mut self, mut pos: usize) {
        let item = self.entries[pos].clone();
        while pos != 0 {
            let parent = (pos - 1) / 4;
            if self.entries[parent].deadline < item.deadline {
                break;
            }
            self.put(pos, self.entries[parent].clone());
            pos = parent;
        }
        self.put(pos, item);
    }
    fn fix_down(&mut self, mut pos: usize) {
        let item = self.entries[pos].clone();
        loop {
            let left = pos * 4 + 1;
            let right = self.entries.len().min(left + 4);
            let mut next = pos;
            let mut next_deadline = item.deadline;
            for i in left..right {
                if self.entries[i].deadline < next_deadline {
                    next = i;
                    next_deadline = self.entries[i].deadline;
                }
            }
            if next == pos {
                break;
            }
            self.put(pos, self.entries[next].clone());
            pos = next;
        }
        self.put(pos, item);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn equal_deadlines_follow_four_ary_heap_order() {
        let mut heap = TimerHeap::default();
        for key in 1..=6 {
            assert!(heap.insert(key, 5.0));
        }
        assert!(!heap.insert(2, 6.0));
        assert!(!heap.insert(7, f64::NAN));
        assert_eq!(heap.len(), 6);
        assert_eq!(heap.pop_due(4.0), None);
        let order: Vec<_> = std::iter::from_fn(|| heap.pop_due(5.0)).map(|(k, _)| k).collect();
        assert_eq!(order, vec![6, 1, 4, 3, 2, 5]);
        assert!(heap.is_empty());
    }
    #[test]
    fn erase_and_restore_preserve_positions_without_stale_entries() {
        let mut heap = TimerHeap::default();
        for key in 0..100 {
            assert!(heap.insert(key, 1.0 + (key % 7) as f64));
        }
        for key in (0..100).step_by(3) {
            assert!(heap.erase(&key).is_some());
        }
        for key in (0..100).step_by(3) {
            assert!(heap.erase(&key).is_none());
        }
        let mut prev = 0.0;
        let mut count = 0;
        while let Some((key, deadline)) = heap.pop_due(10.0) {
            assert!(deadline >= prev);
            assert_ne!(key % 3, 0);
            prev = deadline;
            count += 1;
        }
        assert_eq!(count, 66);
        assert!(heap.positions.is_empty());
    }
}
