// Copyright 2017-2020 Telegram Systems LLP
// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Online-code generation and belief propagation, following td/fec/online.
use super::Parameters;

fn xor(target: &mut [u8], source: &[u8]) {
    for (a, b) in target.iter_mut().zip(source) {
        *a ^= b;
    }
}

struct Random([u64; 2]);
impl Random {
    fn new(mut seed: u64) -> Self {
        let mut next = || {
            seed = seed.wrapping_add(0x9e3779b97f4a7c15);
            let mut z = seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
            z ^ (z >> 31)
        };
        Self([next(), next()])
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0[0];
        let y = self.0[1];
        self.0[0] = y;
        x ^= x << 23;
        self.0[1] = x ^ y ^ (x >> 17) ^ (y >> 26);
        self.0[1].wrapping_add(y)
    }
}

struct Code {
    sources: usize,
    outer: usize,
    distribution: Vec<f64>,
}
impl Code {
    fn new(p: Parameters) -> Self {
        let sources = p.symbols_count as usize;
        Self {
            sources,
            outer: (1.0 + 0.55 * 3.0 * 0.001 * sources as f64) as usize,
            distribution: Self::degree_distribution(),
        }
    }
    fn outer_rows(&self) -> Vec<Vec<usize>> {
        let mut rows = (0..self.outer).map(|i| vec![self.sources + i]).collect::<Vec<_>>();
        let mut random = Random::new(1);
        for i in 0..self.sources {
            for _ in 0..3 {
                rows[(random.next() % self.outer as u64) as usize].push(i);
            }
        }
        rows
    }
    fn degree_distribution() -> Vec<f64> {
        let epsilon: f64 = 0.001;
        let count =
            ((epsilon * epsilon / 4.0).ln() / (1.0 - epsilon / 2.0).ln() + 1.0 - 1e-9) as usize;
        let x = 1.0 - (1.0 + 1.0 / count as f64) / (1.0 + epsilon);
        let mut p = Vec::with_capacity(count);
        p.push(x);
        for i in 2..=count {
            let y = (1.0 - x) * count as f64 / ((count as f64 - 1.0) * i as f64 * (i - 1) as f64);
            p.push(p.last().unwrap() + y);
        }
        p
    }
    fn inner_row(&self, id: u32) -> Vec<usize> {
        let mut random = Random::new(id as u64);
        let x = (random.next() % (1 << 20)) as f64 / (1 << 20) as f64;
        let degree =
            self.distribution.iter().position(|p| x < *p).expect("online degree distribution") + 1;
        // Repeated indices remain separate edges, as in the reference implementation.
        (0..degree).map(|_| (random.next() % (self.sources + self.outer) as u64) as usize).collect()
    }
}

pub(super) struct Encoder {
    code: Code,
    symbols: Vec<Vec<u8>>,
    size: usize,
}
impl Encoder {
    pub(super) fn new(data: &[u8], p: Parameters) -> Self {
        let code = Code::new(p);
        let size = p.symbol_size as usize;
        let mut symbols = vec![vec![0; size]; code.sources + code.outer];
        for (i, chunk) in data.chunks(size).enumerate() {
            symbols[i][..chunk.len()].copy_from_slice(chunk);
        }
        for (i, row) in code.outer_rows().into_iter().enumerate() {
            let mut data = vec![0; size];
            for source in row.into_iter().skip(1) {
                xor(&mut data, &symbols[source]);
            }
            symbols[code.sources + i] = data;
        }
        Self { code, symbols, size }
    }
    pub(super) fn symbol(&self, id: u32) -> Vec<u8> {
        let mut data = vec![0; self.size];
        for i in self.code.inner_row(id) {
            xor(&mut data, &self.symbols[i]);
        }
        data
    }
}

struct Equation {
    left: usize,
    symbols_xor: usize,
    data: Vec<u8>,
}
pub(super) struct Decoder {
    code: Code,
    symbols: Vec<Option<Vec<u8>>>,
    links: Vec<Vec<usize>>,
    equations: Vec<Equation>,
    ready: Vec<usize>,
    known: usize,
    sources_known: usize,
}
impl Decoder {
    pub(super) fn new(p: Parameters) -> Self {
        let code = Code::new(p);
        let count = code.sources + code.outer;
        let outer_rows = code.outer_rows();
        let mut decoder = Self {
            code,
            symbols: vec![None; count],
            links: vec![Vec::new(); count],
            equations: Vec::new(),
            ready: Vec::new(),
            known: 0,
            sources_known: 0,
        };
        for row in outer_rows {
            decoder.add_equation(row, vec![0; p.symbol_size as usize]);
        }
        decoder
    }
    pub(super) fn add_symbol(&mut self, id: u32, data: Vec<u8>) {
        self.add_equation(self.code.inner_row(id), data);
    }
    fn add_equation(&mut self, row: Vec<usize>, mut data: Vec<u8>) {
        let mut equation = Equation { left: 0, symbols_xor: 0, data: Vec::new() };
        let id = self.equations.len();
        for i in row {
            if let Some(symbol) = &self.symbols[i] {
                xor(&mut data, symbol);
            } else {
                equation.left += 1;
                equation.symbols_xor ^= i;
                self.links[i].push(id);
            }
        }
        if equation.left == 0 {
            return;
        }
        let immediate = equation.left == 1;
        equation.data = data;
        self.equations.push(equation);
        if immediate {
            self.ready.push(id);
            self.propagate();
        }
    }
    fn propagate(&mut self) {
        while self.known < self.symbols.len() {
            let Some(id) = self.ready.pop() else {
                break;
            };
            let equation = &self.equations[id];
            if equation.left == 0 {
                continue;
            }
            assert_eq!(equation.left, 1);
            let symbol = equation.symbols_xor;
            if self.symbols[symbol].is_some() {
                continue;
            }
            let data = equation.data.clone();
            // Reference linked lists visit the most recently inserted edge first.
            for &next in self.links[symbol].iter().rev() {
                let e = &mut self.equations[next];
                xor(&mut e.data, &data);
                e.symbols_xor ^= symbol;
                e.left -= 1;
                if e.left == 1 {
                    self.ready.push(next);
                }
            }
            self.symbols[symbol] = Some(data);
            self.known += 1;
            if symbol < self.code.sources {
                self.sources_known += 1;
            }
        }
    }
    pub(super) fn is_ready(&self) -> bool {
        self.sources_known == self.code.sources
    }
    pub(super) fn data(&self, size: usize) -> Vec<u8> {
        assert!(self.is_ready());
        let mut data = Vec::with_capacity(size);
        for symbol in self.symbols[..self.code.sources].iter() {
            let symbol = symbol.as_ref().unwrap();
            data.extend_from_slice(&symbol[..symbol.len().min(size - data.len())]);
        }
        data
    }
}
