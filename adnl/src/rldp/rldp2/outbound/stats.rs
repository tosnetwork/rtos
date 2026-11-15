// Copyright 2017-2020 Telegram Systems LLP
// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Port of RLDP2 Pacer, RttStats, BdwStats, Bbr and LossSender from TOS/TON.
use rand::Rng;

#[derive(Default)]
struct TimedStat {
    current: Option<f64>,
    next: Option<f64>,
    next_at: f64,
}
impl TimedStat {
    fn add(&mut self, value: f64, now: f64, minimum: bool) -> f64 {
        let now = now.max(self.next_at);
        if self.next_at + 10.0 < now {
            self.current = None;
            self.next = None;
            self.next_at = now;
        } else if self.next_at + 5.0 < now {
            self.current = self.next.take();
            self.next_at = now;
        }
        for slot in [&mut self.current, &mut self.next] {
            if slot.is_none_or(|old| if minimum { value < old } else { value > old }) {
                *slot = Some(value);
            }
        }
        self.current.unwrap()
    }
}

pub(super) struct Rtt {
    pub last: f64,
    pub smoothed: f64,
    pub variance: f64,
    pub window_min: f64,
    pub round: u32,
    min: f64,
    round_at: f64,
    window: TimedStat,
}
impl Default for Rtt {
    fn default() -> Self {
        Self {
            last: -1.0,
            smoothed: -1.0,
            variance: -1.0,
            window_min: 0.05,
            round: 0,
            min: -1.0,
            round_at: 0.0,
            window: TimedStat::default(),
        }
    }
}
impl Rtt {
    pub fn sample(&mut self, sample: f64, now: f64) {
        if !(0.001..=10.0).contains(&sample) {
            return;
        }
        self.last = sample.max(0.001);
        self.window_min = self.window.add(self.last, now, true);
        // The connection passes ack_delay=0, as does RldpConnection.cpp.
        if self.smoothed < 0.0 {
            self.min = self.last;
            self.smoothed = self.last;
            self.variance = self.last / 2.0;
        } else {
            self.min = self.min.min(self.last);
            self.smoothed += (self.last - self.smoothed) / 8.0;
            self.variance += ((self.smoothed - self.last).abs() - self.variance) / 4.0;
        }
        if self.round_at + self.smoothed <= now {
            self.round_at = now;
            self.round = self.round.wrapping_add(1);
        }
    }
    pub fn probe_delay(&self, k: u32) -> f64 {
        if self.last < 0.0 {
            0.1
        } else {
            (self.smoothed + self.variance * 4.0 + 0.001) * k as f64
        }
    }
    pub fn loss_delay(&self) -> f64 {
        let rtt = self.last.max(self.smoothed);
        (if rtt < 0.0 { 0.05 } else { rtt }) * 8.0 / 7.0
    }
}

#[derive(Clone, Copy, Default)]
pub(super) struct PacketInfo {
    first_sent: f64,
    delivered_at: f64,
    delivered: u64,
    paused: bool,
}
pub(super) struct Bandwidth {
    pub window_max: f64,
    delivered_at: f64,
    delivered: u64,
    paused_at: f64,
    window: TimedStat,
}
impl Default for Bandwidth {
    fn default() -> Self {
        Self {
            window_max: 100.0,
            delivered_at: 0.0,
            delivered: 0,
            paused_at: 0.0,
            window: TimedStat::default(),
        }
    }
}
impl Bandwidth {
    pub fn sent(&self, first_sent: f64) -> PacketInfo {
        PacketInfo {
            first_sent,
            delivered_at: self.delivered_at,
            delivered: self.delivered,
            paused: self.paused_at != 0.0,
        }
    }
    pub fn ack(&mut self, info: PacketInfo, sent_at: f64, now: f64, delivered: u32) {
        self.delivered_at = now;
        self.delivered = self.delivered.wrapping_add(delivered as u64);
        let effective = info.delivered_at.max(info.first_sent);
        if self.paused_at <= effective {
            self.paused_at = 0.0;
        }
        let passed = (sent_at - info.first_sent).max(now - effective);
        let rate = self.delivered.wrapping_sub(info.delivered) as f64 / passed;
        if !info.paused || rate >= self.window_max {
            self.window_max = self.window.add(rate, now, false);
        }
    }
    pub fn pause(&mut self, now: f64) {
        self.paused_at = now;
    }
}

pub(super) struct Pacer {
    speed: f64,
    capacity: f64,
    capacity_at: f64,
    pub wakeup: f64,
}
impl Default for Pacer {
    fn default() -> Self {
        Self { speed: 10.0, capacity: 20.0, capacity_at: 0.0, wakeup: 0.0 }
    }
}
impl Pacer {
    pub fn set_speed(&mut self, speed: f64) {
        self.speed = speed.max(1.0);
    }
    pub fn send(&mut self, now: f64) {
        if self.capacity_at > 0.0 && self.capacity_at <= now {
            self.capacity = (self.capacity + (now - self.capacity_at) * self.speed)
                .min(40.0_f64.max(self.speed * 0.001));
        }
        self.capacity_at = now;
        if 1.0 < self.capacity {
            self.capacity -= 1.0;
        } else {
            self.wakeup = now + (1.0 - self.capacity) / self.speed;
            self.capacity = 0.0;
            self.capacity_at = self.wakeup;
        }
    }
}

#[derive(Default, PartialEq, Eq)]
enum BbrState {
    #[default]
    Start,
    Drain,
    ProbeBandwidth,
}
pub(super) struct Bbr {
    peak: f64,
    peak_round: u32,
    cycle: usize,
    cycle_at: f64,
    state: BbrState,
    min_rtt: f64,
    max_bandwidth: f64,
}
impl Default for Bbr {
    fn default() -> Self {
        Self {
            peak: -1.0,
            peak_round: 0,
            cycle: 0,
            cycle_at: 0.0,
            state: BbrState::Start,
            min_rtt: 0.0,
            max_bandwidth: 0.0,
        }
    }
}
impl Bbr {
    pub fn step(&mut self, rtt: &Rtt, bandwidth: &Bandwidth, in_flight: u32, now: f64) {
        self.min_rtt = rtt.window_min;
        self.max_bandwidth = bandwidth.window_max;
        if self.max_bandwidth > self.peak * 1.25 {
            self.peak = self.max_bandwidth;
            self.peak_round = rtt.round;
        }
        if self.state == BbrState::Start && self.peak_round.wrapping_add(3) < rtt.round {
            self.state = BbrState::Drain;
        }
        if self.state == BbrState::Drain && (in_flight as f64) < self.max_bandwidth * self.min_rtt {
            self.state = BbrState::ProbeBandwidth;
            self.cycle = rand::thread_rng().gen_range(1..=5);
            self.cycle_at = now;
        }
        if self.state == BbrState::ProbeBandwidth && self.cycle_at + rtt.window_min <= now {
            self.cycle_at = now;
            self.cycle = (self.cycle + 1) % 6;
        }
    }
    pub fn rate(&self) -> f64 {
        // Preserve the reference's operation order: a rounded reciprocal
        // changes the finite Drain pacing rate by one ULP for some inputs.
        match self.state {
            BbrState::Start => self.max_bandwidth * 2.8,
            BbrState::Drain => self.max_bandwidth / 2.8,
            BbrState::ProbeBandwidth => {
                [0.75, 1.0, 1.0, 1.0, 1.0, 1.25][self.cycle] * self.max_bandwidth
            }
        }
    }
    pub fn window(&self) -> u32 {
        let gain = if self.state == BbrState::ProbeBandwidth { 2.0 } else { 2.8 };
        ((self.max_bandwidth * self.min_rtt * gain + 1.0) as u32).max(10)
    }
}

pub(super) struct Loss {
    loss: f64,
    probability_loss: f64,
    ack: u32,
    lost: u32,
    n: usize,
    values: Vec<f64>,
    results: Vec<u32>,
    result_index: usize,
}
impl Default for Loss {
    fn default() -> Self {
        Self {
            loss: 0.1,
            probability_loss: 0.1,
            ack: 0,
            lost: 0,
            n: 0,
            values: vec![1.0, 0.0],
            results: vec![0],
            result_index: 0,
        }
    }
}
impl Loss {
    pub fn update(&mut self, ack: u32, lost: u32) {
        self.ack = self.ack.wrapping_add(ack);
        self.lost = self.lost.wrapping_add(lost);
        let total = self.ack.wrapping_add(self.lost);
        if total > 1000 {
            let loss = (self.lost as f64 / total as f64).clamp(0.001, 0.2);
            if (loss - self.loss).abs() > 0.005 {
                self.probability_loss = loss;
                self.n = 0;
                self.values = vec![1.0, 0.0];
                self.results = vec![0];
                self.result_index = 0;
            }
            self.loss = loss;
            self.ack = 0;
            self.lost = 0;
        }
    }
    pub fn send_n(&mut self, n: u32) -> u32 {
        let loss = self.probability_loss;
        if n >= 50 {
            // Same negative-binomial quantile and search interval as the GSL
            // reference build. Compute the upper tail directly to preserve its
            // 1e-9 threshold without summing a CDF almost equal to one.
            let mean = n as f64 * loss / (1.0 - loss);
            let deviation = (mean / (1.0 - loss)).sqrt();
            let mut low = (mean + deviation) as u32;
            let mut high = low + (deviation + 1.0) as u32 * 15;
            while low + 1 < high {
                let k = (low + high) / 2;
                if 1.0 - negative_binomial_tail(n, k, loss) > 1.0 - 1e-9 {
                    high = k;
                } else {
                    low = k;
                }
            }
            return high + n;
        }
        while self.results.len() <= n as usize {
            self.n += 1;
            self.values.push(0.0);
            self.values[self.n] = self.values[self.n - 1];
            for j in (0..=self.n).rev() {
                self.values[j + 1] += self.values[j] * loss;
                self.values[j] *= 1.0 - loss;
            }
            while self.result_index < self.n && self.values[self.result_index] < 1.0 - 1e-9 {
                self.result_index += 1;
            }
            if self.results.len() == self.n - self.result_index {
                self.results.push(self.n as u32);
            }
        }
        self.results[n as usize]
    }
}

fn negative_binomial_tail(n: u32, k: u32, loss: f64) -> f64 {
    let first = k + 1;
    let mut log_mass = n as f64 * (-loss).ln_1p() + first as f64 * loss.ln();
    for j in 1..=first {
        log_mass += ((n as f64 + j as f64 - 1.0) / j as f64).ln();
    }
    let mut mass = log_mass.exp();
    let mut sum = mass;
    let mut j = first;
    loop {
        mass *= loss * (n as f64 + j as f64) / (j as f64 + 1.0);
        let next = sum + mass;
        if next == sum {
            return sum;
        }
        sum = next;
        j += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loss_quantile_matches_gsl_reference_at_algorithm_boundary() {
        // Literal outputs of actual TOS1181 LossStats/LossSender, GSL enabled.
        let cases = [
            (0, 0, 1, 9),
            (0, 0, 5, 17),
            (0, 0, 49, 76),
            (0, 0, 50, 77),
            (0, 0, 100, 139),
            (10000, 1, 49, 54),
            (10000, 1, 50, 55),
            (10000, 2500, 49, 93),
            (10000, 2500, 50, 95),
            (10000, 2500, 119, 194),
        ];
        for (ack, lost, n, expected) in cases {
            let mut loss = Loss::default();
            loss.update(ack, lost);
            assert_eq!(loss.send_n(n), expected, "{ack}/{lost}/{n}");
        }
    }

    #[test]
    fn pacer_and_timed_windows_keep_cpp_equality_boundaries() {
        let mut pacer = Pacer::default();
        pacer.set_speed(280.0);
        for _ in 0..20 {
            pacer.send(1.0);
        }
        assert_eq!(pacer.wakeup, 1.0);
        pacer.send(1.0);
        assert_eq!(pacer.wakeup, 1.0 + 1.0 / 280.0);
        let mut stat = TimedStat::default();
        assert_eq!(stat.add(4.0, 1.0, true), 4.0);
        assert_eq!(stat.add(8.0, 5.0, true), 4.0);
        assert_eq!(stat.add(9.0, 5.01, true), 4.0);
        assert_eq!(stat.add(10.0, 10.02, true), 9.0);
        assert_eq!(stat.add(11.0, 20.03, true), 11.0);
    }

    #[test]
    fn drain_rate_preserves_cpp_division_rounding() {
        // Actual clean TOS1181 Bbr::step/get_rate bits, independently recorded
        // in net07/review-e55fdcde/rate-cpp.txt. Round4 remains in Drain:
        // in_flight1000 exceeds every tested bandwidth-delay product.
        let cases = [
            (3.0, 0x3ff1249249249249u64),
            (7.0, 0x4004000000000000),
            (17.0, 0x4018492492492493),
            (99.0, 0x4041adb6db6db6dc),
            (100.0, 0x4041db6db6db6db7),
            (101.0, 0x4042092492492493),
            (1000.0, 0x4076524924924925),
        ];
        for (bandwidth, expected) in cases {
            let mut rtt = Rtt::default();
            let mut bdw = Bandwidth::default();
            bdw.window_max = bandwidth;
            let mut bbr = Bbr::default();
            bbr.step(&rtt, &bdw, 1000, 1000.0);
            rtt.round = 4;
            bbr.step(&rtt, &bdw, 1000, 1001.0);
            assert!(bbr.state == BbrState::Drain);
            assert_eq!(bbr.rate().to_bits(), expected, "bandwidth={bandwidth}");
        }
    }
}
