use std::collections::{HashMap, VecDeque};

pub const MIB: u64 = 1 << 20;
#[derive(Clone, Copy, Hash, Eq, PartialEq, Debug)]
pub struct Identity {
    pub pid: u32,
    pub born: u64,
}

#[derive(Default)]
pub struct History(VecDeque<(u64, u64)>);

impl History {
    pub fn add(&mut self, time: u64, value: u64) {
        if let Some(&(last, _)) = self.0.back() {
            if time.saturating_sub(last) > 90 {
                self.0.clear();
            } else if time <= last {
                return;
            }
        }
        self.0.push_back((time, value));
        while self.0.len() > 61 || time - self.0[0].0 > 600 {
            self.0.pop_front();
        }
    }
    pub fn ready(&self) -> bool {
        self.0.len() >= 7 && self.0.back().unwrap().0 - self.0[0].0 >= 60
    }
    pub fn finding(&self) -> Option<String> {
        if !self.ready() {
            return None;
        }
        let (start, a) = self.0[0];
        let (end, b) = *self.0.back()?;
        let n = self.0.len() - 1;
        let duration = end - start;
        // Require gains in each third and a mostly upward path, not just a large endpoint delta.
        let cuts = [0, n / 3, 2 * n / 3, n];
        let gain = b.checked_sub(a)?;
        let travel: u64 = self
            .0
            .iter()
            .zip(self.0.iter().skip(1))
            .map(|(x, y)| x.1.abs_diff(y.1))
            .sum();
        let rate = gain as f64 * 60.0 / duration as f64 / MIB as f64;
        if rate < 1.0
            || gain < 6 * MIB
            || (gain as f64) < 0.7 * travel as f64
            || !cuts
                .windows(2)
                .all(|w| self.0[w[1]].1.saturating_sub(self.0[w[0]].1) >= MIB)
        {
            return None;
        }
        let lo = self.0.iter().map(|x| x.1).min()?;
        let hi = self.0.iter().map(|x| x.1).max()?;
        let bars = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
        let graph: String = (0..=12)
            .map(|i| bars[((self.0[i * n / 12].1 - lo) * 7 / (hi - lo)) as usize])
            .collect();
        Some(format!(
            "{graph}    {duration} s    {:.1} → {:.1} MiB    +{rate:.2} MiB/min\r\n    Gained ≥1 MiB in each of three windows; net gain ≥70% of all movement.",
            a as f64 / MIB as f64,
            b as f64 / MIB as f64
        ))
    }
}

#[derive(Default)]
pub struct Trends(pub HashMap<Identity, History>);
impl Trends {
    pub fn update(&mut self, time: u64, values: impl Iterator<Item = (Identity, u64)>) {
        let mut previous = std::mem::take(&mut self.0);
        for (id, value) in values.take(32768) {
            let mut h = previous.remove(&id).unwrap_or_default();
            h.add(time, value);
            self.0.insert(id, h);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn series(values: [u64; 7]) -> History {
        let mut h = History::default();
        for (i, v) in values.into_iter().enumerate() {
            h.add(i as u64 * 10, v * MIB)
        }
        h
    }
    #[test]
    fn sustained() {
        assert!(series([20, 22, 24, 26, 28, 30, 32]).finding().is_some())
    }
    #[test]
    fn plateau() {
        assert!(series([20, 20, 60, 60, 60, 60, 60]).finding().is_none())
    }
    #[test]
    fn sawtooth() {
        assert!(series([20, 40, 21, 41, 22, 42, 27]).finding().is_none())
    }
    #[test]
    fn pid_reuse() {
        let mut t = Trends::default();
        for i in 0..8 {
            t.update(
                i * 10,
                [(Identity { pid: 7, born: 1 }, i * MIB)].into_iter(),
            )
        }
        let id = Identity { pid: 7, born: 2 };
        t.update(80, [(id, 99 * MIB)].into_iter());
        assert_eq!(t.0.len(), 1);
        assert!(!t.0[&id].ready());
    }
}
