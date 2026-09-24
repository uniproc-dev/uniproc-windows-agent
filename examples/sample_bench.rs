//! Microbenchmark for the CPU-sample counters:
//!   cargo run --release --example sample_bench
//!
//! Compares, on a synthetic sample stream shaped like the kernel profiler's,
//! how the ETW pump accumulates samples per thread and how the window fold
//! sums the counters. The hot functions are `#[inline(never)]` so their
//! assembly can be read with `cargo rustc --release --example sample_bench
//! -- --emit asm`.

use std::hint::black_box;
use std::time::Instant;

use fxhash::FxHashMap;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    tid: u32,
    pid_hint: u32,
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn chance(&mut self, per_mille: u64) -> bool {
        self.below(1000) < per_mille
    }
}

fn stream(cpus: usize, samples: usize, threads: u32, rng: &mut Rng) -> Vec<Key> {
    let pick = |rng: &mut Rng| -> Key {
        if rng.chance(500) {
            return Key { tid: 0, pid_hint: 0 };
        }
        let r = rng.below(1 << 20) as f64 / (1u64 << 20) as f64;
        let tid = 4 + 4 * ((r * r * r) * threads as f64) as u32;
        Key {
            tid,
            pid_hint: 1000 + tid / 64 * 4,
        }
    };

    let mut current: Vec<Key> = (0..cpus).map(|_| pick(rng)).collect();
    let mut out = Vec::with_capacity(samples);
    let mut cpu = 0;
    while out.len() < samples {
        for _ in 0..8 {
            if rng.chance(100) {
                current[cpu] = pick(rng);
            }
            out.push(current[cpu]);
        }
        cpu = (cpu + 1) % cpus;
    }
    out.truncate(samples);
    out
}

#[inline(never)]
fn accumulate_hashmap(samples: &[Key], map: &mut FxHashMap<Key, u64>) {
    map.clear();
    for &k in samples {
        *map.entry(k).or_default() += 1;
    }
}

#[inline(never)]
fn accumulate_vec_scan(samples: &[Key], v: &mut Vec<(Key, u64)>) {
    v.clear();
    for &k in samples {
        match v.iter_mut().find(|(key, _)| *key == k) {
            Some((_, n)) => *n += 1,
            None => v.push((k, 1)),
        }
    }
}

#[inline(never)]
fn accumulate_vec_last_hit(samples: &[Key], v: &mut Vec<(Key, u64)>) {
    v.clear();
    let mut last = usize::MAX;
    for &k in samples {
        if let Some((key, n)) = v.get_mut(last)
            && *key == k
        {
            *n += 1;
            continue;
        }
        match v.iter().position(|(key, _)| *key == k) {
            Some(i) => {
                v[i].1 += 1;
                last = i;
            }
            None => {
                v.push((k, 1));
                last = v.len() - 1;
            }
        }
    }
}

#[inline(never)]
fn accumulate_hashmap_last_hit(samples: &[Key], map: &mut FxHashMap<Key, u64>) {
    map.clear();
    let mut run: Option<(Key, u64)> = None;
    for &k in samples {
        match &mut run {
            Some((key, n)) if *key == k => *n += 1,
            _ => {
                if let Some((key, n)) = run.take() {
                    *map.entry(key).or_default() += n;
                }
                run = Some((k, 1));
            }
        }
    }
    if let Some((key, n)) = run {
        *map.entry(key).or_default() += n;
    }
}

#[inline(never)]
fn sum_hashmap(map: &FxHashMap<u32, u64>) -> u64 {
    map.values().sum()
}

#[inline(never)]
fn sum_vec(v: &[u64]) -> u64 {
    v.iter().sum()
}

#[inline(never)]
fn sum_pairs(v: &[(u32, u64)]) -> u64 {
    v.iter().map(|(_, n)| n).sum()
}

fn time<T>(label: &str, per: usize, rounds: usize, mut f: impl FnMut() -> T) {
    for _ in 0..rounds / 10 + 1 {
        black_box(f());
    }
    let mut best = f64::MAX;
    for _ in 0..7 {
        let started = Instant::now();
        for _ in 0..rounds {
            black_box(f());
        }
        best = best.min(started.elapsed().as_secs_f64() / rounds as f64);
    }
    println!(
        "  {label:32} {:9.2} us per call  {:6.2} ns per item",
        best * 1e6,
        best * 1e9 / per as f64
    );
}

fn main() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);

    for (cpus, threads) in [(16usize, 200u32), (16, 2000), (64, 2000)] {
        let batch = stream(cpus, cpus * 100, threads, &mut rng);
        let distinct = {
            let mut m = FxHashMap::default();
            accumulate_hashmap(&batch, &mut m);
            m.len()
        };
        let runs = batch.windows(2).filter(|w| w[0] != w[1]).count() + 1;
        println!(
            "accumulate one 100 ms batch: {cpus} cpus, {} samples, {distinct} distinct threads, {runs} runs",
            batch.len()
        );

        let mut map = FxHashMap::default();
        time("FxHashMap entry", batch.len(), 2000, || {
            accumulate_hashmap(&batch, &mut map)
        });
        let mut map = FxHashMap::default();
        time("FxHashMap + run of same key", batch.len(), 2000, || {
            accumulate_hashmap_last_hit(&batch, &mut map)
        });
        let mut v = Vec::new();
        time("Vec linear scan", batch.len(), 2000, || {
            accumulate_vec_scan(&batch, &mut v)
        });
        let mut v = Vec::new();
        time("Vec scan + last hit", batch.len(), 2000, || {
            accumulate_vec_last_hit(&batch, &mut v)
        });
    }

    for pids in [150usize, 600, 5000] {
        println!("sum over {pids} per-process counters at the window fold:");
        let map: FxHashMap<u32, u64> = (0..pids as u32)
            .map(|i| (1000 + i * 4, rng.below(1000)))
            .collect();
        let v: Vec<u64> = map.values().copied().collect();
        let pairs: Vec<(u32, u64)> = map.iter().map(|(&k, &n)| (k, n)).collect();
        assert_eq!(sum_hashmap(&map), sum_vec(&v));
        assert_eq!(sum_vec(&v), sum_pairs(&pairs));

        time("FxHashMap values().sum()", pids, 200_000, || sum_hashmap(&map));
        time("Vec<u64> sum", pids, 200_000, || sum_vec(&v));
        time("Vec<(u32,u64)> sum", pids, 200_000, || sum_pairs(&pairs));
    }
}
