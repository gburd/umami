//! End-to-end detection throughput benchmarks.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use umami::Detector;

fn corpus(n: usize) -> Vec<String> {
    let templates = [
        "GET /api/v2/users/{} HTTP/1.1 200 {}",
        "level=info msg=ok host=node{} latency={}",
        "Jan 23 10:23:45 web01 sshd[{}]: Accepted publickey for deploy port {} ssh2",
        "disk usage at {} percent on /dev/sda{}",
    ];
    (0..n)
        .map(|i| templates[i % templates.len()].replace("{}", &i.to_string()))
        .collect()
}

fn bench(c: &mut Criterion) {
    let lines = corpus(10_000);
    let mut group = c.benchmark_group("detect");
    group.throughput(Throughput::Elements(lines.len() as u64));
    group.bench_function("observe_10k", |b| {
        b.iter(|| {
            let mut d = Detector::new();
            for (i, line) in lines.iter().enumerate() {
                black_box(d.observe("bench", black_box(line), i as i64));
            }
        })
    });
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
