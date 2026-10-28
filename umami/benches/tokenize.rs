//! Tokenizer throughput benchmarks.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use umami::Tokenizer;

const SAMPLES: &[&str] = &[
    "Jan 23 10:23:45 web01 sshd[1234]: Failed password for root from 192.168.1.5 port 22 ssh2",
    "2020-11-12T15:45:54+0000 INFO starting service version=3.6.9 pid=4815",
    "level=error msg=\"database connection failed\" host=db-7 port=5432 retries=3",
    "{\"timestamp\":\"2020-11-12T15:45:54Z\",\"level\":\"error\",\"retries\":3}",
    "192.168.1.5 - - [23/Jan/2020:10:23:45 +0000] \"GET /index.html HTTP/1.1\" 200 1547",
    "GET /api/v2/users/4815 HTTP/1.1 200 0.123",
];

fn bench(c: &mut Criterion) {
    let corpus: Vec<&str> = SAMPLES.iter().copied().cycle().take(10_000).collect();
    let bytes: usize = corpus.iter().map(|l| l.len()).sum();

    for tok in [Tokenizer::Structure, Tokenizer::Legacy] {
        let name = tok.name();
        let mut group = c.benchmark_group(format!("tokenize/{name}"));
        group.throughput(Throughput::Bytes(bytes as u64));
        group.bench_function("10k_lines", |b| {
            b.iter(|| {
                for line in &corpus {
                    black_box(tok.tokenize(black_box(line)));
                }
            })
        });
        group.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
