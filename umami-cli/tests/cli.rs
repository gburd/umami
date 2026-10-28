//! Integration tests for the `umami` command-line binary.

use assert_cmd::Command;
use predicates::prelude::*;

fn umami() -> Command {
    Command::cargo_bin("umami").unwrap()
}

#[test]
fn tokenize_test_printer() {
    umami()
        .arg("tokenize")
        .write_stdin("web01 sshd ok\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("0{web01}"))
        .stdout(predicate::str::contains("0{sshd}"));
}

#[test]
fn tokenize_number_classification() {
    umami()
        .arg("tokenize")
        .write_stdin("count 42\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("5{42}"));
}

#[test]
fn tokenize_static_drops_delimiters() {
    let out = umami()
        .args(["tokenize", "--pretty", "static"])
        .write_stdin("a b c\n")
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    // static joins structural tokens with single spaces, no `{` markers
    assert!(
        !stdout.contains('{'),
        "static output should not contain token markers"
    );
    assert!(stdout.contains("a b c"));
}

#[test]
fn tokenize_legacy_tokenizer() {
    umami()
        .args(["tokenize", "--tokenizer", "legacy"])
        .write_stdin("sshd[123]: ok\n")
        .assert()
        .success()
        // legacy keeps `sshd[123` as one literal
        .stdout(predicate::str::contains("0{sshd[123}"));
}

#[test]
fn tokenize_positional_args() {
    umami()
        .args(["tokenize", "hello world"])
        .assert()
        .success()
        .stdout(predicate::str::contains("0{hello}"));
}

#[test]
fn invalid_tokenizer_fails() {
    umami()
        .args(["tokenize", "--tokenizer", "bogus"])
        .write_stdin("x\n")
        .assert()
        .failure();
}

#[test]
fn sim_summary() {
    umami()
        .arg("sim")
        .write_stdin("GET /a 200\nGET /b 200\ndisk full\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("events:"))
        .stdout(predicate::str::contains("anomalies:"))
        .stdout(predicate::str::contains("reduction:"));
}

#[test]
fn pipeline_show_all_filters_repeats() {
    let out = umami()
        .args(["pipeline", "--show-all"])
        .write_stdin("login ok id=1\nlogin ok id=2\nPANIC overflow\n")
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    // first novel structure -> anomaly; repeat -> ok; new structure -> anomaly
    assert!(stdout.contains("never_before_seen"));
    assert!(stdout.contains("ok "));
}

#[test]
fn ingest_emits_json() {
    umami()
        .args(["ingest", "--system", "web01"])
        .write_stdin("service started\nERROR boom\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"kind\":"))
        .stdout(predicate::str::contains("\"system\":\"web01\""));
}

#[test]
fn load_reports_throughput() {
    umami()
        .args(["load", "--count", "1000"])
        .assert()
        .success()
        .stdout(predicate::str::contains("throughput"))
        .stdout(predicate::str::contains("profiles   4"));
}

fn heartbeats(minutes: std::ops::Range<u32>) -> String {
    minutes
        .map(|m| format!("2020-01-01 10:{m:02}:00 heartbeat ok\n"))
        .collect()
}

#[test]
fn pipeline_reports_stops_and_absence_on_event_time() {
    let input = format!("{}2020-01-01 10:30:00 disk error\n", heartbeats(0..10));
    umami()
        .arg("pipeline")
        .write_stdin(input)
        .assert()
        .success()
        .stdout(
            "never_before_seen  2020-01-01 10:00:00 heartbeat ok\n\
             event_stop         [stdin] <*> heartbeat ok\n\
             system_away        [stdin]\n\
             never_before_seen  2020-01-01 10:30:00 disk error\n",
        );
}

#[test]
fn untimed_lines_before_the_first_timestamp_do_not_block_sweeps() {
    let input = format!(
        "starting up\n{}2020-01-01 10:20:00 other\n",
        heartbeats(0..10)
    );
    umami()
        .arg("pipeline")
        .write_stdin(input)
        .assert()
        .success()
        .stdout(predicate::str::contains("event_stop"));
}

#[test]
fn tagged_systems_are_tracked_separately() {
    let mut input = String::new();
    for m in 0..20 {
        input += &format!("a\t2020-01-01 10:{m:02}:00 tick\n");
        if m < 5 {
            input += &format!("b\t2020-01-01 10:{m:02}:00 tick\n");
        }
    }
    let out = umami()
        .args(["pipeline", "--tagged"])
        .write_stdin(input)
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("new_in_system"), "{stdout}");
    assert!(stdout.contains("system_away        [b]"), "{stdout}");
    assert!(!stdout.contains("[a]"), "{stdout}");
}

#[test]
fn ingest_includes_hash() {
    umami()
        .arg("ingest")
        .write_stdin("disk full\n")
        .assert()
        .success()
        .stdout(predicate::str::is_match(r#""hash":"[0-9a-f]{16}""#).unwrap());
}

#[test]
fn invalid_utf8_is_replaced_not_fatal() {
    umami()
        .arg("pipeline")
        .write_stdin(&b"ok line\n\xff\xfe bad\n"[..])
        .assert()
        .success()
        .stdout(predicate::str::contains("\u{fffd}\u{fffd} bad"));
}

#[test]
fn unknown_tokenizer_lists_choices() {
    umami()
        .args(["pipeline", "--tokenizer", "bogus"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("structure, legacy"));
}

#[test]
fn state_file_carries_learning_across_runs() {
    let dir = std::env::temp_dir().join(format!("umami-cli-state-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let state = dir.join("state.json");
    let _ = std::fs::remove_file(&state);
    let run = |input: &str, extra: &[&str]| {
        let out = umami()
            .args(["pipeline", "--state", state.to_str().unwrap()])
            .args(extra)
            .write_stdin(input.to_string())
            .assert();
        String::from_utf8(out.get_output().stdout.clone()).unwrap()
    };
    assert!(run("disk full on sda1\n", &[]).contains("never_before_seen"));
    // learned last time: filtered now
    assert_eq!(run("disk full on sda2\n", &[]), "");
    // a state saved by another tokenizer is refused, not silently misused
    umami()
        .args([
            "pipeline",
            "--tokenizer",
            "legacy",
            "--state",
            state.to_str().unwrap(),
        ])
        .write_stdin("x\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("saved with --tokenizer"));
    std::fs::write(&state, "{not json").unwrap();
    umami()
        .args(["pipeline", "--state", state.to_str().unwrap()])
        .write_stdin("x\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("state.json"));
    std::fs::remove_dir_all(&dir).unwrap();
}
