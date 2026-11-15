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
fn legacy_tokenizer_is_rejected() {
    umami()
        .args(["tokenize", "--tokenizer", "legacy"])
        .write_stdin("sshd[123]: ok\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("possible values: structure"));
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
        .stderr(predicate::str::contains("possible values: structure"));
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
    // A state saved with a removed tokenizer is refused, not silently misused.
    let mut saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap();
    saved["tokenizer"] = "legacy".into();
    std::fs::write(&state, serde_json::to_vec(&saved).unwrap()).unwrap();
    umami()
        .args(["pipeline", "--state", state.to_str().unwrap()])
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

#[test]
fn a_date_in_the_message_does_not_move_the_clock() {
    // Before the fix the 2099 date became "now" and the real stop at 10:10
    // was never reported.
    let input = format!(
        "{}cert for host expires 2099-01-01 00:00:00 renew soon\n{}2020-01-01 10:30:00 boom\n",
        heartbeats(0..6),
        heartbeats(6..10)
    );
    umami()
        .arg("pipeline")
        .write_stdin(input)
        .assert()
        .success()
        .stdout(predicate::str::contains("event_stop"));
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("umami-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn syslog_across_new_year_keeps_the_clock_moving() {
    let mut input = String::new();
    for m in 50..60 {
        input += &format!("Dec 31 23:{m}:00 h cron: tick\n");
    }
    for m in 0..11 {
        input += &format!("Jan  1 00:{m:02}:00 h cron: tick\n");
    }
    input += "Jan  1 00:40:00 h kernel: disk error\n";
    umami()
        .arg("pipeline")
        .write_stdin(input)
        .assert()
        .success()
        .stdout(predicate::str::contains("event_stop"))
        .stdout(predicate::str::contains("system_away"));
}

#[test]
fn state_path_ending_in_tmp_is_still_written_atomically() {
    let dir = scratch("tmp-ext");
    let state = dir.join("s.tmp");
    umami()
        .args(["pipeline", "--state", state.to_str().unwrap()])
        .write_stdin("hello\n")
        .assert()
        .success();
    assert!(state.exists());
    assert!(!dir.join("s.tmp.tmp").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn unwritable_state_fails_before_reading_input() {
    let dir = scratch("nodir");
    let state = dir.join("missing").join("s.json");
    umami()
        .args(["pipeline", "--state", state.to_str().unwrap()])
        .write_stdin("hello\n")
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("missing/s.json"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn state_is_saved_when_the_output_pipe_closes() {
    let dir = scratch("pipe");
    let state = dir.join("s.json");
    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("umami"))
        .args(["pipeline", "--state", state.to_str().unwrap()])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take()); // the reader goes away, as with `| head -0`
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().unwrap();
        for i in 0..20_000 {
            if writeln!(stdin, "word{} {}", "x".repeat(i % 7), "y".repeat(i % 11)).is_err() {
                break;
            }
        }
    }
    assert!(child.wait().unwrap().success());
    let saved = std::fs::read_to_string(&state).unwrap();
    assert!(saved.contains("\"tokenizer\":\"structure\""));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn resuming_with_an_untimed_first_line_does_not_report_everything_away() {
    let dir = scratch("resume");
    let state = dir.join("s.json");
    let run = |input: String| {
        let out = umami()
            .args(["pipeline", "--tagged", "--state", state.to_str().unwrap()])
            .write_stdin(input)
            .assert()
            .success();
        String::from_utf8(out.get_output().stdout.clone()).unwrap()
    };
    let mut day1 = String::new();
    for m in 0..30 {
        day1 += &format!("a\t2020-01-01 10:{m:02}:00 tick\nb\t2020-01-01 10:{m:02}:00 tock\n");
    }
    run(day1);
    let resumed = run("a\treplay header\na\t2020-01-01 10:31:00 tick\n".to_string());
    assert!(!resumed.contains("system_away"), "{resumed}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn sim_counts_sweep_anomalies() {
    let input = format!("{}2020-01-01 10:30:00 disk error\n", heartbeats(0..10));
    umami()
        .arg("sim")
        .write_stdin(input)
        .assert()
        .success()
        // 2 lines + event_stop + system_away; 9 of 11 lines filtered
        .stdout(predicate::str::contains("anomalies: 4\n"))
        .stdout(predicate::str::contains("reduction: 81.8%"));
}

#[test]
fn untimed_input_keeps_the_wall_clock_across_runs() {
    let dir = scratch("untimed");
    let state = dir.join("s.json");
    let run = || {
        umami()
            .args(["pipeline", "--state", state.to_str().unwrap()])
            .write_stdin("plain line\n")
            .assert()
            .success();
    };
    run();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    run();
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
    assert_eq!(v["clock"], "wall");
    let profile = v["store"]["systems"]["stdin"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .clone();
    // the second run was stamped with the wall clock, not the saved time
    assert!(
        profile["interval_stats"]["mean"].as_f64().unwrap() >= 1.0,
        "{profile}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
