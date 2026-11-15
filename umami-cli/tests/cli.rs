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
    let input = format!("{}2020-01-01 10:40:00 disk error\n", heartbeats(0..21));
    umami()
        .arg("pipeline")
        .write_stdin(input)
        .assert()
        .success()
        .stdout(
            "never_before_seen  2020-01-01 10:00:00 heartbeat ok\n\
             event_stop         [stdin] <*> heartbeat ok\n\
             system_away        [stdin]\n\
             never_before_seen  2020-01-01 10:40:00 disk error\n",
        );
}

#[test]
fn untimed_lines_before_the_first_timestamp_do_not_block_sweeps() {
    let input = format!(
        "starting up\n{}2020-01-01 10:40:00 other\n",
        heartbeats(0..21)
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
        heartbeats(6..21)
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
    let input = format!("{}2020-01-01 10:40:00 disk error\n", heartbeats(0..21));
    umami()
        .arg("sim")
        .write_stdin(input)
        .assert()
        .success()
        // 2 lines + event_stop + system_away; 20 of 22 lines filtered
        .stdout(predicate::str::contains("anomalies: 4\n"))
        .stdout(predicate::str::contains("reduction: 90.9%"));
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

#[test]
fn syslog_multi_day_gap_advances_saved_clock() {
    let dir = scratch("gap");
    let state = dir.join("s.json");
    umami()
        .args(["pipeline", "--state", state.to_str().unwrap()])
        .write_stdin("2020-03-01 00:00:00 tick\nMar  5 00:00:00 tick\n")
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(state).unwrap()).unwrap();
    let profile = v["store"]["systems"]["stdin"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap();
    assert_eq!(profile["last_seen"], 1_583_366_400i64);
}

#[test]
fn future_input_does_not_mutate_saved_learning() {
    let dir = scratch("future");
    let state = dir.join("s.json");
    umami()
        .args(["pipeline", "--state", state.to_str().unwrap()])
        .write_stdin("2020-03-01 00:00:00 tick\n")
        .assert()
        .success();
    let before = std::fs::read(&state).unwrap();
    umami()
        .args(["pipeline", "--state", state.to_str().unwrap()])
        .write_stdin("2099-03-01 00:00:00 poison\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("future"));
    assert_eq!(std::fs::read(&state).unwrap(), before);
}

#[test]
fn malformed_envelopes_are_not_overwritten() {
    let dir = scratch("envelope");
    let state = dir.join("s.json");
    umami()
        .args(["pipeline", "--state", state.to_str().unwrap()])
        .write_stdin("hello\n")
        .assert()
        .success();
    let good: serde_json::Value = serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap();
    for (key, value) in [
        ("clock", serde_json::json!("bogus")),
        ("format", serde_json::json!(1)),
        ("unexpected", serde_json::json!(true)),
    ] {
        let mut bad = good.clone();
        bad[key] = value;
        let bytes = serde_json::to_vec(&bad).unwrap();
        std::fs::write(&state, &bytes).unwrap();
        umami()
            .args(["pipeline", "--state", state.to_str().unwrap()])
            .write_stdin("hello\n")
            .assert()
            .failure();
        assert_eq!(std::fs::read(&state).unwrap(), bytes);
    }
}

#[test]
fn multiline_preserves_orphans_and_assembles_one_event() {
    umami()
        .args(["ingest", "--multiline"])
        .write_stdin("  orphan\nerror happened\n  stack frame\n\tat caller\n")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "error happened\\n  stack frame\\n\\tat caller",
        ))
        .stdout(predicate::str::contains("  orphan"));
    umami()
        .args(["sim", "--multiline", "--tagged"])
        .assert()
        .failure();
}

#[test]
fn explicit_time_format_normalizes_full_prefix_and_offset() {
    let dir = scratch("format");
    let state = dir.join("s.json");
    umami()
        .args([
            "sim",
            "--state",
            state.to_str().unwrap(),
            "--time-format",
            "%d %B %Y %H:%M:%S %z",
        ])
        .write_stdin("01 March 2020 02:00:00 +0200 tick\n02 April 2020 02:00:00 +0200 tick\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("profiles:  1"));
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(state).unwrap()).unwrap();
    let p = v["store"]["systems"]["stdin"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap();
    assert_eq!(p["first_seen"], 1_583_020_800i64);
    assert_eq!(p["last_seen"], 1_585_785_600i64);
    umami()
        .args(["sim", "--time-format", "%Y/%m/%d %H:%M:%S"])
        .write_stdin("not a timestamp\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("--time-format"));
    umami()
        .args(["sim", "--time-format", "%m/%d %H:%M:%S"])
        .write_stdin("03/01 00:00:00 tick\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("year"));
}

#[test]
fn oversized_event_fails_without_learning_it() {
    umami()
        .args(["sim", "--multiline"])
        .write_stdin(format!("error\n {}\n", "x".repeat(1024 * 1024)))
        .assert()
        .failure()
        .stderr(predicate::str::contains("1048576"));
    umami()
        .arg("sim")
        .write_stdin("x".repeat(1024 * 1024 + 1))
        .assert()
        .failure()
        .stderr(predicate::str::contains("1048576"));
}

#[cfg(unix)]
fn wait_for_exit(child: &mut std::process::Child) -> std::process::ExitStatus {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if std::time::Instant::now() >= until {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("child failed to exit before deadline");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[cfg(unix)]
fn signal(child: &std::process::Child, name: &str) {
    assert!(std::process::Command::new("kill")
        .args([name, &child.id().to_string()])
        .status()
        .unwrap()
        .success());
}

#[cfg(unix)]
#[test]
fn signals_checkpoint_idle_busy_and_backpressured_input() {
    use std::io::Write;
    use std::process::Stdio;
    for (name, busy, blocked) in [
        ("-INT", false, false),
        ("-TERM", false, false),
        ("-TERM", true, false),
        ("-TERM", true, true),
    ] {
        let dir = scratch(&format!("signal-{name}-{busy}-{blocked}"));
        let state = dir.join("s.json");
        let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("umami"))
            .args(["pipeline", "--show-all", "--state", state.to_str().unwrap()])
            .stdin(Stdio::piped())
            .stdout(if blocked {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        writeln!(stdin, "accepted marker").unwrap();
        let producer = if busy {
            Some(std::thread::spawn(move || {
                while writeln!(stdin, "busy line {}", "x".repeat(2000)).is_ok() {}
            }))
        } else {
            None
        };
        std::thread::sleep(std::time::Duration::from_millis(300));
        signal(&child, name);
        assert!(
            wait_for_exit(&mut child).success(),
            "{name} busy={busy} blocked={blocked}"
        );
        if let Some(producer) = producer {
            producer.join().unwrap();
        }
        umami()
            .args(["pipeline", "--state", state.to_str().unwrap()])
            .write_stdin("accepted marker\n")
            .assert()
            .success()
            .stdout("");
    }
}

#[cfg(unix)]
#[test]
fn concurrent_state_writer_is_rejected() {
    use std::io::Write;
    use std::process::Stdio;
    let dir = scratch("lock");
    let state = dir.join("s.json");
    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("umami"))
        .args(["pipeline", "--state", state.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    writeln!(child.stdin.as_mut().unwrap(), "first writer").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    let out = umami()
        .args(["pipeline", "--state", state.to_str().unwrap()])
        .write_stdin("second writer\n")
        .assert();
    signal(&child, "-TERM");
    let _ = wait_for_exit(&mut child);
    out.failure().stderr(predicate::str::contains("lock"));
}

#[test]
fn tagged_year_anchors_survive_restart_independently() {
    let dir = scratch("anchors");
    let state = dir.join("s.json");
    let run = |input: &str| {
        umami()
            .args(["pipeline", "--tagged", "--state", state.to_str().unwrap()])
            .write_stdin(input.to_string())
            .assert()
            .success();
    };
    run("a\t2020-12-31 23:00:00 tick\nb\t2019-03-01 00:00:00 tick\n");
    run("a\tJan  2 00:00:00 tick\nb\tMar  5 00:00:00 tick\n");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(state).unwrap()).unwrap();
    assert_eq!(v["anchors"]["a"], 1_609_545_600i64);
    assert_eq!(v["anchors"]["b"], 1_551_744_000i64);
}

#[test]
fn changed_preprocessing_settings_are_rejected_without_overwrite() {
    let dir = scratch("preprocessing");
    let state = dir.join("s.json");
    umami()
        .args(["sim", "--state", state.to_str().unwrap()])
        .write_stdin("hello\n")
        .assert()
        .success();
    let original = std::fs::read(&state).unwrap();
    for extra in [
        vec!["--multiline"],
        vec!["--tagged"],
        vec!["--parameters"],
        vec!["--system", "elsewhere"],
        vec!["--time-format", "%Y/%m/%d %H:%M:%S"],
    ] {
        umami()
            .args(["sim", "--state", state.to_str().unwrap()])
            .args(extra)
            .write_stdin("hello\n")
            .assert()
            .failure()
            .stderr(predicate::str::contains("settings"));
        assert_eq!(std::fs::read(&state).unwrap(), original);
    }
}

#[cfg(unix)]
#[test]
fn multiline_idle_flush_includes_partial_line_and_preserves_blank_events() {
    use std::io::{BufRead, BufReader, Write};
    use std::process::Stdio;
    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("umami"))
        .args(["ingest", "--multiline"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if sender.send(line.unwrap()).is_err() {
                break;
            }
        }
    });
    write!(stdin, "error happened\n  partial frame").unwrap();
    let flushed = receiver.recv_timeout(std::time::Duration::from_secs(3));
    signal(&child, "-TERM");
    let _ = wait_for_exit(&mut child);
    reader.join().unwrap();
    assert!(flushed
        .unwrap()
        .contains("error happened\\n  partial frame"));
    umami()
        .args(["sim", "--multiline"])
        .write_stdin("\n\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("events:    2"));
}

#[cfg(unix)]
#[test]
fn shutdown_reports_checkpoint_failure() {
    use std::io::{BufRead, BufReader, Write};
    use std::process::Stdio;
    let dir = scratch("save-failure");
    let state = dir.join("s.json");
    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("umami"))
        .args(["pipeline", "--state", state.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.as_mut().unwrap(), "accepted marker").unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert!(line.contains("accepted marker"));
    std::fs::create_dir(&state).unwrap();
    signal(&child, "-TERM");
    assert!(!wait_for_exit(&mut child).success());
    let mut stderr = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut stderr).unwrap();
    assert!(stderr.contains("s.json"), "{stderr}");
}

#[test]
fn parameter_change_output_identifies_slot_ordinals() {
    let mut input = "2020-01-01 00:00:00 status 200\n".repeat(20);
    input.push_str("2020-01-01 00:00:01 status 500\n");
    umami()
        .args(["ingest", "--parameters"])
        .write_stdin(input.clone())
        .assert()
        .success()
        .stdout(predicate::str::contains("\"changed_params\":[1]"));
    umami()
        .args(["pipeline", "--parameters"])
        .write_stdin(input)
        .assert()
        .success()
        .stdout(predicate::str::contains("[changed_params: 1]"));
}

#[test]
fn version_one_state_has_a_migration_diagnostic() {
    let dir = scratch("version-one");
    let state = dir.join("s.json");
    let old = br#"{"format":1,"clock":"wall","tokenizer":"structure","store":{}}"#;
    std::fs::write(&state, old).unwrap();
    umami()
        .args(["sim", "--state", state.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("state format must be 2"));
    assert_eq!(std::fs::read(state).unwrap(), old);
}

#[test]
fn multiline_continuation_timestamp_cannot_advance_clock() {
    let dir = scratch("continuation-time");
    let state = dir.join("s.json");
    umami()
        .args(["sim", "--multiline", "--state", state.to_str().unwrap()])
        .write_stdin("2020-03-01 00:00:00 tick\n  2099-01-01 00:00:00 body time\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("events:    1"));
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(state).unwrap()).unwrap();
    assert_eq!(v["anchors"]["stdin"], 1_583_020_800i64);
}

#[cfg(unix)]
#[test]
#[ignore = "exercises the real sixty-second checkpoint deadline"]
fn checkpoint_deadline_runs_with_idle_busy_and_blocked_streams() {
    use std::io::Write;
    use std::process::Stdio;
    let mut processes = Vec::new();
    for (busy, blocked) in [(false, false), (true, false), (true, true)] {
        let dir = scratch(&format!("deadline-{busy}-{blocked}"));
        let state = dir.join("s.json");
        let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("umami"))
            .args(["pipeline", "--show-all", "--state", state.to_str().unwrap()])
            .stdin(Stdio::piped())
            .stdout(if blocked {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        writeln!(stdin, "accepted marker").unwrap();
        let (producer, idle) = if busy {
            (
                Some(std::thread::spawn(move || {
                    while writeln!(stdin, "busy line").is_ok() {}
                })),
                None,
            )
        } else {
            (None, Some(stdin))
        };
        processes.push((child, producer, idle, state));
    }
    std::thread::sleep(std::time::Duration::from_secs(62));
    let mut failures = Vec::new();
    for (mut child, producer, _idle, state) in processes {
        // SIGKILL cannot trigger a final checkpoint, so only the timer can pass this test.
        child.kill().unwrap();
        child.wait().unwrap();
        if let Some(producer) = producer {
            producer.join().unwrap();
        }
        if !state.exists() {
            failures.push(state);
            continue;
        }
        umami()
            .args(["pipeline", "--state", state.to_str().unwrap()])
            .write_stdin("accepted marker\n")
            .assert()
            .success()
            .stdout("");
    }
    assert!(
        failures.is_empty(),
        "missing timed checkpoints: {failures:?}"
    );
}

#[test]
fn duplicate_and_missing_state_fields_are_rejected() {
    let dir = scratch("strict-fields");
    let state = dir.join("s.json");
    umami()
        .args(["sim", "--state", state.to_str().unwrap()])
        .write_stdin("hello\n")
        .assert()
        .success();
    let good = std::fs::read_to_string(&state).unwrap();
    let duplicate = good.replacen("\"format\":2", "\"format\":2,\"format\":2", 1);
    let missing = good.replacen("\"time_format\":null,", "", 1);
    assert_ne!(good, missing);
    for bad in [duplicate, missing] {
        std::fs::write(&state, &bad).unwrap();
        umami()
            .args(["sim", "--state", state.to_str().unwrap()])
            .write_stdin("hello\n")
            .assert()
            .failure();
        assert_eq!(std::fs::read_to_string(&state).unwrap(), bad);
    }
}

#[test]
fn leap_day_rollover_uses_next_year_before_date_validation() {
    let state = scratch("leap-rollover").join("s.json");
    umami()
        .args(["sim", "--state", state.to_str().unwrap()])
        .write_stdin("2023-12-31 00:00:00 tick\nFeb 29 00:00:00 tick\n")
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(state).unwrap()).unwrap();
    assert_eq!(v["anchors"]["stdin"], 1_709_164_800i64);
}

#[test]
fn corrupt_nested_state_is_rejected_without_overwrite() {
    let state = scratch("nested-state").join("s.json");
    umami()
        .args(["sim", "--state", state.to_str().unwrap()])
        .write_stdin("2020-01-01 00:00:00 tick\n")
        .assert()
        .success();
    let good: serde_json::Value = serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap();
    let hash = good["store"]["systems"]["stdin"]
        .as_object()
        .unwrap()
        .keys()
        .next()
        .unwrap();
    for (field, value) in [
        ("last_seen", serde_json::json!(4_070_908_800i64)),
        ("first_seen", serde_json::json!(i64::MIN)),
        ("first_seen", serde_json::json!(1_577_836_801i64)),
        ("last_spike", serde_json::json!(4_070_908_800i64)),
        ("last_stop", serde_json::json!(0)),
        ("rate/minute", serde_json::json!(i64::MIN)),
        ("rate/minute", serde_json::json!(67_848_480i64)),
        ("interval_stats/mean", serde_json::json!(-1)),
        ("rate/stats/m2", serde_json::json!(-1)),
        ("hash", serde_json::json!(0)),
    ] {
        let mut bad = good.clone();
        *bad.pointer_mut(&format!("/store/systems/stdin/{hash}/{field}"))
            .unwrap() = value;
        assert_state_rejected(&state, &bad);
    }
    let mut bad = good.clone();
    bad["store"]["clocks"]["stdin"]["lag"] = serde_json::json!(i64::MIN);
    assert_state_rejected(&state, &bad);
}

fn assert_state_rejected(state: &std::path::Path, bad: &serde_json::Value) {
    let bytes = serde_json::to_vec(bad).unwrap();
    std::fs::write(state, &bytes).unwrap();
    umami()
        .args(["sim", "--state", state.to_str().unwrap()])
        .write_stdin("2020-01-01 00:01:00 tick\n")
        .assert()
        .failure();
    assert_eq!(std::fs::read(state).unwrap(), bytes);
}

#[cfg(unix)]
#[test]
fn hardlinked_state_is_refused() {
    let dir = scratch("hardlink");
    let state = dir.join("s.json");
    umami()
        .args(["sim", "--state", state.to_str().unwrap()])
        .write_stdin("hello\n")
        .assert()
        .success();
    let alias = dir.join("alias.json");
    std::fs::hard_link(&state, &alias).unwrap();
    let before = std::fs::read(&state).unwrap();
    for path in [&state, &alias] {
        umami()
            .args(["sim", "--state", path.to_str().unwrap()])
            .write_stdin("hello\n")
            .assert()
            .failure()
            .stderr(predicate::str::contains("hard link"));
        assert_eq!(std::fs::read(path).unwrap(), before);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn output_failure_is_reported_while_input_is_idle() {
    use std::io::{Read, Write};
    use std::process::Stdio;
    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("umami"))
        .arg("pipeline")
        .stdin(Stdio::piped())
        .stdout(
            std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .unwrap(),
        )
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.as_mut().unwrap(), "accepted marker").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(200));
    if child.try_wait().unwrap().is_none() {
        signal(&child, "-TERM");
    }
    let status = wait_for_exit(&mut child);
    let mut error = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut error)
        .unwrap();
    assert!(!status.success(), "{error}");
    assert!(error.contains("space"), "{error}");
}

#[cfg(unix)]
#[test]
fn parse_error_drains_preceding_accepted_output() {
    use std::io::{Read, Write};
    use std::process::Stdio;
    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("umami"))
        .arg("pipeline")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let accepted = format!("2020-01-01 00:00:00 {}", "x".repeat(100_000));
    let input = format!("{accepted}\n2099-01-01 00:00:00 rejected\n");
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()).unwrap());
    std::thread::sleep(std::time::Duration::from_millis(200));
    let mut output = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    writer.join().unwrap();
    assert!(!wait_for_exit(&mut child).success());
    assert_eq!(output, format!("never_before_seen  {accepted}\n"));
}

#[test]
fn anchors_must_name_known_systems_and_not_exceed_learned_time() {
    let state = scratch("anchor-consistency").join("s.json");
    umami()
        .args(["sim", "--state", state.to_str().unwrap()])
        .write_stdin("2020-01-01 00:00:00 tick\n")
        .assert()
        .success();
    let good: serde_json::Value = serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap();
    let mut ahead = good.clone();
    ahead["anchors"]["stdin"] = serde_json::json!(1_735_689_600i64);
    assert_state_rejected(&state, &ahead);
    let mut unknown = good;
    unknown["anchors"]["unknown"] = serde_json::json!(1_577_836_800i64);
    assert_state_rejected(&state, &unknown);
}

#[test]
fn input_outside_supported_time_range_does_not_change_state() {
    for (name, extra, seed, bad) in [
        (
            "auto",
            vec![],
            "2020-01-01 00:00:00 tick\n",
            "0000-01-01T00:00:00+0100 tick\n",
        ),
        (
            "explicit",
            vec!["--time-format", "%Y/%m/%d %H:%M:%S"],
            "2020/01/01 00:00:00 tick\n",
            "-0001/01/01 00:00:00 tick\n",
        ),
    ] {
        let state = scratch(&format!("range-{name}")).join("s.json");
        umami()
            .args(["sim", "--state", state.to_str().unwrap()])
            .args(&extra)
            .write_stdin(seed)
            .assert()
            .success();
        let before = std::fs::read(&state).unwrap();
        umami()
            .args(["sim", "--state", state.to_str().unwrap()])
            .args(&extra)
            .write_stdin(bad)
            .assert()
            .failure()
            .stderr(predicate::str::contains("supported timestamp range"));
        assert_eq!(std::fs::read(state).unwrap(), before);
    }
}

#[test]
fn earliest_supported_timestamp_roundtrips_through_state() {
    let state = scratch("range-boundary").join("s.json");
    for _ in 0..2 {
        umami()
            .args(["sim", "--state", state.to_str().unwrap()])
            .write_stdin("0000-01-01T00:00:00Z tick\n")
            .assert()
            .success();
    }
}

#[test]
fn historical_anchor_can_precede_a_wall_clock_observation() {
    let state = scratch("wall-to-event-anchor").join("s.json");
    umami()
        .args(["sim", "--state", state.to_str().unwrap()])
        .write_stdin("plain wall clock event\n2020-01-01 00:00:00 historical event\n")
        .assert()
        .success();
    umami()
        .args(["sim", "--state", state.to_str().unwrap()])
        .write_stdin("2020-01-01 00:01:00 historical event\n")
        .assert()
        .success();
}
