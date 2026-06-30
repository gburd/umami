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
        .stdout(predicate::str::contains("throughput"));
}
