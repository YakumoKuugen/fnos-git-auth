//! 不依赖 fnOS 服务器的命令行端到端测试。

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;

struct TestEnv {
    _dir: tempfile::TempDir,
    config_dir: PathBuf,
    git_config: PathBuf,
}

impl TestEnv {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("config");
        let git_config = dir.path().join("gitconfig");
        std::fs::write(&git_config, b"").unwrap();
        Self {
            _dir: dir,
            config_dir,
            git_config,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::cargo_bin("fnos-git-auth").unwrap();
        command
            .env("FNOS_GIT_AUTH_CONFIG_DIR", &self.config_dir)
            .env("GIT_CONFIG_GLOBAL", &self.git_config)
            .env("GIT_CONFIG_NOSYSTEM", "1");
        command
    }
}

fn config_path(env: &TestEnv) -> PathBuf {
    env.config_dir.join("config.json")
}

#[test]
fn help_lists_all_commands() {
    let env = TestEnv::new();
    let output = env.command().arg("--help").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for command in [
        "login",
        "logout",
        "status",
        "refresh",
        "update",
        "config",
        "git",
        "diagnostic",
    ] {
        assert!(stdout.contains(command), "missing command {command}");
    }
}

#[test]
fn login_help_lists_two_factor_options() {
    let env = TestEnv::new();
    let output = env.command().args(["login", "--help"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--code"));
    assert!(stdout.contains("--trust-device"));
}

#[test]
fn status_reports_logged_out() {
    let env = TestEnv::new();
    env.command()
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("当前未登录"));
}

#[test]
fn config_can_be_shown_set_and_reset() {
    let env = TestEnv::new();
    env.command()
        .arg("config")
        .assert()
        .success()
        .stdout(predicate::str::contains("auto_save_credentials"));

    env.command()
        .args(["config", "-k", "timeout", "-v", "45"])
        .assert()
        .success()
        .stdout(predicate::str::contains("45.0"));

    env.command()
        .args(["config", "-k", "timeout"])
        .assert()
        .success()
        .stdout(predicate::str::contains("45.0"));

    env.command().args(["config", "-r"]).assert().success();
    env.command()
        .args(["config", "-k", "timeout"])
        .assert()
        .success()
        .stdout(predicate::str::contains("30.0"));
}

#[test]
fn unknown_config_key_fails() {
    let env = TestEnv::new();
    env.command()
        .args(["config", "-k", "does_not_exist", "-v", "1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("未知配置项"));
}

#[test]
fn git_show_works_without_headers() {
    let env = TestEnv::new();
    env.command()
        .args(["git", "--show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("未配置 extraHeader"));
}

#[test]
fn refresh_and_logout_fail_when_logged_out() {
    let env = TestEnv::new();
    env.command()
        .arg("refresh")
        .assert()
        .failure()
        .stderr(predicate::str::contains("未登录"));
    env.command()
        .arg("logout")
        .assert()
        .failure()
        .stderr(predicate::str::contains("未登录"));
}

#[test]
fn diagnostic_print_contains_sections_and_no_config_leak() {
    let env = TestEnv::new();
    std::fs::create_dir_all(&env.config_dir).unwrap();
    std::fs::write(
        config_path(&env),
        r#"{"server":{"url":"demo.fnos.net","username":"alice","fnos_token":"super-secret-token","entry_token":"another-secret-token"},"preferences":{}}"#,
    )
    .unwrap();

    let output = env
        .command()
        .args(["diagnostic", "--print"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"system\""));
    assert!(stdout.contains("\"tool\""));
    assert!(!stdout.contains("super-secret-token"));
    assert!(!stdout.contains("another-secret-token"));
}

#[test]
fn diagnostic_package_is_created() {
    let env = TestEnv::new();
    let output_dir = env.config_dir.join("out");
    env.command()
        .args(["diagnostic", "-o"])
        .arg(&output_dir)
        .assert()
        .success()
        .stdout(predicate::str::contains("诊断包已生成"));
    assert!(list_files(&output_dir)
        .iter()
        .any(|name| name.ends_with(".tar.gz")));
}

fn list_files(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect()
}
