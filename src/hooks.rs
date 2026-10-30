//! 全局 Git hooks：在 push 前按需刷新 entry-token。
//!
//! Git for Windows 使用 Git Bash 执行 hooks，因此各平台统一生成 POSIX shell 脚本。
//! 安装时会记录用户原有的 `core.hooksPath`，登出时恢复，避免破坏自定义 hooks。

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use crate::git::GitRunner;
use crate::paths::AppPaths;
use crate::util::{create_private_dir, set_private_file_permissions, write_private_file};

const HOOK_NAMES: &[&str] = &["pre-push", "pre-auto-gc"];

/// 生成 hook 脚本。优先使用生成 hook 的可执行文件，避免 PATH 中的旧版本抢先命中。
pub fn hook_script(executable: &Path) -> String {
    let executable = executable.to_string_lossy().replace('\\', "/");
    let quoted = shell_single_quote(&executable);
    format!(
        r#"#!/bin/sh
# 此文件由 fnos-git-auth 自动生成，请勿手动修改。
# 在 git push 前刷新 entry-token，避免服务端提前失效导致 401/403。

FNOS_GIT_AUTH=""
if [ -x '{quoted}' ]; then
    FNOS_GIT_AUTH='{quoted}'
elif command -v fnos-git-auth >/dev/null 2>&1; then
    FNOS_GIT_AUTH="fnos-git-auth"
fi

if [ -z "$FNOS_GIT_AUTH" ]; then
    exit 0
fi

"$FNOS_GIT_AUTH" refresh >/dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "[fnos-git-auth] Token 刷新失败，请检查登录状态" >&2
fi

# 刷新失败也不要阻止 git 操作。
exit 0
"#
    )
}

fn shell_single_quote(value: &str) -> String {
    value.replace('\'', "'\\''")
}

pub fn setup(paths: &AppPaths, git: &GitRunner) -> Result<()> {
    let hooks_dir = paths.hooks_dir();
    let current = git.hooks_path()?;

    if let Some(current) = current.as_deref() {
        if !normalize_path(current).eq(&normalize_path(&hooks_dir.to_string_lossy())) {
            println!("警告: 检测到已有自定义 hooks 路径: {current}");
            println!("将被暂时覆盖为: {}", hooks_dir.display());
            if !paths.hooks_backup_file().exists() {
                write_private_file(&paths.hooks_backup_file(), current.as_bytes())?;
            }
        }
    }

    create_private_dir(paths.dir())?;
    create_private_dir(&hooks_dir)?;

    let executable =
        std::env::current_exe().unwrap_or_else(|_| Path::new("fnos-git-auth").to_path_buf());
    let script = hook_script(&executable);
    for hook_name in HOOK_NAMES {
        let path = hooks_dir.join(hook_name);
        fs::write(&path, script.as_bytes())
            .with_context(|| format!("写入 hook 失败: {}", path.display()))?;
        set_hook_permissions(&path);
    }

    git.set_hooks_path(&hooks_dir.to_string_lossy())
        .with_context(|| "设置 core.hooksPath 失败")?;
    println!("已设置全局 git hooks: {}", hooks_dir.display());
    Ok(())
}

pub fn remove(paths: &AppPaths, git: &GitRunner) -> Result<()> {
    let hooks_dir = paths.hooks_dir();
    let current = git.hooks_path()?;
    let ours = current
        .as_deref()
        .map(|path| normalize_path(path) == normalize_path(&hooks_dir.to_string_lossy()))
        .unwrap_or(false);

    if ours {
        git.unset_hooks_path()?;
        println!("已移除全局 git hooks 配置");

        let backup_file = paths.hooks_backup_file();
        if backup_file.exists() {
            if let Ok(previous) = fs::read_to_string(&backup_file) {
                let previous = previous.trim();
                if !previous.is_empty() {
                    git.set_hooks_path(previous)?;
                    println!("已恢复原有 hooks 路径: {previous}");
                }
            }
            let _ = fs::remove_file(backup_file);
        }
    }

    if hooks_dir.exists() {
        fs::remove_dir_all(&hooks_dir)
            .with_context(|| format!("删除 hooks 目录失败: {}", hooks_dir.display()))?;
        println!("已删除 hooks 目录: {}", hooks_dir.display());
    }
    Ok(())
}

pub fn has(paths: &AppPaths, git: &GitRunner) -> bool {
    let hooks_dir = paths.hooks_dir();
    git.hooks_path()
        .ok()
        .flatten()
        .map(|path| normalize_path(&path) == normalize_path(&hooks_dir.to_string_lossy()))
        .unwrap_or(false)
}

/// 标准化路径，便于跨平台比较（Git 在 Windows 上可能返回正斜杠）。
pub fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase()
}

#[cfg(unix)]
fn set_hook_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o755));
}

#[cfg(not(unix))]
fn set_hook_permissions(path: &Path) {
    // Windows 上 Git 通过 Git Bash 调用脚本，不依赖执行位。
    set_private_file_permissions(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_contains_required_parts() {
        let script = hook_script(Path::new("/usr/local/bin/fnos-git-auth"));
        assert!(script.starts_with("#!/bin/sh"));
        assert!(script.contains(" refresh >/dev/null"));
        assert!(script.contains("/usr/local/bin/fnos-git-auth"));
        assert!(script.ends_with("exit 0\n"));
    }

    #[test]
    fn quotes_executable_paths() {
        let script = hook_script(Path::new("/tmp/it's here/fnos-git-auth"));
        assert!(script.contains(r#"'/tmp/it'\''s here/fnos-git-auth'"#));
    }

    fn test_git() -> Option<(tempfile::TempDir, GitRunner)> {
        if std::process::Command::new("git")
            .arg("--version")
            .output()
            .is_err()
        {
            return None;
        }
        let dir = tempfile::tempdir().unwrap();
        let git = GitRunner::with_global_config(dir.path().join("gitconfig"));
        Some((dir, git))
    }

    #[test]
    fn installs_and_removes_hooks() {
        let Some((dir, git)) = test_git() else {
            return;
        };
        let paths = AppPaths::new(dir.path().join("app"));

        setup(&paths, &git).unwrap();
        assert!(has(&paths, &git));
        for name in HOOK_NAMES {
            let content = fs::read_to_string(paths.hooks_dir().join(name)).unwrap();
            assert!(content.contains(" refresh >/dev/null"));
        }

        remove(&paths, &git).unwrap();
        assert!(!has(&paths, &git));
        assert!(!paths.hooks_dir().exists());
    }

    #[test]
    fn restores_previous_hooks_path() {
        let Some((dir, git)) = test_git() else {
            return;
        };
        let custom = dir.path().join("my-hooks");
        fs::create_dir_all(&custom).unwrap();
        git.set_hooks_path(&custom.to_string_lossy()).unwrap();
        let paths = AppPaths::new(dir.path().join("app"));

        setup(&paths, &git).unwrap();
        assert!(has(&paths, &git));

        remove(&paths, &git).unwrap();
        let restored = git.hooks_path().unwrap();
        assert_eq!(
            restored.map(|path| normalize_path(&path)),
            Some(normalize_path(&custom.to_string_lossy()))
        );
    }
}
