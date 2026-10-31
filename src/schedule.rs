//! 定时自动刷新：把 `refresh --if-needed` 交给系统计划任务。
//!
//! entry-token 只有几小时有效期，而 Git hooks 只在 `push` / `auto-gc` 时触发，
//! `fetch` / `pull` 以及睡醒后都不会刷新。这里为每个平台安装一个周期性任务：
//!
//! - macOS：LaunchAgent（登录时执行一次，之后按间隔重复）；
//! - Linux：systemd user timer（`Persistent=true`，唤醒/开机后补跑）；
//! - Windows：任务计划程序 + `wscript` 启动脚本（避免弹出控制台窗口）。
//!
//! 任务本身只执行 `refresh --if-needed`：token 仍然充足时不会发起网络请求。

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::paths::AppPaths;

/// 默认定时刷新间隔（分钟）。
pub const DEFAULT_INTERVAL_MINUTES: u64 = 30;
/// 允许的最小间隔（分钟）。
pub const MIN_INTERVAL_MINUTES: u64 = 5;
/// 允许的最大间隔（分钟）。
pub const MAX_INTERVAL_MINUTES: u64 = 24 * 60;
/// Windows 任务计划程序中的任务名。
pub const TASK_NAME: &str = "fnos-git-auth refresh";
/// macOS LaunchAgent 的 label。
pub const LAUNCH_AGENT_LABEL: &str = "com.fnos-git-auth.refresh";

/// 安装定时刷新任务。
pub fn install(paths: &AppPaths, interval_minutes: u64) -> Result<()> {
    if !(MIN_INTERVAL_MINUTES..=MAX_INTERVAL_MINUTES).contains(&interval_minutes) {
        bail!("刷新间隔必须在 {MIN_INTERVAL_MINUTES} 到 {MAX_INTERVAL_MINUTES} 分钟之间");
    }
    let executable = executable()?;
    platform::install(paths, &executable, interval_minutes)
}

/// 卸载定时刷新任务。
pub fn uninstall() -> Result<()> {
    platform::uninstall()
}

/// 打印定时刷新任务状态。
pub fn status() -> Result<()> {
    platform::status()
}

/// 当前平台是否已安装定时刷新任务。
pub fn is_installed() -> bool {
    platform::is_installed()
}

fn executable() -> Result<PathBuf> {
    std::env::current_exe().context("无法确定当前可执行文件路径")
}

// ---------------------------------------------------------------------------
// 各平台任务内容。生成函数与平台无关，便于在任意平台上测试。
// ---------------------------------------------------------------------------

/// 生成 macOS LaunchAgent plist。
#[allow(dead_code)]
pub(crate) fn launch_agent_plist(executable: &Path, interval_minutes: u64, log: &Path) -> String {
    let executable = xml_escape(&executable.to_string_lossy());
    let log = xml_escape(&log.to_string_lossy());
    let seconds = interval_minutes * 60;
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LAUNCH_AGENT_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{executable}</string>
        <string>refresh</string>
        <string>--if-needed</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StartInterval</key>
    <integer>{seconds}</integer>
    <key>ProcessType</key>
    <string>Background</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
    <key>StandardOutPath</key>
    <string>{log}</string>
    <key>StandardErrorPath</key>
    <string>{log}</string>
</dict>
</plist>
"#
    )
}

/// 生成 systemd service 单元。
#[allow(dead_code)]
pub(crate) fn systemd_service(executable: &Path) -> String {
    let executable = systemd_escape(&executable.to_string_lossy());
    format!(
        "[Unit]\n\
         Description=Refresh fnOS git entry-token\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         ExecStart={executable} refresh --if-needed\n"
    )
}

/// 生成 systemd timer 单元。
#[allow(dead_code)]
pub(crate) fn systemd_timer(interval_minutes: u64) -> String {
    format!(
        "[Unit]\n\
         Description=Periodically refresh fnOS git entry-token\n\
         \n\
         [Timer]\n\
         OnBootSec=2min\n\
         OnUnitActiveSec={interval_minutes}min\n\
         Persistent=true\n\
         \n\
         [Install]\n\
         WantedBy=timers.target\n"
    )
}

/// 生成 Windows 任务计划程序 XML。
#[allow(dead_code)]
pub(crate) fn windows_task_xml(wscript: &Path, vbs: &Path, interval_minutes: u64) -> String {
    let command = xml_escape(&wscript.to_string_lossy());
    let arguments = xml_escape(&format!("//B \"{}\"", vbs.display()));
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Periodically refresh the fnOS Git entry-token</Description>
    <URI>\{TASK_NAME}</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
    <CalendarTrigger>
      <StartBoundary>2020-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
      <Repetition>
        <Interval>PT{interval_minutes}M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
      <Arguments>{arguments}</Arguments>
    </Exec>
  </Actions>
</Task>
"#
    )
}

/// 生成 Windows 启动脚本：以隐藏窗口运行一次刷新。
#[allow(dead_code)]
pub(crate) fn windows_launcher_vbs(executable: &Path) -> String {
    let command = format!("\"{}\" refresh --if-needed", executable.display());
    let command = command.replace('"', "\"\"");
    format!(
        "' 由 fnos-git-auth 自动生成，请勿手动修改。\r\n\
         Set shell = CreateObject(\"WScript.Shell\")\r\n\
         WScript.Quit shell.Run(\"{command}\", 0, True)\r\n"
    )
}

/// 生成带 BOM 的 UTF-16LE 字节串（Windows 的计划任务 XML、VBScript 都能识别）。
#[allow(dead_code)]
pub(crate) fn utf16le_bom(text: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(2 + text.len() * 2);
    bytes.extend_from_slice(&[0xFF, 0xFE]);
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// systemd 的 ExecStart 参数转义：含空格的路径需要加引号。
fn systemd_escape(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

// ---------------------------------------------------------------------------
// macOS
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod platform {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};

    use anyhow::{bail, Context, Result};

    use crate::paths::AppPaths;
    use crate::util::{create_private_dir, write_private_file};

    use super::{launch_agent_plist, LAUNCH_AGENT_LABEL};

    fn plist_path() -> Result<PathBuf> {
        let home = dirs::home_dir().context("无法确定用户主目录")?;
        Ok(home
            .join("Library/LaunchAgents")
            .join(format!("{LAUNCH_AGENT_LABEL}.plist")))
    }

    fn uid() -> Result<String> {
        let output = Command::new("id")
            .arg("-u")
            .output()
            .context("无法执行 id 命令")?;
        if !output.status.success() {
            bail!("无法获取当前用户 UID");
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    fn launchctl(args: &[&str]) -> std::io::Result<Output> {
        Command::new("launchctl").args(args).output()
    }

    pub fn install(paths: &AppPaths, executable: &Path, interval_minutes: u64) -> Result<()> {
        let plist = plist_path()?;
        if let Some(parent) = plist.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("创建目录失败: {}", parent.display()))?;
        }

        let log_dir = paths.dir().join("logs");
        create_private_dir(&log_dir)?;
        let log = log_dir.join("refresh.log");

        let content = launch_agent_plist(executable, interval_minutes, &log);
        write_private_file(&plist, content.as_bytes())?;

        let domain = format!("gui/{}", uid()?);
        let service = format!("{domain}/{LAUNCH_AGENT_LABEL}");
        let _ = launchctl(&["bootout", service.as_str()]);

        let plist_arg = plist.to_string_lossy().to_string();
        let output = launchctl(&["bootstrap", domain.as_str(), plist_arg.as_str()])
            .context("无法执行 launchctl，当前系统可能不支持 LaunchAgent")?;
        if !output.status.success() {
            bail!(
                "launchctl bootstrap 失败: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }

        println!("已安装定时刷新任务（LaunchAgent）: {}", plist.display());
        println!("  间隔: 每 {interval_minutes} 分钟，登录时也会执行一次");
        println!("  日志: {}", log.display());
        Ok(())
    }

    pub fn uninstall() -> Result<()> {
        let plist = plist_path()?;
        if let Ok(uid) = uid() {
            let service = format!("gui/{uid}/{LAUNCH_AGENT_LABEL}");
            let _ = launchctl(&["bootout", service.as_str()]);
        }
        if plist.exists() {
            fs::remove_file(&plist)
                .with_context(|| format!("删除 LaunchAgent 失败: {}", plist.display()))?;
            println!("已卸载定时刷新任务");
        } else {
            println!("未安装定时刷新任务");
        }
        Ok(())
    }

    pub fn status() -> Result<()> {
        let plist = plist_path()?;
        println!("平台: macOS（LaunchAgent）");
        if !plist.is_file() {
            println!("状态: 未安装");
            println!("安装: fnos-git-auth schedule install");
            return Ok(());
        }

        println!("配置文件: {}", plist.display());
        let loaded = uid()
            .ok()
            .map(|uid| format!("gui/{uid}/{LAUNCH_AGENT_LABEL}"))
            .and_then(|service| launchctl(&["print", service.as_str()]).ok())
            .map(|output| output.status.success())
            .unwrap_or(false);
        println!(
            "运行状态: {}",
            if loaded {
                "已加载"
            } else {
                "未加载（重新执行 schedule install 可修复）"
            }
        );
        Ok(())
    }

    pub fn is_installed() -> bool {
        plist_path().map(|path| path.is_file()).unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// Linux
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod platform {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};

    use anyhow::{Context, Result};

    use crate::paths::AppPaths;

    use super::{systemd_service, systemd_timer};

    const UNIT: &str = "fnos-git-auth-refresh";

    fn unit_dir() -> Result<PathBuf> {
        let home = dirs::home_dir().context("无法确定用户主目录")?;
        Ok(home.join(".config/systemd/user"))
    }

    fn systemctl(args: &[&str]) -> std::io::Result<Output> {
        Command::new("systemctl").arg("--user").args(args).output()
    }

    pub fn install(_paths: &AppPaths, executable: &Path, interval_minutes: u64) -> Result<()> {
        let dir = unit_dir()?;
        fs::create_dir_all(&dir).with_context(|| format!("创建目录失败: {}", dir.display()))?;

        let service = dir.join(format!("{UNIT}.service"));
        let timer = dir.join(format!("{UNIT}.timer"));
        fs::write(&service, systemd_service(executable))
            .with_context(|| format!("写入 {} 失败", service.display()))?;
        fs::write(&timer, systemd_timer(interval_minutes))
            .with_context(|| format!("写入 {} 失败", timer.display()))?;

        let _ = systemctl(&["daemon-reload"]);
        let timer_name = format!("{UNIT}.timer");
        let enabled = systemctl(&["enable", "--now", timer_name.as_str()])
            .map(|output| output.status.success())
            .unwrap_or(false);

        println!("已写入 systemd 用户定时任务: {}", timer.display());
        println!("  间隔: 每 {interval_minutes} 分钟，开机/唤醒后补跑");
        if enabled {
            println!("  状态: 已启用并启动");
        } else {
            println!("  状态: 未能自动启用，请手动执行:");
            println!("    systemctl --user enable --now {UNIT}.timer");
            println!("  若在 SSH/容器中运行，可能还需要: loginctl enable-linger $USER");
        }
        Ok(())
    }

    pub fn uninstall() -> Result<()> {
        let dir = unit_dir()?;
        let timer_name = format!("{UNIT}.timer");
        let _ = systemctl(&["disable", "--now", timer_name.as_str()]);

        let mut removed = false;
        for name in [format!("{UNIT}.service"), timer_name] {
            let path = dir.join(name);
            if path.exists() {
                fs::remove_file(&path).with_context(|| format!("删除 {} 失败", path.display()))?;
                removed = true;
            }
        }
        let _ = systemctl(&["daemon-reload"]);

        if removed {
            println!("已卸载定时刷新任务");
        } else {
            println!("未安装定时刷新任务");
        }
        Ok(())
    }

    pub fn status() -> Result<()> {
        let dir = unit_dir()?;
        let timer = dir.join(format!("{UNIT}.timer"));
        println!("平台: Linux（systemd user timer）");
        if !timer.is_file() {
            println!("状态: 未安装");
            println!("安装: fnos-git-auth schedule install");
            return Ok(());
        }

        println!("单元文件: {}", timer.display());
        let timer_name = format!("{UNIT}.timer");
        match systemctl(&["is-active", timer_name.as_str()]) {
            Ok(output) => {
                let state = String::from_utf8_lossy(&output.stdout).trim().to_string();
                println!(
                    "运行状态: {}",
                    if output.status.success() {
                        state
                    } else {
                        format!(
                            "{}（可执行 systemctl --user enable --now {timer_name}）",
                            state
                        )
                    }
                );
            }
            Err(_) => println!("运行状态: 无法执行 systemctl"),
        }
        Ok(())
    }

    pub fn is_installed() -> bool {
        unit_dir()
            .map(|dir| dir.join(format!("{UNIT}.timer")).is_file())
            .unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod platform {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};

    use anyhow::{bail, Context, Result};

    use crate::paths::AppPaths;
    use crate::util::create_private_dir;

    use super::{utf16le_bom, windows_launcher_vbs, windows_task_xml, TASK_NAME};

    fn vbs_path(paths: &AppPaths) -> PathBuf {
        paths.dir().join("refresh.vbs")
    }

    fn xml_path(paths: &AppPaths) -> PathBuf {
        paths.dir().join("refresh-task.xml")
    }

    fn wscript_path() -> PathBuf {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        PathBuf::from(root).join("System32").join("wscript.exe")
    }

    fn schtasks(args: &[&str]) -> std::io::Result<Output> {
        Command::new("schtasks").args(args).output()
    }

    pub fn install(paths: &AppPaths, executable: &Path, interval_minutes: u64) -> Result<()> {
        create_private_dir(paths.dir())?;

        let vbs = vbs_path(paths);
        let xml = xml_path(paths);
        fs::write(&vbs, utf16le_bom(&windows_launcher_vbs(executable)))
            .with_context(|| format!("写入启动脚本失败: {}", vbs.display()))?;
        fs::write(
            &xml,
            utf16le_bom(&windows_task_xml(&wscript_path(), &vbs, interval_minutes)),
        )
        .with_context(|| format!("写入任务定义失败: {}", xml.display()))?;

        let xml_arg = xml.to_string_lossy().to_string();
        let output = schtasks(&["/Create", "/F", "/TN", TASK_NAME, "/XML", xml_arg.as_str()])
            .context("无法执行 schtasks，命令提示符权限可能不足")?;
        if !output.status.success() {
            bail!(
                "创建计划任务失败: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }

        println!("已安装定时刷新任务（任务计划程序）: {TASK_NAME}");
        println!("  间隔: 每 {interval_minutes} 分钟，登录时也会执行一次");
        println!("  启动脚本: {}", vbs.display());
        Ok(())
    }

    pub fn uninstall() -> Result<()> {
        let output = schtasks(&["/Delete", "/F", "/TN", TASK_NAME]);
        let removed = output
            .map(|output| output.status.success())
            .unwrap_or(false);

        if let Ok(paths) = AppPaths::from_env() {
            for path in [vbs_path(&paths), xml_path(&paths)] {
                if path.exists() {
                    let _ = fs::remove_file(&path);
                }
            }
        }

        if removed {
            println!("已卸载定时刷新任务");
        } else {
            println!("未安装定时刷新任务");
        }
        Ok(())
    }

    pub fn status() -> Result<()> {
        println!("平台: Windows（任务计划程序）");
        let output = schtasks(&["/Query", "/TN", TASK_NAME]);
        let installed = output
            .map(|output| output.status.success())
            .unwrap_or(false);
        if installed {
            println!("任务名: {TASK_NAME}");
            println!("状态: 已安装");
        } else {
            println!("状态: 未安装");
            println!("安装: fnos-git-auth schedule install");
        }
        Ok(())
    }

    pub fn is_installed() -> bool {
        schtasks(&["/Query", "/TN", TASK_NAME])
            .map(|output| output.status.success())
            .unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// 其他平台
// ---------------------------------------------------------------------------

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
mod platform {
    use std::path::Path;

    use anyhow::{bail, Result};

    use crate::paths::AppPaths;

    pub fn install(_paths: &AppPaths, _executable: &Path, _interval_minutes: u64) -> Result<()> {
        bail!("当前平台暂不支持自动安装定时任务，请用 cron 定期执行: fnos-git-auth refresh --if-needed");
    }

    pub fn uninstall() -> Result<()> {
        Ok(())
    }

    pub fn status() -> Result<()> {
        println!("当前平台暂不支持自动安装定时任务");
        Ok(())
    }

    pub fn is_installed() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn plist_contains_program_and_interval() {
        let plist = launch_agent_plist(
            Path::new("/usr/local/bin/fnos-git-auth"),
            30,
            Path::new("/home/u/.fnos-git-auth/logs/refresh.log"),
        );
        assert!(plist.contains("<string>com.fnos-git-auth.refresh</string>"));
        assert!(plist.contains("<string>/usr/local/bin/fnos-git-auth</string>"));
        assert!(plist.contains("<integer>1800</integer>"));
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(plist.contains("/home/u/.fnos-git-auth/logs/refresh.log"));
    }

    #[test]
    fn plist_escapes_special_characters() {
        let plist = launch_agent_plist(Path::new("/tmp/a&b"), 15, Path::new("/tmp/log"));
        assert!(plist.contains("/tmp/a&amp;b"));
        assert!(plist.contains("<integer>900</integer>"));
    }

    #[test]
    fn systemd_units_contain_interval() {
        let service = systemd_service(Path::new("/usr/local/bin/fnos-git-auth"));
        assert!(service.contains("ExecStart=\"/usr/local/bin/fnos-git-auth\" refresh --if-needed"));

        let timer = systemd_timer(45);
        assert!(timer.contains("OnUnitActiveSec=45min"));
        assert!(timer.contains("Persistent=true"));
    }

    #[test]
    fn windows_task_has_two_triggers_and_repetition() {
        let xml = windows_task_xml(
            Path::new("C:\\Windows\\System32\\wscript.exe"),
            Path::new("C:\\Users\\u\\.fnos-git-auth\\refresh.vbs"),
            30,
        );
        assert!(xml.contains("<LogonTrigger>"));
        assert!(xml.contains("<CalendarTrigger>"));
        assert!(xml.contains("<Interval>PT30M</Interval>"));
        assert!(xml.contains("C:\\Windows\\System32\\wscript.exe"));
        assert!(xml.contains("//B &quot;C:\\Users\\u\\.fnos-git-auth\\refresh.vbs&quot;"));
    }

    #[test]
    fn windows_vbs_quotes_executable() {
        let vbs = windows_launcher_vbs(Path::new("C:\\Program Files\\fnos\\fnos-git-auth.exe"));
        assert!(
            vbs.contains("\"\"C:\\Program Files\\fnos\\fnos-git-auth.exe\"\" refresh --if-needed")
        );
        assert!(vbs.contains(", 0, True"));
    }

    #[test]
    fn utf16le_has_bom() {
        let bytes = utf16le_bom("ab");
        assert_eq!(&bytes[..2], &[0xFF, 0xFE]);
        assert_eq!(&bytes[2..], &[0x61, 0x00, 0x62, 0x00]);
    }
}
