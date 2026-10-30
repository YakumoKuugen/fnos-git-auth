//! 命令行入口与交互式登录流程。

use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand};
use serde_json::Value;

use crate::auth::{AuthService, LoginOptions};
use crate::config::{default_preferences, display_value, ConfigStore};
use crate::credentials::CredentialsStore;
use crate::diagnostic;
use crate::git::{ensure_git_available, GitRunner};
use crate::paths::AppPaths;
use crate::update;
use crate::util::normalize_server;

#[derive(Parser, Debug)]
#[command(
    name = "fnos-git-auth",
    bin_name = "fnos-git-auth",
    version,
    about = "飞牛 fnOS Git 认证工具",
    long_about = "飞牛 fnOS Git 认证工具\n\n自动配置 git extraHeader 实现通过 fn connect 服务免密访问 fnOS NAS 上的 Git 仓库。",
    disable_help_subcommand = true,
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// 登录到 fnOS 服务器
    Login(LoginArgs),
    /// 登出并清除 token
    Logout(LogoutArgs),
    /// 查看认证状态
    Status,
    /// 刷新 token
    Refresh(RefreshArgs),
    /// 检查并更新工具
    Update(UpdateArgs),
    /// 查看或设置配置
    Config(ConfigArgs),
    /// 管理 git 配置
    #[command(name = "git")]
    Git(GitArgs),
    /// 生成诊断信息包
    Diagnostic(DiagnosticArgs),
}

#[derive(Args, Debug)]
pub struct LoginArgs {
    /// fnOS 服务器地址 (如: xxx.fnos.net)
    #[arg(short = 's', long)]
    pub server: Option<String>,
    /// 用户名
    #[arg(short = 'u', long)]
    pub username: Option<String>,
    /// 密码
    #[arg(short = 'p', long)]
    pub password: Option<String>,
    /// 不保存凭据
    #[arg(short = 'n', long)]
    pub no_save: bool,
    /// 两步验证码（6 位数字）；不提供时在登录过程中提示输入
    #[arg(long)]
    pub code: Option<String>,
    /// 将当前设备标记为可信设备，减少后续两步验证
    #[arg(long)]
    pub trust_device: bool,
}

#[derive(Args, Debug)]
pub struct LogoutArgs {
    /// 同时删除保存的凭据
    #[arg(short = 'a', long = "all")]
    pub clear_all: bool,
}

#[derive(Args, Debug)]
pub struct RefreshArgs {
    /// 仅在 token 即将过期时刷新（供 git hook 调用）
    #[arg(long, hide = true)]
    pub if_needed: bool,
}

#[derive(Args, Debug)]
pub struct UpdateArgs {
    /// 仅检查，不下载
    #[arg(short = 'c', long)]
    pub check: bool,
    /// 强制更新
    #[arg(short = 'f', long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct ConfigArgs {
    /// 配置项名称
    #[arg(short = 'k', long)]
    pub key: Option<String>,
    /// 配置值
    #[arg(short = 'v', long)]
    pub value: Option<String>,
    /// 重置所有配置
    #[arg(short = 'r', long)]
    pub reset: bool,
}

#[derive(Args, Debug)]
pub struct GitArgs {
    /// 显示 extraHeader 配置
    #[arg(short = 's', long)]
    pub show: bool,
    /// 清除所有配置
    #[arg(short = 'c', long)]
    pub clear: bool,
    /// 清除指定服务器配置
    #[arg(short = 'r', long)]
    pub remove: Option<String>,
    /// 设置凭证缓存时间（秒）
    #[arg(short = 't', long)]
    pub timeout: Option<u64>,
}

#[derive(Args, Debug)]
pub struct DiagnosticArgs {
    /// 输出目录
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,
    /// 仅打印到控制台
    #[arg(short = 'p', long)]
    pub print: bool,
}

struct LoginInput {
    server: String,
    username: String,
    password: String,
    password_entered: bool,
}

pub async fn run() -> Result<()> {
    let cli = Cli::parse();
    let paths = AppPaths::from_env()?;
    let git = GitRunner::new();

    match cli.command {
        Commands::Login(args) => run_login(&paths, &git, args).await,
        Commands::Logout(args) => run_logout(&paths, &git, args),
        Commands::Status => {
            AuthService::new(paths).status();
            Ok(())
        }
        Commands::Refresh(args) => run_refresh(&paths, &git, args).await,
        Commands::Update(args) => run_update(args),
        Commands::Config(args) => run_config(&paths, args),
        Commands::Git(args) => run_git(&git, args),
        Commands::Diagnostic(args) => run_diagnostic(&paths, &git, args),
    }
}

async fn run_login(paths: &AppPaths, git: &GitRunner, args: LoginArgs) -> Result<()> {
    ensure_git_available(git)?;
    let auto_save = ConfigStore::new(paths.clone()).pref_bool("auto_save_credentials", true);
    let no_save = args.no_save;
    let options = LoginOptions {
        two_factor_code: args.code.clone(),
        trust_device: args.trust_device,
        interactive_two_factor: true,
    };
    let input = gather_login(paths, args)?;

    AuthService::new(paths.clone())
        .login_with_options(&input.server, &input.username, &input.password, options)
        .await
        .map_err(|error| anyhow!("登录失败: {error:#}"))?;

    if no_save || !input.password_entered || !auto_save {
        return Ok(());
    }

    if prompt_confirm("是否保存账号密码?", true)? {
        CredentialsStore::new(paths.clone()).save(&input.username, &input.password)?;
        println!("已保存凭据");
    }
    Ok(())
}

fn run_logout(paths: &AppPaths, git: &GitRunner, args: LogoutArgs) -> Result<()> {
    ensure_git_available(git)?;
    let result = AuthService::new(paths.clone()).logout();

    if args.clear_all {
        CredentialsStore::new(paths.clone()).delete()?;
        println!("已删除保存的凭据");
    }
    result
}

async fn run_refresh(paths: &AppPaths, git: &GitRunner, args: RefreshArgs) -> Result<()> {
    ensure_git_available(git)?;
    AuthService::new(paths.clone())
        .refresh(args.if_needed)
        .await
        .map_err(|error| anyhow!("刷新失败: {error:#}"))
}

fn run_update(args: UpdateArgs) -> Result<()> {
    let info = match update::check_for_updates() {
        Ok(info) => info,
        Err(error) => {
            println!("当前版本: {}", update::current_version());
            println!("无法获取最新版本信息: {error:#}");
            return Ok(());
        }
    };
    update::print_update_info(&info)?;

    if args.check {
        return Ok(());
    }
    if info.has_update || args.force {
        if args.force && !info.has_update {
            println!("强制重新下载...");
        }
        update::install_from_info(&info)?;
    }
    Ok(())
}

fn run_config(paths: &AppPaths, args: ConfigArgs) -> Result<()> {
    let store = ConfigStore::new(paths.clone());

    if args.reset {
        store.reset_preferences()?;
        println!("已重置所有配置为默认值");
        return Ok(());
    }

    let Some(key) = args.key else {
        println!("当前配置:");
        for (key, value) in store.preferences() {
            let default = default_preferences().get(&key).cloned();
            let is_default = default.as_ref() == Some(&value);
            println!(
                "  {key}: {}{}",
                display_value(&value),
                if is_default { " (默认)" } else { "" }
            );
        }
        return Ok(());
    };

    if args.value.is_none() {
        match store.preference(&key) {
            Some(value) => println!("{key}: {}", display_value(&value)),
            None => println!("未知配置项: {key}"),
        }
        return Ok(());
    }

    let defaults = default_preferences();
    let Some(default) = defaults.get(&key) else {
        let valid: Vec<String> = defaults.keys().cloned().collect();
        bail!(
            "错误: 未知配置项 '{key}'\n有效的配置项:\n  {}",
            valid.join("\n  ")
        );
    };
    let value = args.value.unwrap_or_default();
    let parsed = parse_preference_value(&value, default)
        .with_context(|| format!("配置项 {key} 的值无效"))?;
    store.set_preference(&key, parsed.clone())?;
    println!("已设置 {key} = {}", display_value(&parsed));
    Ok(())
}

fn parse_preference_value(value: &str, default: &Value) -> Result<Value> {
    match default {
        Value::Bool(_) => Ok(Value::Bool(matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "true" | "1" | "yes" | "on"
        ))),
        Value::Number(number) if number.is_i64() || number.is_u64() => {
            let parsed: i64 = value.trim().parse().context("请输入整数")?;
            Ok(Value::Number(parsed.into()))
        }
        Value::Number(_) => {
            let parsed: f64 = value.trim().parse().context("请输入数字")?;
            if !parsed.is_finite() {
                bail!("请输入有限数字");
            }
            Ok(serde_json::json!(parsed))
        }
        _ => Ok(Value::String(value.to_string())),
    }
}

fn run_git(git: &GitRunner, args: GitArgs) -> Result<()> {
    ensure_git_available(git)?;

    if args.show || (!args.clear && args.remove.is_none() && args.timeout.is_none()) {
        let headers = git.list_extra_headers()?;
        if headers.is_empty() {
            println!("未配置 extraHeader");
        } else {
            println!("Git extraHeader 配置:");
            for line in headers {
                println!("  {line}");
            }
        }
        return Ok(());
    }

    if args.clear {
        let removed = git.clear_all_extra_headers()?;
        if removed.is_empty() {
            println!("没有需要清除的配置");
        } else {
            for key in removed {
                println!("已清除: {key}");
            }
        }
        return Ok(());
    }

    if let Some(server) = args.remove {
        let server = normalize_server(&server).unwrap_or(server);
        git.remove_extra_header(&server)?;
        println!("已清除服务器 {server} 的配置");
        return Ok(());
    }

    if let Some(timeout) = args.timeout {
        if timeout == 0 {
            git.set_credential_cache(0)?;
            println!("已禁用 git 凭证缓存");
        } else {
            git.set_credential_cache(timeout)?;
            println!("已设置凭证缓存: {timeout} 秒");
        }
    }
    Ok(())
}

fn run_diagnostic(paths: &AppPaths, git: &GitRunner, args: DiagnosticArgs) -> Result<()> {
    if args.print {
        return diagnostic::print_info(paths, git);
    }
    let path = diagnostic::create_package(paths, git, args.output.as_deref())
        .map_err(|error| anyhow!("生成失败: {error:#}"))?;
    println!("诊断包已生成: {}", path.display());
    println!("敏感信息已脱敏，可安全上传。");
    Ok(())
}

fn gather_login(paths: &AppPaths, args: LoginArgs) -> Result<LoginInput> {
    let store = ConfigStore::new(paths.clone());
    let saved_server = store.server_url();
    let saved_credentials = CredentialsStore::new(paths.clone()).get();

    let mut server = match args.server.as_deref() {
        Some(server) => normalize_server(server),
        None => saved_server.as_deref().and_then(normalize_server),
    };
    while server.is_none() {
        let input = prompt_line("服务器地址")?;
        server = normalize_server(&input);
    }
    let server = server.unwrap();

    let server_changed = saved_server
        .as_deref()
        .map(|saved| !saved.eq_ignore_ascii_case(&server))
        .unwrap_or(true);

    let saved_username = saved_credentials.as_ref().map(|c| c.username.as_str());
    let saved_password = saved_credentials.as_ref().map(|c| c.password.as_str());

    let username = match args.username {
        Some(username) => username,
        None if !server_changed && saved_username.is_some() && saved_password.is_some() => {
            saved_username.unwrap().to_string()
        }
        None => {
            let value = prompt_line("用户名")?;
            if value.trim().is_empty() {
                bail!("用户名不能为空");
            }
            value.trim().to_string()
        }
    };

    let (password, password_entered) = match args.password {
        Some(password) => (password, false),
        None if !server_changed
            && saved_username.is_some()
            && saved_password.is_some()
            && saved_username == Some(username.as_str()) =>
        {
            (saved_password.unwrap().to_string(), false)
        }
        None => (prompt_password("密码")?, true),
    };

    Ok(LoginInput {
        server,
        username,
        password,
        password_entered,
    })
}

fn prompt_line(label: &str) -> Result<String> {
    print!("{label}: ");
    io::stdout().flush().ok();
    let mut input = String::new();
    let read = io::stdin()
        .read_line(&mut input)
        .with_context(|| format!("读取{label}失败"))?;
    if read == 0 {
        bail!("无法读取输入，请在交互式终端中运行，或使用 -s/-u/-p 参数");
    }
    Ok(input.trim_end_matches(['\r', '\n']).to_string())
}

fn prompt_password(label: &str) -> Result<String> {
    let password = if io::stdin().is_terminal() {
        rpassword::prompt_password(format!("{label}: ")).context("读取密码失败")?
    } else {
        print!("{label}: ");
        io::stdout().flush().ok();
        let mut input = String::new();
        let read = io::stdin().read_line(&mut input).context("读取密码失败")?;
        if read == 0 {
            bail!("无法读取密码，请使用 -p 参数");
        }
        input.trim_end_matches(['\r', '\n']).to_string()
    };
    if password.is_empty() {
        bail!("密码不能为空");
    }
    Ok(password)
}

fn prompt_confirm(label: &str, default: bool) -> Result<bool> {
    let hint = if default { "[Y/n]" } else { "[y/N]" };
    loop {
        print!("{label} {hint} ");
        io::stdout().flush().ok();
        let mut input = String::new();
        let read = io::stdin()
            .read_line(&mut input)
            .context("读取确认信息失败")?;
        if read == 0 {
            return Ok(false);
        }
        match input.trim().to_ascii_lowercase().as_str() {
            "" => return Ok(default),
            "y" | "yes" | "是" => return Ok(true),
            "n" | "no" | "否" => return Ok(false),
            _ => {}
        }
    }
}

/// 暴露命令定义，方便测试帮助信息和命令列表。
pub fn command() -> clap::Command {
    Cli::command()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_commands_are_registered() {
        let names: Vec<String> = command()
            .get_subcommands()
            .map(|command| command.get_name().to_string())
            .collect();
        for expected in [
            "login",
            "logout",
            "status",
            "refresh",
            "update",
            "config",
            "git",
            "diagnostic",
        ] {
            assert!(names.contains(&expected.to_string()));
        }
    }

    #[test]
    fn parses_login_arguments() {
        let cli = Cli::try_parse_from([
            "fnos-git-auth",
            "login",
            "-s",
            "demo.fnos.net",
            "-u",
            "alice",
            "-p",
            "secret",
            "-n",
            "--code",
            "583213",
            "--trust-device",
        ])
        .unwrap();
        match cli.command {
            Commands::Login(args) => {
                assert_eq!(args.server.as_deref(), Some("demo.fnos.net"));
                assert_eq!(args.username.as_deref(), Some("alice"));
                assert_eq!(args.password.as_deref(), Some("secret"));
                assert_eq!(args.code.as_deref(), Some("583213"));
                assert!(args.trust_device);
                assert!(args.no_save);
            }
            _ => panic!("wrong command"),
        }
    }

    #[test]
    fn parses_git_and_config_flags() {
        let cli = Cli::try_parse_from(["fnos-git-auth", "git", "-s"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Git(GitArgs { show: true, .. })
        ));

        let cli =
            Cli::try_parse_from(["fnos-git-auth", "config", "-k", "timeout", "-v", "60"]).unwrap();
        match cli.command {
            Commands::Config(args) => {
                assert_eq!(args.key.as_deref(), Some("timeout"));
                assert_eq!(args.value.as_deref(), Some("60"));
            }
            _ => panic!("wrong command"),
        }
    }

    #[test]
    fn parses_preference_types() {
        assert_eq!(
            parse_preference_value("false", &serde_json::json!(true)).unwrap(),
            serde_json::json!(false)
        );
        assert_eq!(
            parse_preference_value("42", &serde_json::json!(8)).unwrap(),
            serde_json::json!(42)
        );
        assert_eq!(
            parse_preference_value("45.5", &serde_json::json!(30.0)).unwrap(),
            serde_json::json!(45.5)
        );
        assert!(parse_preference_value("abc", &serde_json::json!(30.0)).is_err());
    }
}
