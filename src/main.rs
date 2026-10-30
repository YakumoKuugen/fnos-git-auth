use std::process::ExitCode;

#[cfg(windows)]
struct ConsoleEncoding {
    output: u32,
    input: u32,
}

#[cfg(windows)]
impl Drop for ConsoleEncoding {
    fn drop(&mut self) {
        #[link(name = "kernel32")]
        extern "system" {
            fn SetConsoleOutputCP(code_page: u32) -> i32;
            fn SetConsoleCP(code_page: u32) -> i32;
        }
        unsafe {
            SetConsoleOutputCP(self.output);
            SetConsoleCP(self.input);
        }
    }
}

#[cfg(windows)]
fn enable_utf8_console() -> ConsoleEncoding {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetConsoleOutputCP() -> u32;
        fn GetConsoleCP() -> u32;
        fn SetConsoleOutputCP(code_page: u32) -> i32;
        fn SetConsoleCP(code_page: u32) -> i32;
    }

    // 中文 Windows 控制台默认代码页是 936；临时切到 UTF-8，退出时恢复。
    let output = unsafe { GetConsoleOutputCP() };
    let input = unsafe { GetConsoleCP() };
    unsafe {
        SetConsoleOutputCP(65001);
        SetConsoleCP(65001);
    }
    ConsoleEncoding { output, input }
}

#[cfg(not(windows))]
struct ConsoleEncoding;

#[cfg(not(windows))]
fn enable_utf8_console() -> ConsoleEncoding {
    ConsoleEncoding
}

#[tokio::main]
async fn main() -> ExitCode {
    let _console = enable_utf8_console();
    match fnos_git_auth::cli::run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::FAILURE
        }
    }
}
