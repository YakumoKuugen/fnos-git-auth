//! 确保仓库中的文本文件统一为 UTF-8（不带 BOM），防止编辑器产生乱码。

use std::fs;
use std::path::{Path, PathBuf};

const TEXT_EXTENSIONS: &[&str] = &["rs", "toml", "md", "yml", "yaml", "lock"];
const TEXT_FILES: &[&str] = &[".gitignore", ".gitattributes", ".editorconfig", "LICENSE"];

#[test]
fn source_files_are_utf8_without_bom() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    collect(&root, &mut files);

    assert!(!files.is_empty());
    for path in files {
        let bytes = fs::read(&path).expect("read file");
        assert!(
            !(bytes.starts_with(&[0xEF, 0xBB, 0xBF])),
            "{} 包含 UTF-8 BOM，请保存为 UTF-8（无 BOM）",
            path.display()
        );
        let text = String::from_utf8(bytes)
            .unwrap_or_else(|_| panic!("{} 不是有效 UTF-8", path.display()));
        assert!(
            !text.contains('\u{FFFD}'),
            "{} 包含乱码替换字符 U+FFFD",
            path.display()
        );
    }
}

fn collect(dir: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if matches!(name.as_ref(), "target" | ".git") {
                continue;
            }
            collect(&path, files);
            continue;
        }
        let is_text = path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| TEXT_EXTENSIONS.contains(&extension))
            || TEXT_FILES.contains(&name.as_ref());
        if is_text {
            files.push(path);
        }
    }
}
