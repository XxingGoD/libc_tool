use std::io::{self, Write};
use std::process;

struct MenuOption {
    key: &'static str,
    title: &'static str,
    description: &'static str,
}

const OPTIONS: [MenuOption; 4] = [
    MenuOption {
        key: "1",
        title: "Quick Start",
        description: "使用默认配置，快速生成初始化结果",
    },
    MenuOption {
        key: "2",
        title: "Advanced",
        description: "逐项选择端口、路径和附加选项",
    },
    MenuOption {
        key: "3",
        title: "Import",
        description: "导入已有配置文件并继续调整",
    },
    MenuOption {
        key: "q",
        title: "Quit",
        description: "退出向导",
    },
];

fn print_intro() {
    println!("libc_tool Rust wizard demo");
    println!("=========================");
    println!("这个示例演示一个最小终端交互向导。");
    println!();
}

fn print_menu() {
    println!("请选择初始化模式：");
    for option in OPTIONS {
        println!("  [{}] {:<11} {}", option.key, option.title, option.description);
    }
    println!();
}

fn prompt_line(prompt: &str) -> io::Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn prompt_choice() -> String {
    loop {
        match prompt_line("> ") {
            Ok(choice) if choice.is_empty() => {
                println!("默认选择 Quick Start。");
                return "1".to_string();
            }
            Ok(choice) => {
                if OPTIONS.iter().any(|option| option.key == choice) {
                    return choice;
                }
                println!("无效输入，请重新选择。");
            }
            Err(err) => {
                eprintln!("读取输入失败: {err}");
                process::exit(1);
            }
        }
    }
}

fn prompt_confirm(message: &str, default_yes: bool) -> bool {
    let suffix = if default_yes { "[Y/n]" } else { "[y/N]" };
    loop {
        let prompt = format!("{message} {suffix} ");
        match prompt_line(&prompt) {
            Ok(answer) if answer.is_empty() => return default_yes,
            Ok(answer) => match answer.to_ascii_lowercase().as_str() {
                "y" | "yes" => return true,
                "n" | "no" => return false,
                _ => println!("请输入 y 或 n。"),
            },
            Err(err) => {
                eprintln!("读取输入失败: {err}");
                process::exit(1);
            }
        }
    }
}

fn run_quick_start() {
    println!();
    println!("已选择 Quick Start");
    println!("将使用默认端口 10001、默认 gdb 端口 1234。");
    if prompt_confirm("继续生成配置吗？", true) {
        println!("已确认，下一步可以执行实际初始化逻辑。");
    } else {
        println!("已取消。");
    }
}

fn run_advanced() {
    println!();
    println!("已选择 Advanced");
    let port = prompt_line("请输入服务端口 [10001]: ").unwrap_or_default();
    let gdb_port = prompt_line("请输入 gdb 端口 [1234]: ").unwrap_or_default();
    let port = if port.is_empty() { "10001" } else { port.as_str() };
    let gdb_port = if gdb_port.is_empty() { "1234" } else { gdb_port.as_str() };
    println!("已记录端口配置: service={port}, gdb={gdb_port}");
}

fn run_import() {
    println!();
    println!("已选择 Import");
    let path = prompt_line("请输入配置文件路径: ").unwrap_or_default();
    if path.is_empty() {
        println!("未输入路径，已取消导入。");
    } else {
        println!("这里可以继续实现读取配置文件: {path}");
    }
}

fn main() {
    print_intro();
    print_menu();
    match prompt_choice().as_str() {
        "1" => run_quick_start(),
        "2" => run_advanced(),
        "3" => run_import(),
        "q" => println!("已退出。"),
        _ => unreachable!(),
    }
}
