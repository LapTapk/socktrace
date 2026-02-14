use clap::Parser;

#[derive(Parser, Debug)]
struct Cli {
    #[arg(env = "SOCKTRACE_SOCK")]
    sock: Option<String>,

    #[arg(env = "SOCKTRACE_TARGET")]
    target: Vec<String>   
}

fn main() -> nix::Result<()> {
    let args = Cli::parse();
    Ok(())
}
