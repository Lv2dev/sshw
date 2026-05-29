use sshw::cli;

fn main() {
    let exit_code = match cli::run() {
        Ok(exit_code) => exit_code,
        Err(err) => {
            eprintln!("{err}");
            1
        }
    };
    std::process::exit(exit_code);
}
