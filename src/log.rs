#[macro_export]
macro_rules! log_err {
    ($err:expr) => {
        eprintln!("[{}:{}] error: {}", file!(), line!(), $err);
    };
}
