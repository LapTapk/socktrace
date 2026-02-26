#[macro_export]
macro_rules! log_err {
    ($err:expr) => {
        eprintln!("[{}:{}] error: {}", file!(), line!(), $err);
    };
}

#[macro_export]
macro_rules! ctx {
    ($expr:expr, $($arg:tt)*) => {
        $expr.with_context(|| format!($($arg)*))
    };
}
