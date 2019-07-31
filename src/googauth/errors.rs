use failure::Fail;
use std::process::exit;

pub fn handle_error<T: Fail>(fail: &T, msg: &'static str) {
    let mut err_msg = format!("ERROR: {}", msg);
    let mut cur_fail: Option<&dyn Fail> = Some(fail);
    while let Some(cause) = cur_fail {
        err_msg += &format!("\n    caused by: {}", cause);
        cur_fail = cause.cause();
    }
    println!("{}", err_msg);
    exit(1);
}
