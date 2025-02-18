#[no_mangle]
pub extern "C" fn enforce(pid: i32, uid: i32) -> i32 {
    if uid == 0 {
        return 0;
    }
    1
}
