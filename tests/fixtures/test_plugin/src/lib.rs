// Only compile for WASM targets
#![cfg_attr(target_arch = "wasm32", no_std)]
#![allow(static_mut_refs)]

#[cfg(target_arch = "wasm32")]
extern crate alloc;

#[cfg(target_arch = "wasm32")]
use core::alloc::{GlobalAlloc, Layout};

// Simple bump allocator for WASM
#[cfg(target_arch = "wasm32")]
struct BumpAllocator;

#[cfg(target_arch = "wasm32")]
const HEAP_SIZE: usize = 65536;
#[cfg(target_arch = "wasm32")]
static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];
#[cfg(target_arch = "wasm32")]
static mut HEAP_POS: usize = 0;

#[cfg(target_arch = "wasm32")]
unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size();
        let align = layout.align();

        // Align up
        let pos = (HEAP_POS + align - 1) & !(align - 1);
        if pos + size > HEAP_SIZE {
            return core::ptr::null_mut();
        }

        HEAP_POS = pos + size;
        HEAP.as_mut_ptr().add(pos)
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // No-op for bump allocator
    }
}

#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// Memory exports
#[no_mangle]
pub extern "C" fn alloc(size: u32) -> u32 {
    let layout = Layout::from_size_align(size as usize, 1).unwrap();
    unsafe { ALLOCATOR.alloc(layout) as u32 }
}

#[no_mangle]
pub extern "C" fn dealloc(_ptr: u32, _size: u32) {
    // No-op for bump allocator
}

// Helper to return a string as packed i64: (ptr << 32) | len
fn return_json(s: &str) -> i64 {
    let ptr = alloc(s.len() as u32);
    if ptr == 0 {
        return 0;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(s.as_ptr(), ptr as *mut u8, s.len());
    }
    ((ptr as i64) << 32) | (s.len() as i64)
}

#[no_mangle]
pub extern "C" fn plugin_info() -> i64 {
    return_json(r#"{"ok":{"id":"test","name":"Test Plugin","version":"1.0.0","api_version":"1","required_secrets":[],"icon_url":null,"config_schema":null}}"#)
}

#[no_mangle]
pub extern "C" fn get_authorize_url(_ptr: u32, _len: u32) -> i64 {
    return_json(r#"{"ok":"https://example.com/oauth?state=test"}"#)
}

#[no_mangle]
pub extern "C" fn handle_callback(_ptr: u32, _len: u32) -> i64 {
    return_json(r#"{"ok":{"access_token":"test-token","token_type":"Bearer","expires_at":null,"refresh_token":null}}"#)
}

#[no_mangle]
pub extern "C" fn refresh_tokens(_ptr: u32, _len: u32) -> i64 {
    return_json(r#"{"ok":{"access_token":"refreshed-token","token_type":"Bearer","expires_at":null,"refresh_token":null}}"#)
}

#[no_mangle]
pub extern "C" fn get_profile(_ptr: u32, _len: u32) -> i64 {
    return_json(r#"{"ok":{"account_id":"12345","display_name":"Test User","profile_url":null,"avatar_url":null}}"#)
}

#[no_mangle]
pub extern "C" fn sync_account(_ptr: u32, _len: u32) -> i64 {
    return_json(r#"{"ok":[]}"#)
}
