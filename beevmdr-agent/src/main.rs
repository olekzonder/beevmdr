use anyhow::{Result, bail};
use bazaar::BazaarHashDB;
use cache::Key;
use cache::Value;
use std::mem;
use std::mem::MaybeUninit;
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::skel::SkelBuilder as _;
use libbpf_rs::skel::OpenSkel as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc,Mutex};
use std::time::Duration;
use std::collections::HashMap;
use std::path::Path;

mod cache;
mod bazaar;
mod beevmdr {
    include!(concat!(env!("OUT_DIR"), "/beevmdr.skel.rs"));
}
use beevmdr::*;

const TASK_COMM_LEN: usize = 16;
const MAX_FILE_SIZE: usize = 255;

#[repr(C)]
struct Output {
    ts: u64,
    pid: u32,
    comm: [u8; TASK_COMM_LEN],
    filename: [u8; MAX_FILE_SIZE],
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

fn event_handler(data: &[u8], table: &Arc<Mutex<HashMap<Key, Value>>>, bazaar: &BazaarHashDB) -> ::std::os::raw::c_int {
    if data.len() != mem::size_of::<Output>() {
        eprintln!(
            "Invalid size {} != {}",
            data.len(),
            mem::size_of::<Output>()
        );
        return -1;
    }
    let event = unsafe { &*(data.as_ptr() as *const Output) };
    
    let comm = String::from_utf8_lossy(&event.comm);
    let comm = comm.trim_end_matches('\0');
    
    let filename_bytes = &event.filename;
    let filename = if let Some(null_pos) = filename_bytes.iter().position(|&x| x == 0) {
        String::from_utf8_lossy(&filename_bytes[..null_pos]).into_owned()
    } else {
        String::from_utf8_lossy(filename_bytes).into_owned()
    };

    if Path::new(&filename).starts_with("/proc") {
        return 0;
    }
    if let Some(mut value) = cache::lookup_or_insert(table, &filename) {
        if !value.checked {
            if bazaar.contains_hash(&value.sha256) {
                println!("[ALERT] Malicious binary detected!");
                println!("comm: {:?}, path: {} sha256: {}", comm, filename, value.sha256);
            }
        }
        value.checked = true;
    }
    0
}

fn main() -> Result<()> {
    bump_memlock_rlimit()?;
    let bazaar = BazaarHashDB::load("/opt/bazaar.txt")?;
    let table = cache::new_shared_table(); // Create shared hash table

    let skel_builder = BeevmdrSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object).unwrap();
    let skel = open_skel.load().unwrap();
    let _links = skel.progs.trace_exec.attach()?;
    
    let map = skel.maps.rb;

    let table_clone = Arc::clone(&table);
    let mut builder = RingBufferBuilder::new();
    builder
        .add(&map, move |data| event_handler(data, &table_clone, &bazaar))
        .unwrap();

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    let ringbuf = builder.build().unwrap();
    println!("Waiting for events...");

    while running.load(Ordering::SeqCst) {
        ringbuf.poll(Duration::from_millis(100))?;
    }

    Ok(())
}