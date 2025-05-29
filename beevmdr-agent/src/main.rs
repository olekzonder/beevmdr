use anyhow::{Result, bail};
use std::mem;
use std::mem::MaybeUninit;
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::skel::SkelBuilder as _;
use libbpf_rs::skel::OpenSkel as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod beevmdr {
    include!(concat!(env!("OUT_DIR"), "/beevmdr.skel.rs"));
}
use beevmdr::*;

const TASK_COMM_LEN: usize = 16;
const MAX_FILE_SIZE: usize = 255; // Renamed to match BPF

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

fn event_handler(data: &[u8]) -> ::std::os::raw::c_int {
    if data.len() != mem::size_of::<Output>() {
        eprintln!(
            "Invalid size {} != {}",
            data.len(),
            mem::size_of::<Output>()
        );
        return -1;
    }
    let event = unsafe { &*(data.as_ptr() as *const Output) };
    
    // Process comm
    let comm = String::from_utf8_lossy(&event.comm);
    let comm = comm.trim_end_matches('\0');
    
    // Process filename
    let filename_bytes = &event.filename;
    let filename = if let Some(null_pos) = filename_bytes.iter().position(|&x| x == 0) {
        String::from_utf8_lossy(&filename_bytes[..null_pos]).into_owned()
    } else {
        String::from_utf8_lossy(filename_bytes).into_owned()
    };
    
    println!("COMM: {} PID: {} FILENAME: {}", comm, event.pid, filename);
    0
}

fn main() -> Result<()> {
    bump_memlock_rlimit()?;

    let skel_builder = BeevmdrSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object).unwrap();
    let skel = open_skel.load().unwrap();
    let _links = skel.progs.trace_exec.attach()?;
    
    let mut builder = RingBufferBuilder::new();
    let map = skel.maps.rb;
    builder
        .add(&map, event_handler)
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