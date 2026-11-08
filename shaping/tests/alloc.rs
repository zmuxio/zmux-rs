//! A shaped record allocates nothing once the pipe's instance exists.

#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};

use zmux::PipeId;
use zmux::shaping::{Effects, Event, EventKind, RecordPlan, RecordView, Shaper};
use zmux_shaping::{MachineFactory, Options};

struct Counting;
static COUNT: AtomicU64 = AtomicU64::new(0);

// SAFETY: forwards to the system allocator.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        COUNT.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
}

#[global_allocator]
static A: Counting = Counting;

const DEF: &str = r#"{"tables":{"a":[[3,100,1400],[1,0,0],[1,4000,9000]]},"machines":[
 {"start":0,"counters":1,"timers":1,"states":[
  {"record":{"target":{"t":"a"},"pad_multiple":{"t":[[1,16,64]],"scope":"pipe"},"delay":{"t":[[1,0,0],[1,1,5]]}},
   "enter":[{"op":"set","slot":0,"value":3},{"op":"timer","slot":0,"after":{"t":[[1,10,100]]}},
            {"op":"inject","after":1000,"len":{"t":"a"}},{"op":"rate","rate":100000}],
   "next":[{"on":"record_out","to":1,"if":{"what":"seq","cmp":"ge","value":2},"prob":500000}]},
  {"record":{"max_len":1200},
   "enter":[{"op":"sub","slot":0,"value":1},{"op":"weight","value":{"t":[[1,1,9]]}}],
   "next":[{"on":"timer","slot":0,"to":0},{"on":"record_in","to":0},{"on":"record_out","to":0,"prob":100000}]}]},
 {"start":0,"states":[{"record":{"pad":{"t":[[1,0,16]]}},"next":[{"on":"injected","to":0}]}]}]}"#;

#[test]
fn plans_and_events_do_not_allocate() {
    let f = MachineFactory::from_json(DEF.as_bytes(), Options::default()).unwrap();
    let mut m = f.shaper();
    let mut now = 0;
    let step = |m: &mut zmux_shaping::MachineShaper, now: &mut u64| {
        *now += 50;
        let mut plan = RecordPlan::default();
        m.plan(
            &RecordView::new(PipeId::new(0), 0, 0, 16382, *now),
            &mut plan,
        );
        for kind in [EventKind::Wake, EventKind::Injected, EventKind::RecordIn] {
            let mut fx = Effects::default();
            m.on_event(
                &Event::new(kind, PipeId::new(0), *now).with_len(100, false),
                &mut fx,
            );
        }
    };
    let mut fx = Effects::default();
    m.on_event(&Event::new(EventKind::Start, PipeId::new(0), 0), &mut fx);
    step(&mut m, &mut now);
    let before = COUNT.load(Ordering::Relaxed);
    for _ in 0..100_000 {
        step(&mut m, &mut now);
    }
    let n = COUNT.load(Ordering::Relaxed) - before;
    println!("allocations over 100000 rounds: {n}");
    assert_eq!(n, 0);
}
