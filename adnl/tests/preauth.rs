use adnl::preauth::{
    preauth_source, AdmissionError as Error, DecryptBudget, PreauthGate, RateLimiter,
};
use std::{
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::{Arc, Barrier},
};

fn addr(id: u8) -> SocketAddr {
    format!("192.0.2.{id}:1234").parse().unwrap()
}
fn budget(burst: u32, limit: usize) -> Arc<DecryptBudget> {
    DecryptBudget::new(burst, 60.0, limit).unwrap()
}
fn reason<E: Default>(result: Result<adnl::preauth::Ticket<E>, Error>) -> Error {
    match result {
        Err(error) => error,
        Ok(_) => panic!("expected refusal"),
    }
}

#[test]
fn source_normalizes_port_ipv6_prefix_mapped_family_and_scope() {
    assert_eq!(preauth_source(addr(1)), "192.0.2.1:0".parse().unwrap());
    let a: SocketAddr = "[2001:db8:1234:abcd:1:2:3:4]:1234".parse().unwrap();
    let b: SocketAddr = "[2001:db8:1234:abcd:ffff:ffff:ffff:ffff]:4321".parse().unwrap();
    assert_eq!(preauth_source(a), preauth_source(b));
    assert_eq!(preauth_source(a), "[2001:db8:1234:abcd::]:0".parse().unwrap());
    let mapped: SocketAddr = "[::ffff:192.0.2.1]:1234".parse().unwrap();
    assert_eq!(preauth_source(mapped), "[::]:0".parse().unwrap());
    assert_ne!(preauth_source(mapped), preauth_source(addr(1)));
    let scoped = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 55, 7, 9));
    assert_eq!(preauth_source(scoped), "[::]:0".parse().unwrap());
}

#[test]
fn rate_capacity_refill_and_fullness_match_strict_boundaries() {
    let mut rate = RateLimiter::new(3, 2.0).unwrap();
    assert!(!rate.is_full_at(0.0));
    assert!(rate.is_full_at(0.001));
    for _ in 0..3 {
        assert!(rate.take_at(10.0));
    }
    assert!(!rate.can_take_at(10.0));
    assert!(!rate.take_at(11.999));
    assert_eq!(rate.ready_at_at(10.0), 12.0);
    assert!(rate.can_take_at(12.0));
    assert!(rate.take_at(12.0));
    assert!(!rate.take_at(f64::NAN));
    assert!(RateLimiter::new(0, 1.0).is_err());
    assert!(RateLimiter::new(1, 0.0).is_err());
    assert!(RateLimiter::new(1, f64::INFINITY).is_err());
}

#[test]
fn pinned_entries_cannot_be_evicted_until_all_tickets_drop() {
    let gate = PreauthGate::<()>::new(2, 20, 60.0).unwrap();
    let p = budget(100, 100);
    let l = budget(100, 100);
    let a = gate.admit_at(addr(1), p.clone(), l.clone(), 0.0).unwrap();
    let a2 = gate.admit_at(addr(1), p.clone(), l.clone(), 0.0).unwrap();
    let b = gate.admit_at(addr(2), p.clone(), l.clone(), 0.0).unwrap();
    assert_eq!(a.with_source(|s| s.in_flight()), 2);
    drop(a);
    assert_eq!(reason(gate.admit_at(addr(3), p.clone(), l.clone(), 0.0)), Error::SourceLimit);
    assert_eq!(gate.len(), 2);
    drop(a2);
    let c = gate.admit_at(addr(3), p.clone(), l.clone(), 0.0).unwrap();
    assert!(!gate.contains(addr(1)));
    assert!(gate.contains(addr(2)));
    drop((b, c));
    assert_eq!((p.in_flight(), l.in_flight()), (0, 0));
}

#[test]
fn refusal_priority_and_release_do_not_refund_rate_debt() {
    let gate = PreauthGate::<()>::new(4, 1, 60.0).unwrap();
    let p = budget(1, 10);
    let l = budget(1, 0);
    assert_eq!(reason(gate.admit_at(addr(1), p.clone(), l.clone(), 0.0)), Error::LocalBudget);
    assert_eq!((p.in_flight(), l.in_flight()), (0, 0));
    assert_eq!(reason(gate.admit_at(addr(1), p.clone(), l.clone(), 0.0)), Error::RateLimited);
    assert_eq!(reason(gate.admit_at(addr(2), p.clone(), l.clone(), 0.0)), Error::ProcessBudget);
    assert_eq!(gate.len(), 2);
    let gate = PreauthGate::<()>::new(8, 20, 60.0).unwrap();
    let p = budget(1, 1);
    let l = budget(100, 100);
    let a = gate.admit_at(addr(1), p.clone(), l.clone(), 0.0).unwrap();
    assert_eq!(reason(gate.admit_at(addr(2), p.clone(), l.clone(), 60.0)), Error::ProcessBudget);
    drop(a);
    let b = gate.admit_at(addr(3), p.clone(), l.clone(), 60.0).unwrap();
    drop(b);
    assert_eq!(reason(gate.admit_at(addr(4), p.clone(), l.clone(), 60.0)), Error::ProcessBudget);
}

#[test]
fn refused_idle_source_is_touched_before_eviction() {
    let gate = PreauthGate::<()>::new(2, 1, 60.0).unwrap();
    let p = budget(100, 100);
    let l = budget(100, 100);
    drop(gate.admit_at(addr(1), p.clone(), l.clone(), 0.0).unwrap());
    drop(gate.admit_at(addr(2), p.clone(), l.clone(), 0.0).unwrap());
    assert_eq!(reason(gate.admit_at(addr(1), p.clone(), l.clone(), 0.0)), Error::RateLimited);
    let c = gate.admit_at(addr(3), p.clone(), l.clone(), 0.0).unwrap();
    assert!(gate.contains(addr(1)));
    assert!(!gate.contains(addr(2)));
    assert!(gate.contains(addr(3)));
    drop(c);
}

#[test]
fn owned_ticket_pins_extra_and_budgets_after_gate_handle_drops() {
    let gate = PreauthGate::<u32>::new(2, 10, 60.0).unwrap();
    let p = budget(100, 100);
    let l = budget(100, 100);
    let a = gate.admit_at(addr(1), p.clone(), l.clone(), 0.0).unwrap();
    a.with_source(|s| s.extra = 7);
    let b = gate.admit_at(addr(2), p.clone(), l.clone(), 0.0).unwrap();
    drop(a);
    gate.erase_idle_if(|s| s.extra == 7);
    assert_eq!(gate.len(), 1);
    assert!(gate.contains(addr(2)));
    gate.erase_idle_if(|_| true);
    assert_eq!(gate.len(), 1);
    drop(gate);
    b.with_source(|s| s.extra = 9);
    assert_eq!(b.with_source(|s| s.extra), 9);
    drop(b);
    assert_eq!((p.in_flight(), l.in_flight()), (0, 0));
}

#[test]
fn aliased_pools_are_charged_and_released_twice() {
    let gate = PreauthGate::<()>::new(2, 10, 60.0).unwrap();
    let shared = budget(10, 1);
    assert_eq!(
        reason(gate.admit_at(addr(1), shared.clone(), shared.clone(), 0.0)),
        Error::LocalBudget
    );
    assert_eq!(shared.in_flight(), 0);
    let shared = budget(10, 2);
    let ticket = gate.admit_at(addr(1), shared.clone(), shared.clone(), 0.0).unwrap();
    assert_eq!(shared.in_flight(), 2);
    drop(ticket);
    assert_eq!(shared.in_flight(), 0);
}

#[test]
fn callback_panic_recovery_keeps_ticket_and_idle_invariants() {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    let gate = PreauthGate::<u32>::new(2, 10, 60.0).unwrap();
    let p = budget(100, 100);
    let l = budget(100, 100);
    let ticket = gate.admit_at(addr(1), p.clone(), l.clone(), 0.0).unwrap();
    assert!(catch_unwind(AssertUnwindSafe(|| ticket.with_source(|s| {
        s.extra = 8;
        panic!("extra callback")
    })))
    .is_err());
    drop(ticket);
    assert_eq!((p.in_flight(), l.in_flight()), (0, 0));
    assert!(catch_unwind(AssertUnwindSafe(|| gate.erase_idle_if(|_| panic!("cleanup callback"))))
        .is_err());
    drop(gate.admit_at(addr(1), p.clone(), l.clone(), 0.0).unwrap());
    gate.erase_idle_if(|_| true);
    assert!(gate.is_empty());
}

#[test]
fn concurrent_gates_share_one_process_concurrency_limit() {
    let process = budget(100, 2);
    let ready = Arc::new(Barrier::new(9));
    let release = Arc::new(Barrier::new(9));
    let mut threads = Vec::new();
    for id in 1..=8 {
        let p = process.clone();
        let ready = ready.clone();
        let release = release.clone();
        threads.push(std::thread::spawn(move || {
            let gate = PreauthGate::<()>::new(1, 10, 60.0).unwrap();
            let ticket = gate.admit_at(addr(id), p, budget(10, 1), 0.0).ok();
            ready.wait();
            release.wait();
            drop(ticket);
        }));
    }
    ready.wait();
    assert_eq!(process.in_flight(), 2);
    release.wait();
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(process.in_flight(), 0);
    assert!(Arc::ptr_eq(&DecryptBudget::process_default(), &DecryptBudget::process_default()));
    assert!(!Arc::ptr_eq(&DecryptBudget::local_default(), &DecryptBudget::local_default()));
}
