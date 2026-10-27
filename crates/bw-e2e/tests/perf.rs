//! MLS at 50 members (the default room size): grow a group to 50 through
//! one adder (every existing member processes every commit), then one
//! message encrypted once and decrypted by 49. Timed; prints `PERF` lines.

use std::time::Instant;

use bw_e2e::{Event, Identity};

#[test]
fn fifty_member_group_commit_and_fan_out() {
    let n = 50;
    let ids: Vec<Identity> = (0..n)
        .map(|i| Identity::new(&format!("bot_perf{i:02}")).unwrap())
        .collect();
    let t0 = Instant::now();
    let mut groups = vec![ids[0].create_group("room-perf").unwrap()];
    let mut worst_commit = std::time::Duration::ZERO;
    for i in 1..n {
        let kp = ids[i].key_package().unwrap();
        let tc = Instant::now();
        let (commit, welcome) = groups[0].add_member(&ids[0], &kp).unwrap();
        worst_commit = worst_commit.max(tc.elapsed());
        for (j, g) in groups.iter_mut().enumerate().skip(1) {
            assert!(matches!(
                g.process(&ids[j], &commit).unwrap(),
                Event::Commit { .. }
            ));
        }
        let (g, _) = ids[i].join(&welcome).unwrap();
        groups.push(g);
    }
    let grown = t0.elapsed();
    assert_eq!(groups[0].members().len(), n);
    assert_eq!(groups[n - 1].epoch(), groups[0].epoch());

    // One commit at full size (an Add for a 51st key would not fit the
    // room; a self-update style rekey is the same cost): time the add of
    // one more member to a 50-member group and its processing by all 50.
    let extra = Identity::new("bot_perf_extra").unwrap();
    let tc = Instant::now();
    let (commit, _welcome) = groups[0]
        .add_member(&ids[0], &extra.key_package().unwrap())
        .unwrap();
    let commit_at_50 = tc.elapsed();
    let tp = Instant::now();
    for (j, g) in groups.iter_mut().enumerate().skip(1) {
        g.process(&ids[j], &commit).unwrap();
    }
    let processed_at_50 = tp.elapsed();

    let t1 = Instant::now();
    let ct = groups[0].encrypt(&ids[0], b"hello fifty").unwrap();
    for (j, g) in groups.iter_mut().enumerate().skip(1) {
        match g.process(&ids[j], &ct).unwrap() {
            Event::Message { plaintext, .. } => assert_eq!(plaintext, b"hello fifty"),
            e => panic!("expected a message, got {e:?}"),
        }
    }
    let fanout = t1.elapsed();
    eprintln!(
        "PERF mls: grow to {n} in {grown:?} (slowest add {worst_commit:?}); commit at 50: {commit_at_50:?} to create, {processed_at_50:?} for 49 others; one message decrypted by 49 in {fanout:?}; ciphertext {} bytes",
        ct.len()
    );
}
