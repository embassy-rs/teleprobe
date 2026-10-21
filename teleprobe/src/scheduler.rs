use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::oneshot;

pub type JobId = u64;

struct Waiter {
    id: JobId,
    targets: Vec<String>,
    since: Instant,
}

/// The scheduling rules, without any async or real time, so they can be tested directly.
pub struct Scheduler {
    reserve_after: Duration,
    next_id: JobId,
    /// Waiting jobs, oldest first.
    queue: VecDeque<Waiter>,
    /// Running jobs and the targets they hold.
    running: HashMap<JobId, Vec<String>>,
}

impl Scheduler {
    pub fn new(reserve_after: Duration) -> Self {
        Self {
            reserve_after,
            next_id: 0,
            queue: VecDeque::new(),
            running: HashMap::new(),
        }
    }

    /// Adds a job to the back of the queue. `targets` must not contain duplicates.
    pub fn enqueue(&mut self, targets: Vec<String>, now: Instant) -> JobId {
        let id = self.next_id;
        self.next_id += 1;
        self.queue.push_back(Waiter {
            id,
            targets,
            since: now,
        });
        id
    }

    /// Removes a job, whether it's waiting or running. Unknown ids are ignored.
    pub fn remove(&mut self, id: JobId) {
        self.running.remove(&id);
        self.queue.retain(|w| w.id != id);
    }

    /// Starts every waiting job that can start now, and returns their ids.
    pub fn grant(&mut self, now: Instant) -> Vec<JobId> {
        // Targets that jobs further back in the queue can't take: busy, or reserved by an
        // earlier job that has waited too long.
        let mut blocked: HashSet<String> = self.running.values().flatten().cloned().collect();
        let mut granted = Vec::new();

        let mut i = 0;
        while i < self.queue.len() {
            let w = &self.queue[i];
            if w.targets.iter().all(|t| !blocked.contains(t)) {
                blocked.extend(w.targets.iter().cloned());
                let w = self.queue.remove(i).unwrap();
                granted.push(w.id);
                self.running.insert(w.id, w.targets);
            } else {
                if now.duration_since(w.since) >= self.reserve_after {
                    blocked.extend(w.targets.iter().cloned());
                }
                i += 1;
            }
        }

        granted
    }
}

struct State {
    scheduler: Scheduler,
    wakers: HashMap<JobId, oneshot::Sender<()>>,
}

/// Shared, async front-end to [`Scheduler`].
pub struct Queue {
    state: Mutex<State>,
}

impl Queue {
    pub fn new(reserve_after: Duration) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                scheduler: Scheduler::new(reserve_after),
                wakers: HashMap::new(),
            }),
        })
    }

    /// Waits until the job holds all of `targets`. Dropping the future gives up its place in the queue.
    pub async fn acquire(self: &Arc<Self>, targets: Vec<String>) -> Grant {
        let (tx, rx) = oneshot::channel();
        let id = {
            let mut state = self.state.lock();
            let id = state.scheduler.enqueue(targets, Instant::now());
            state.wakers.insert(id, tx);
            id
        };
        // Created before waiting, so that dropping the future while queued removes the job.
        let grant = Grant {
            queue: self.clone(),
            id,
        };
        self.update();
        rx.await.expect("waker dropped while job is still queued");
        grant
    }

    fn update(&self) {
        let mut state = self.state.lock();
        let state = &mut *state;
        for id in state.scheduler.grant(Instant::now()) {
            if let Some(tx) = state.wakers.remove(&id) {
                let _ = tx.send(());
            }
        }
    }
}

/// A job's place in the queue, and once granted, its hold on the targets. Dropping it frees both.
pub struct Grant {
    queue: Arc<Queue>,
    id: JobId,
}

impl Drop for Grant {
    fn drop(&mut self) {
        {
            let mut state = self.queue.state.lock();
            state.scheduler.remove(self.id);
            state.wakers.remove(&self.id);
        }
        self.queue.update();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RESERVE_AFTER: Duration = Duration::from_secs(30);

    fn targets(t: &[&str]) -> Vec<String> {
        t.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn same_target_is_fifo() {
        let t0 = Instant::now();
        let mut s = Scheduler::new(RESERVE_AFTER);
        let j1 = s.enqueue(targets(&["a"]), t0);
        let j2 = s.enqueue(targets(&["a"]), t0);
        let j3 = s.enqueue(targets(&["a"]), t0);

        assert_eq!(s.grant(t0), [j1]);
        assert!(s.grant(t0).is_empty());
        s.remove(j1);
        assert_eq!(s.grant(t0), [j2]);
        s.remove(j2);
        assert_eq!(s.grant(t0), [j3]);
    }

    #[test]
    fn different_targets_run_together() {
        let t0 = Instant::now();
        let mut s = Scheduler::new(RESERVE_AFTER);
        let j1 = s.enqueue(targets(&["a"]), t0);
        let j2 = s.enqueue(targets(&["b"]), t0);
        assert_eq!(s.grant(t0), [j1, j2]);
    }

    #[test]
    fn group_waits_for_all_targets() {
        let t0 = Instant::now();
        let mut s = Scheduler::new(RESERVE_AFTER);
        let j1 = s.enqueue(targets(&["a"]), t0);
        let g = s.enqueue(targets(&["a", "b"]), t0);
        assert_eq!(s.grant(t0), [j1]);
        s.remove(j1);
        assert_eq!(s.grant(t0), [g]);
    }

    #[test]
    fn opposite_groups_dont_deadlock() {
        let t0 = Instant::now();
        let mut s = Scheduler::new(RESERVE_AFTER);
        let g1 = s.enqueue(targets(&["a", "b"]), t0);
        let g2 = s.enqueue(targets(&["b", "a"]), t0);
        assert_eq!(s.grant(t0), [g1]);
        s.remove(g1);
        assert_eq!(s.grant(t0), [g2]);
    }

    #[test]
    fn young_group_is_overtaken() {
        let t0 = Instant::now();
        let mut s = Scheduler::new(RESERVE_AFTER);
        let j1 = s.enqueue(targets(&["b"]), t0);
        assert_eq!(s.grant(t0), [j1]);

        // "a" is free, so a later single-target job may use it while the group waits for "b".
        let _g = s.enqueue(targets(&["a", "b"]), t0);
        let j2 = s.enqueue(targets(&["a"]), t0);
        assert_eq!(s.grant(t0), [j2]);
    }

    #[test]
    fn aged_group_reserves_its_targets() {
        let t0 = Instant::now();
        let mut s = Scheduler::new(RESERVE_AFTER);
        let j1 = s.enqueue(targets(&["b"]), t0);
        assert_eq!(s.grant(t0), [j1]);
        let g = s.enqueue(targets(&["a", "b"]), t0);

        let t1 = t0 + RESERVE_AFTER;
        let j2 = s.enqueue(targets(&["a"]), t1);
        assert!(s.grant(t1).is_empty(), "a is reserved by the group");

        s.remove(j1);
        assert_eq!(s.grant(t1), [g]);
        s.remove(g);
        assert_eq!(s.grant(t1), [j2]);
    }

    #[test]
    fn aged_group_still_waits_for_earlier_jobs() {
        let t0 = Instant::now();
        let mut s = Scheduler::new(RESERVE_AFTER);
        let j1 = s.enqueue(targets(&["b"]), t0);
        assert_eq!(s.grant(t0), [j1]);
        let j2 = s.enqueue(targets(&["b"]), t0);
        let g = s.enqueue(targets(&["a", "b"]), t0);

        let t1 = t0 + RESERVE_AFTER;
        s.remove(j1);
        assert_eq!(s.grant(t1), [j2]);
        s.remove(j2);
        assert_eq!(s.grant(t1), [g]);
    }

    #[test]
    fn removing_a_waiting_job_frees_its_reservation() {
        let t0 = Instant::now();
        let mut s = Scheduler::new(RESERVE_AFTER);
        let j1 = s.enqueue(targets(&["b"]), t0);
        assert_eq!(s.grant(t0), [j1]);
        let g = s.enqueue(targets(&["a", "b"]), t0);

        let t1 = t0 + RESERVE_AFTER;
        let j2 = s.enqueue(targets(&["a"]), t1);
        assert!(s.grant(t1).is_empty());
        s.remove(g);
        assert_eq!(s.grant(t1), [j2]);
    }

    #[tokio::test]
    async fn dropped_acquire_gives_up_its_place() {
        let queue = Queue::new(RESERVE_AFTER);
        let held = queue.acquire(targets(&["a"])).await;

        let gave_up = tokio::time::timeout(Duration::from_millis(10), queue.acquire(targets(&["a"]))).await;
        assert!(gave_up.is_err());

        let next = tokio::spawn({
            let queue = queue.clone();
            async move { queue.acquire(targets(&["a"])).await }
        });
        tokio::task::yield_now().await;
        drop(held);
        let _next = tokio::time::timeout(Duration::from_secs(1), next)
            .await
            .unwrap()
            .unwrap();

        let state = queue.state.lock();
        assert!(state.scheduler.queue.is_empty());
        assert!(state.wakers.is_empty());
    }
}
