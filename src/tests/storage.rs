use std::
{
    time::Duration,
    sync::{ Arc, Mutex },
};

use axum::http::StatusCode;

use crate::
{
    tests::Temp,
    storage::{ self, Replay, Staging },
};

#[tokio::test]
async fn cleanup_preserves_active_sessions_and_count_limit()
{
    let temp = Temp::new();

    let staging = Arc::new(Mutex::new
    (
        Staging::open(temp.path().to_owned(), 100, 1, Duration::from_secs(1), 100).unwrap(),
    ));

    let lease = Staging::begin(staging.clone(), "one".into(), 1).await.unwrap();
    {
        let mut state = staging.lock().unwrap();
        state.sessions.get_mut("one").unwrap().touched = storage::now() - 10;
        state.cleanup().unwrap();
    }

    assert!(lease.path.exists());
    assert_eq!
    (
        Staging::begin(staging.clone(), "two".into(), 1).await.err().unwrap().0,
        StatusCode::INSUFFICIENT_STORAGE
    );
    drop(lease);

    let mut state = staging.lock().unwrap();
    state.sessions.get_mut("one").unwrap().touched = storage::now() - 10;
    state.cleanup().unwrap();
    assert!(!temp.path().join("one").exists());
}

#[test]
fn expired_replay_entries_are_reclaimed()
{
    let temp = Temp::new();

    let mut replay = Replay::open(temp.path().join("replay")).unwrap();
    replay.claim("expired", storage::now() - 1).unwrap();
    replay.cleanup().unwrap();
    assert_eq!(replay.entries, 0);
    replay.claim("expired", storage::now() + 300).unwrap();
}

#[tokio::test]
async fn disk_space_check_rejects_impossible_reservation()
{
    let temp = Temp::new();
    assert!(storage::available_bytes(temp.path()).unwrap() > 0);
    assert_eq!
    (
        storage::ensure_space(temp.path().to_owned(), u64::MAX).await.unwrap_err().0,
        StatusCode::INSUFFICIENT_STORAGE
    );
}
