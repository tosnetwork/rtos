/* Copyright (C) 2026 RTOS contributors. GPL-3.0; see LICENSE. */
use super::*;

#[tokio::test(flavor = "current_thread")]
async fn stopper_failure_waits_for_other_services_without_releasing_failed_mask() {
    let stopper = Arc::new(Stopper::new());
    let failed = Engine::MASK_SERVICE_VALIDATOR_MANAGER;
    let other = Engine::MASK_SERVICE_BOOT;
    stopper.acquire_stop(failed | other);
    stopper.report_service_failure(failed, "validator cleanup failed".to_owned());
    assert!(stopper.check_stop());
    let mut wait = Box::pin(stopper.clone().wait_stop());
    assert!(futures::poll!(&mut wait).is_pending());
    stopper.release_stop(other);
    let error = tokio::time::timeout(Duration::from_secs(5), wait).await.unwrap().unwrap_err();
    assert!(error.to_string().contains("validator cleanup failed"));
    assert!(error.to_string().contains("unreleased service mask"));
    assert_eq!(stopper.stop.load(Ordering::Acquire) & !Engine::MASK_STOP, failed);
    stopper.report_service_failure(0, "unclassified panic".to_owned());
    let error = stopper.wait_stop().await.unwrap_err().to_string();
    assert!(error.contains("validator cleanup failed") && error.contains("unclassified panic"));
}

#[tokio::test(flavor = "current_thread")]
async fn stopper_unclassified_failure_does_not_exempt_live_owners() {
    let stopper = Arc::new(Stopper::new());
    let service = Engine::MASK_SERVICE_BOOT;
    stopper.acquire_stop(service);
    stopper.report_service_failure(0, "unclassified failure".to_owned());
    let mut wait = Box::pin(stopper.clone().wait_stop());
    assert!(futures::poll!(&mut wait).is_pending());
    stopper.release_stop(service);
    assert!(tokio::time::timeout(Duration::from_secs(5), wait)
        .await
        .unwrap()
        .unwrap_err()
        .to_string()
        .contains("unclassified failure"));
    assert_eq!(stopper.stop.load(Ordering::Acquire) & !Engine::MASK_STOP, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn stopper_clean_shutdown_requires_all_owners_to_release() {
    let stopper = Arc::new(Stopper::new());
    stopper.acquire_stop(Engine::MASK_SERVICE_BOOT);
    stopper.set_stop();
    let mut wait = Box::pin(stopper.clone().wait_stop());
    assert!(futures::poll!(&mut wait).is_pending());
    stopper.release_stop(Engine::MASK_SERVICE_BOOT);
    tokio::time::timeout(Duration::from_secs(5), wait).await.unwrap().unwrap();
}
