//! Local semantic probe. Findings are observations, not production guarantees.
use anyhow::{Result, ensure};
use opendal::{Operator, services};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<()> {
    // Default features (including constructor-based registration) are disabled.
    // With cloud-build, explicitly install the selected Rustls HTTP transport.
    opendal::install_default();
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("objects");
    let staging = directory.path().join("staging");
    std::fs::create_dir(&root)?;
    std::fs::create_dir(&staging)?;
    let op = Operator::new(
        services::Fs::default()
            .root(root.to_str().unwrap())
            .atomic_write_dir(staging.to_str().unwrap()),
    )?;
    let capability = op.info().full_capability();
    op.write("data/item", "abcdefghij").await?;
    ensure!(op.stat("data/item").await?.content_length() == 10);
    ensure!(op.read("data/item").await?.to_vec() == b"abcdefghij");
    ensure!(op.read_with("data/item").range(2..5).await?.to_vec() == b"cde");
    op.write("data/item-extra", "neighbor").await?;
    let listing = op.list_with("data/").recursive(true).await?;
    ensure!(listing.len() == 2);

    // Both writers are opened while the destination does not exist. This tests
    // publication-time exclusion, not merely a sequential existence check.
    let mut first = op.writer_with("claims/unique").if_not_exists(true).await?;
    let second = op.writer_with("claims/unique").if_not_exists(true).await;
    first.write("first").await?;
    let first_close = first.close().await;
    let (second_opened, second_close_succeeded) = match second {
        Ok(mut writer) => {
            writer.write("second").await?;
            (true, writer.close().await.is_ok())
        }
        Err(_) => (false, false),
    };
    let winners = usize::from(first_close.is_ok()) + usize::from(second_close_succeeded);

    let mut writer = op.writer("uploads/complete").await?;
    writer.write("part-one").await?;
    let visible_before_close = op.stat("uploads/complete").await.is_ok();
    ensure!(!visible_before_close);
    writer.close().await?;
    ensure!(op.read("uploads/complete").await?.to_vec() == b"part-one");
    let mut abandoned = op.writer("uploads/abort").await?;
    abandoned.write("never-published").await?;
    abandoned.abort().await?;
    ensure!(op.stat("uploads/abort").await.is_err());
    op.delete("data/item").await?;
    ensure!(op.stat("data/item").await.is_err());
    #[cfg(feature = "cloud-build")]
    for (endpoint, region) in [
        ("https://s3.us-east-1.amazonaws.com", "us-east-1"),
        ("https://evaluation-only.r2.cloudflarestorage.com", "auto"),
    ] {
        let _client = Operator::new(
            services::S3::default()
                .bucket("evaluation-only")
                .endpoint(endpoint)
                .region(region)
                .access_key_id("evaluation-only")
                .secret_access_key("evaluation-only")
                .disable_config_load()
                .disable_ec2_metadata(),
        )?;
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "candidate":"opendal", "version":"0.59.5", "backend":"Fs with atomic_write_dir",
            "network_requests":false,
            "baseline_checks":["put/get/stat", "range", "directory list", "delete", "writer publish", "writer abort"],
            "advertised_create_if_absent":capability.write_with_if_not_exists,
            "second_writer_opened_before_first_close":second_opened,
            "create_if_absent_winners":winners,
            "create_if_absent_meets_rebsync_atomic_requirement":winners == 1,
            "visible_before_close":visible_before_close,
        "s3_and_r2_builders":if cfg!(feature = "cloud-build") { "constructed with dummy credentials; provider behavior untested" } else { "not enabled; use cloud-build for construction-only checks" },
            "durability":"file sync_all in source; directory durability not demonstrated",
            "unverified":["cloud I/O", "restart-resumable multipart", "S3 wire server", "restic REST server", "Android target"]
        }))?
    );
    Ok(())
}
