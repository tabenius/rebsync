//! Local semantic probe, not an S3 server or a cloud conformance test.
use anyhow::{Result, ensure};
use futures::TryStreamExt;
use object_store::{
    ObjectStore, ObjectStoreExt, PutMode, PutOptions, aws::AmazonS3Builder, local::LocalFileSystem,
    path::Path,
};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let store = LocalFileSystem::new_with_prefix(directory.path())?.with_fsync(true);
    let key = Path::parse("data/item")?;
    store.put(&key, "abcdefghij".into()).await?;
    ensure!(store.head(&key).await?.size == 10);
    ensure!(store.get(&key).await?.bytes().await?.as_ref() == b"abcdefghij");
    ensure!(store.get_range(&key, 2..5).await?.as_ref() == b"cde");
    store
        .put(&Path::parse("data/item-extra")?, "neighbor".into())
        .await?;
    let listing = store
        .list(Some(&Path::parse("data")?))
        .try_collect::<Vec<_>>()
        .await?;
    ensure!(listing.len() == 2);
    let prefix_listing = store.list(Some(&key)).try_collect::<Vec<_>>().await?;

    let create_key = Path::parse("claims/unique")?;
    let (first, second) = tokio::join!(
        store.put_opts(
            &create_key,
            "first".into(),
            PutOptions {
                mode: PutMode::Create,
                ..Default::default()
            }
        ),
        store.put_opts(
            &create_key,
            "second".into(),
            PutOptions {
                mode: PutMode::Create,
                ..Default::default()
            }
        ),
    );
    let winners = usize::from(first.is_ok()) + usize::from(second.is_ok());
    ensure!(
        winners == 1,
        "create-if-absent allowed {winners} concurrent winners"
    );

    let multipart_key = Path::parse("uploads/complete")?;
    let mut upload = store.put_multipart(&multipart_key).await?;
    upload.put_part("part-one".into()).await?;
    let visible_before_complete = store.head(&multipart_key).await.is_ok();
    ensure!(!visible_before_complete);
    upload.complete().await?;
    ensure!(store.get(&multipart_key).await?.bytes().await?.as_ref() == b"part-one");
    let abort_key = Path::parse("uploads/abort")?;
    let mut abandoned = store.put_multipart(&abort_key).await?;
    abandoned.put_part("never-published".into()).await?;
    abandoned.abort().await?;
    ensure!(store.head(&abort_key).await.is_err());
    store.delete(&key).await?;
    ensure!(store.head(&key).await.is_err());

    // Construct only; explicit dummy keys prevent environment/metadata credentials.
    // No request is sent. Do not confuse builder success with provider validation.
    for (endpoint, region) in [
        ("https://s3.us-east-1.amazonaws.com", "us-east-1"),
        ("https://evaluation-only.r2.cloudflarestorage.com", "auto"),
    ] {
        let _client = AmazonS3Builder::new()
            .with_bucket_name("evaluation-only")
            .with_region(region)
            .with_endpoint(endpoint)
            .with_access_key_id("evaluation-only")
            .with_secret_access_key("evaluation-only")
            .build()?;
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "candidate":"object_store", "version":"0.14.2", "backend":"LocalFileSystem",
            "fsync_enabled":true, "network_requests":false,
            "baseline_checks":["put/get/head", "range", "directory-prefix list", "delete", "multipart publish", "multipart abort"],
            "create_if_absent_winners":winners,
            "visible_before_complete":visible_before_complete,
            "path_segment_prefix_result":prefix_listing.iter().map(|m| m.location.to_string()).collect::<Vec<_>>(),
            "s3_and_r2_builders":"constructed with dummy credentials; provider behavior untested",
            "durability":"fsync option enabled and source reviewed; no power-loss test",
            "unverified":["cloud I/O", "restart-resumable multipart", "S3 wire server", "restic REST server", "Android target"]
        }))?
    );
    Ok(())
}
