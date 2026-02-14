use sqlx::PgPool;

/// Connect to the test database using `TEST_DATABASE_URL`.
pub async fn test_pool() -> PgPool {
    let url =
        std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set for e2e tests");

    let pool = PgPool::connect(&url)
        .await
        .expect("failed to connect to test database");

    sqlx::migrate!()
        .run(&pool)
        .await
        .expect("failed to run migrations on test database");

    pool
}

/// Truncate all application tables, preserving schema.
pub async fn truncate_all(pool: &PgPool) {
    sqlx::query("TRUNCATE records, lexicons, backfill_jobs, admins, network_lexicons RESTART IDENTITY CASCADE")
        .execute(pool)
        .await
        .expect("failed to truncate tables");
}
