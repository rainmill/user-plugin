//! This plugin's migrations, in apply order.

laterite_core::migration_set! {
    module_id: "rainmill.user",
    m0001_create_users,
}

#[cfg(test)]
mod tests {
    use laterite_core::testing::connect_test;

    #[tokio::test]
    async fn migration_applies_on_the_test_backend() {
        let (_db, _guard) = connect_test(&[super::migrations()]).await;
    }
}
