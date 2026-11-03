//! The users service against a real database (the framework's test harness:
//! SQLite in memory by default, the configured backend otherwise).

use laterite_core::events::Events;
use laterite_core::testing::{connect_test, TestGuard};
use laterite_core::Db;
use rainmill_user::{
    Activation, Actor, Credential, LoginAttribute, NewUser, ProfileChanges, UserError,
    UserSettings, Users, GROUP_GUEST, GROUP_REGISTERED,
};

async fn db() -> (Db, TestGuard) {
    connect_test(&[rainmill_user::migrations::migrations()]).await
}

fn service(db: &Db, settings: UserSettings) -> Users {
    Users::new(db.clone(), Events::new(db.clone()), settings)
}

fn alice() -> NewUser {
    NewUser {
        email: Some("alice@acme.test".to_string()),
        first_name: Some("Alice".to_string()),
        last_name: Some("Ash".to_string()),
        password: Some("correct horse battery".to_string()),
        ..Default::default()
    }
}

#[tokio::test]
async fn registers_activates_automatically_and_joins_the_registered_group() {
    let (db, _g) = db().await;
    let users = service(&db, UserSettings::default());
    let registered = users.register(alice()).await.unwrap();
    assert!(registered.activation_code.is_none());
    let user = registered.user;
    assert!(user.is_active());
    assert_eq!(user.display_name, "Alice Ash");
    assert!(user.password_hash.is_some());
    let groups = users.groups_of(user.id).await.unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].code, GROUP_REGISTERED);
    assert_eq!(user.primary_group_id, Some(groups[0].id));
    let log = users.timeline(user.id, 10).await.unwrap();
    assert_eq!(log[0].kind, "user.registered");
    assert!(log[0].is_system);
}

#[tokio::test]
async fn the_login_attribute_is_required_and_unique() {
    let (db, _g) = db().await;
    let users = service(&db, UserSettings::default());
    let missing = users
        .register(NewUser {
            username: Some("alice".to_string()),
            ..Default::default()
        })
        .await;
    assert!(matches!(missing, Err(UserError::Missing("email"))));
    users.register(alice()).await.unwrap();
    let again = users.register(alice()).await;
    assert!(matches!(again, Err(UserError::Taken("email"))));
}

#[tokio::test]
async fn phone_as_the_login_attribute_needs_no_password() {
    let (db, _g) = db().await;
    let users = service(
        &db,
        UserSettings {
            login_attribute: LoginAttribute::Phone,
            ..Default::default()
        },
    );
    let registered = users
        .register(NewUser {
            phone: Some("+919900000000".to_string()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(registered.user.display_name, "+919900000000");
    assert!(registered.user.password_hash.is_none());
    let found = users.by_login("+919900000000").await.unwrap().unwrap();
    assert_eq!(found.id, registered.user.id);
    // Without a password the credential path refuses, rather than panics.
    let attempt = users
        .authenticate(&Credential {
            login: "+919900000000".to_string(),
            password: "anything".to_string(),
        })
        .await;
    assert!(matches!(attempt, Err(UserError::BadCredentials)));
}

#[tokio::test]
async fn user_activation_issues_a_code_that_activates_once() {
    let (db, _g) = db().await;
    let users = service(
        &db,
        UserSettings {
            activation: Activation::User,
            ..Default::default()
        },
    );
    let registered = users.register(alice()).await.unwrap();
    let code = registered.activation_code.clone().unwrap();
    assert!(!registered.user.is_active());
    let attempt = users
        .authenticate(&Credential {
            login: "alice@acme.test".to_string(),
            password: "correct horse battery".to_string(),
        })
        .await;
    assert!(matches!(attempt, Err(UserError::Inactive)));
    let user = users.activate(&code).await.unwrap();
    assert!(user.is_active());
    assert!(matches!(
        users.activate(&code).await,
        Err(UserError::BadToken)
    ));
    assert!(matches!(
        users.activate("nope").await,
        Err(UserError::BadToken)
    ));
}

#[tokio::test]
async fn operator_activation_waits_for_approval() {
    let (db, _g) = db().await;
    let users = service(
        &db,
        UserSettings {
            activation: Activation::Operator,
            ..Default::default()
        },
    );
    let registered = users.register(alice()).await.unwrap();
    assert!(registered.activation_code.is_none());
    assert!(!registered.user.is_active());
    let user = users
        .activate_by_operator(registered.user.id, Actor::operator(1))
        .await
        .unwrap();
    assert!(user.is_active());
    let log = users.timeline(user.id, 10).await.unwrap();
    assert!(log.iter().any(|l| l.kind == "user.approved"
        && l.actor.as_ref().map(|a| a.kind.as_str()) == Some("operator")));
}

#[tokio::test]
async fn authenticates_by_password_and_refuses_bans() {
    let (db, _g) = db().await;
    let users = service(&db, UserSettings::default());
    let id = users.register(alice()).await.unwrap().user.id;
    let credential = Credential {
        login: "alice@acme.test".to_string(),
        password: "correct horse battery".to_string(),
    };
    assert_eq!(users.authenticate(&credential).await.unwrap().id, id);
    let wrong = users
        .authenticate(&Credential {
            password: "wrong".to_string(),
            ..credential.clone()
        })
        .await;
    assert!(matches!(wrong, Err(UserError::BadCredentials)));
    users
        .ban(id, Some("spam".to_string()), Actor::operator(1))
        .await
        .unwrap();
    assert!(matches!(
        users.authenticate(&credential).await,
        Err(UserError::Banned)
    ));
    users.unban(id, Actor::operator(1)).await.unwrap();
    assert_eq!(users.authenticate(&credential).await.unwrap().id, id);
}

#[tokio::test]
async fn resets_a_password_with_a_single_use_token() {
    let (db, _g) = db().await;
    let users = service(&db, UserSettings::default());
    users.register(alice()).await.unwrap();
    assert!(users
        .request_reset("nobody@acme.test", "email")
        .await
        .unwrap()
        .is_none());
    let issued = users
        .request_reset("alice@acme.test", "email")
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        users.reset(&issued.token, "short").await,
        Err(UserError::Password(_))
    ));
    let user = users
        .reset(&issued.token, "another long password")
        .await
        .unwrap();
    assert_eq!(user.email.as_deref(), Some("alice@acme.test"));
    assert!(matches!(
        users.reset(&issued.token, "another long password").await,
        Err(UserError::BadToken)
    ));
    let signed_in = users
        .authenticate(&Credential {
            login: "alice@acme.test".to_string(),
            password: "another long password".to_string(),
        })
        .await
        .unwrap();
    assert_eq!(signed_in.id, user.id);
}

#[tokio::test]
async fn profile_changes_keep_login_attributes_unique() {
    let (db, _g) = db().await;
    let users = service(&db, UserSettings::default());
    let a = users.register(alice()).await.unwrap().user.id;
    let b = users
        .register(NewUser {
            email: Some("bob@acme.test".to_string()),
            password: Some("correct horse battery".to_string()),
            ..Default::default()
        })
        .await
        .unwrap()
        .user
        .id;
    let clash = users
        .update_profile(
            b,
            ProfileChanges {
                email: Some(Some("alice@acme.test".to_string())),
                ..Default::default()
            },
            None,
        )
        .await;
    assert!(matches!(clash, Err(UserError::Taken("email"))));
    let user = users
        .update_profile(
            a,
            ProfileChanges {
                display_name: Some("Ali".to_string()),
                locale: Some(Some("en-IN".to_string())),
                ..Default::default()
            },
            Some(Actor::user(a)),
        )
        .await
        .unwrap();
    assert_eq!(user.display_name, "Ali");
    assert_eq!(user.locale.as_deref(), Some("en-IN"));
}

#[tokio::test]
async fn deletes_softly_by_default_and_restores() {
    let (db, _g) = db().await;
    let users = service(&db, UserSettings::default());
    let id = users.register(alice()).await.unwrap().user.id;
    let soft = users
        .delete(id, &[], Some(Actor::operator(1)))
        .await
        .unwrap();
    assert!(soft);
    let user = users.find(id).await.unwrap();
    assert!(user.deleted_at.is_some());
    assert!(users.by_login("alice@acme.test").await.unwrap().is_none());
    users.restore(id, Actor::operator(1)).await.unwrap();
    assert!(users.by_login("alice@acme.test").await.unwrap().is_some());
    let hard = service(
        &db,
        UserSettings {
            soft_delete: false,
            ..Default::default()
        },
    );
    assert!(!hard.delete(id, &[], None).await.unwrap());
    assert!(matches!(hard.find(id).await, Err(UserError::NotFound)));
}

#[tokio::test]
async fn guests_convert_and_merge() {
    let (db, _g) = db().await;
    let users = service(
        &db,
        UserSettings {
            guests: true,
            ..Default::default()
        },
    );
    let guest = users
        .register(NewUser {
            email: Some("guest@acme.test".to_string()),
            is_guest: true,
            ..Default::default()
        })
        .await
        .unwrap()
        .user;
    assert!(guest.is_guest);
    assert!(users.in_group(guest.id, GROUP_GUEST).await.unwrap());
    let converted = users
        .convert_guest(
            guest.id,
            NewUser {
                email: Some("guest@acme.test".to_string()),
                first_name: Some("Gus".to_string()),
                password: Some("correct horse battery".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(!converted.is_guest);
    assert_eq!(converted.display_name, "Gus");
    assert!(users
        .in_group(converted.id, GROUP_REGISTERED)
        .await
        .unwrap());
    assert!(!users.in_group(converted.id, GROUP_GUEST).await.unwrap());

    let lead = users.register(alice()).await.unwrap().user.id;
    users
        .comment(converted.id, Actor::operator(1), "note")
        .await
        .unwrap();
    users
        .merge(lead, vec![converted.id], Actor::operator(1))
        .await
        .unwrap();
    assert!(matches!(
        users.find(converted.id).await,
        Err(UserError::NotFound)
    ));
    let log = users.timeline(lead, 20).await.unwrap();
    assert!(log.iter().any(|l| l.is_comment));
    assert!(log.iter().any(|l| l.kind == "user.merged"));
}

#[tokio::test]
async fn groups_and_preferences() {
    let (db, _g) = db().await;
    let users = service(&db, UserSettings::default());
    let id = users.register(alice()).await.unwrap().user.id;
    assert!(matches!(
        users.add_to_group(id, "vip").await,
        Err(UserError::NoGroup)
    ));
    rainmill_user::store::insert_group(&db, "vip", "VIP", None)
        .await
        .unwrap();
    users.add_to_group(id, "vip").await.unwrap();
    assert!(users.in_group(id, "vip").await.unwrap());
    users.set_primary_group(id, "vip").await.unwrap();
    let user = users.find(id).await.unwrap();
    let vip = rainmill_user::store::find_group_by_code(&db, "vip")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user.primary_group_id, Some(vip.id));
    users.remove_from_group(id, "vip").await.unwrap();
    assert!(!users.in_group(id, "vip").await.unwrap());

    assert!(users.preference(id, "theme").await.unwrap().is_none());
    users.set_preference(id, "theme", "dark").await.unwrap();
    users.set_preference(id, "theme", "light").await.unwrap();
    assert_eq!(
        users.preference(id, "theme").await.unwrap().as_deref(),
        Some("light")
    );
    users.clear_preference(id, "theme").await.unwrap();
    assert!(users.preference(id, "theme").await.unwrap().is_none());
}

#[tokio::test]
async fn touch_seen_records_once_a_minute() {
    let (db, _g) = db().await;
    let users = service(&db, UserSettings::default());
    let id = users.register(alice()).await.unwrap().user.id;
    users
        .touch_seen(id, Some("203.0.113.9".to_string()))
        .await
        .unwrap();
    let first = users.find(id).await.unwrap();
    assert!(first.last_seen_at.is_some());
    assert_eq!(first.last_ip.as_deref(), Some("203.0.113.9"));
    users
        .touch_seen(id, Some("203.0.113.10".to_string()))
        .await
        .unwrap();
    let second = users.find(id).await.unwrap();
    assert_eq!(second.last_seen_at, first.last_seen_at);
    assert_eq!(second.last_ip.as_deref(), Some("203.0.113.9"));
}
