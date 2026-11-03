//! The user form's write handler. The generic form cannot hash a password,
//! derive a display name or check a login attribute's uniqueness, so the form
//! names this persister and it runs inside the form's transaction.

use std::collections::HashMap;
use std::sync::Arc;

use laterite_admin::persist::{Persister, PersisterReg, SaveError};
use laterite_auth::password::hash_password;
use laterite_core::strata::async_trait;
use laterite_core::validation::ErrorBag;
use laterite_core::{t, Record, SaveCx};

use crate::admin::USER_KEY;
use crate::model::{LoginAttribute, NewUser, ProfileChanges, GROUP_REGISTERED};
use crate::service::display_name;
use crate::store::{self, NewUserRow};

pub(crate) fn persister() -> PersisterReg {
    PersisterReg::new(USER_KEY, Arc::new(UserPersister))
}

pub(crate) struct UserPersister;

#[async_trait]
impl Persister for UserPersister {
    async fn create(&self, cx: &mut SaveCx<'_>, rec: &Record) -> Result<i64, SaveError> {
        let data = &rec.to_text_map();
        let backend = cx.backend();
        let new = NewUser {
            username: opt(data, "username"),
            email: opt(data, "email"),
            phone: opt(data, "phone"),
            first_name: opt(data, "first_name"),
            last_name: opt(data, "last_name"),
            display_name: opt(data, "display_name"),
            password: opt(data, "password"),
            locale: opt(data, "locale"),
            timezone: opt(data, "timezone"),
            is_guest: false,
            ip: None,
        };
        let mut bag = ErrorBag::default();
        if new.email.is_none() && new.phone.is_none() && new.username.is_none() {
            bag.add(
                "email",
                t!("Give the user an email, a phone number or a username."),
            );
        }
        for (attribute, value) in attributes(&new) {
            if let Some(value) = value {
                if taken(cx, attribute, &value, None).await? {
                    bag.add(attribute.as_str(), t!("Another user already has this."));
                }
            }
        }
        let password_hash = match new.password.as_deref() {
            Some(plain) => match hash_password(plain) {
                Ok(hash) => Some(hash),
                Err(e) => {
                    bag.add("password", laterite_core::i18n::Text::from(e.to_string()));
                    None
                }
            },
            None => None,
        };
        if !bag.is_empty() {
            return Err(SaveError::Invalid(bag));
        }
        let login = new
            .email
            .clone()
            .or_else(|| new.phone.clone())
            .or_else(|| new.username.clone())
            .unwrap_or_default();
        // An operator-created user is a registered user like any other.
        let group_id = store::ensure_group_in(backend, cx.conn(), GROUP_REGISTERED, "Registered")
            .await
            .map_err(|e| SaveError::Failed(e.to_string()))?;
        let row = NewUserRow {
            username: new.username.clone(),
            email: new.email.clone(),
            phone: new.phone.clone(),
            first_name: new.first_name.clone(),
            last_name: new.last_name.clone(),
            display_name: display_name(&new, &login),
            password_hash,
            locale: new.locale.clone(),
            timezone: new.timezone.clone(),
            is_guest: false,
            activation_code_hash: None,
            // An operator-created user is active at once: the operator is the
            // approval.
            activated_at: Some(store::now()),
            primary_group_id: Some(group_id),
            created_ip: None,
        };
        let id = store::insert_user_in(backend, cx.conn(), row)
            .await
            .map_err(|e| SaveError::Failed(e.to_string()))?;
        store::add_membership_in(backend, cx.conn(), id, group_id)
            .await
            .map_err(|e| SaveError::Failed(e.to_string()))?;
        if data.get("is_mail_blocked").is_some_and(|v| is_on(v)) {
            store::update_profile_in(
                backend,
                cx.conn(),
                id,
                &ProfileChanges {
                    is_mail_blocked: Some(true),
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| SaveError::Failed(e.to_string()))?;
        }
        if let Some(notes) = opt(data, "notes") {
            store::update_profile_in(
                backend,
                cx.conn(),
                id,
                &ProfileChanges {
                    notes: Some(Some(notes)),
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| SaveError::Failed(e.to_string()))?;
        }
        Ok(id)
    }

    async fn update(&self, cx: &mut SaveCx<'_>, id: &str, rec: &Record) -> Result<(), SaveError> {
        let data = &rec.to_text_map();
        let backend = cx.backend();
        let user_id: i64 = id
            .parse()
            .map_err(|_| SaveError::Failed("invalid user id".to_string()))?;
        let current = store::find_user_in(backend, cx.conn(), user_id)
            .await
            .map_err(|e| SaveError::Failed(e.to_string()))?
            .ok_or_else(|| SaveError::Failed("user not found".to_string()))?;
        let mut bag = ErrorBag::default();
        let new = NewUser {
            username: opt(data, "username"),
            email: opt(data, "email"),
            phone: opt(data, "phone"),
            ..Default::default()
        };
        if new.email.is_none() && new.phone.is_none() && new.username.is_none() {
            bag.add(
                "email",
                t!("Give the user an email, a phone number or a username."),
            );
        }
        for (attribute, value) in attributes(&new) {
            if let Some(value) = value {
                if taken(cx, attribute, &value, Some(user_id)).await? {
                    bag.add(attribute.as_str(), t!("Another user already has this."));
                }
            }
        }
        let password_hash = match opt(data, "password") {
            Some(plain) => match hash_password(&plain) {
                Ok(hash) => Some(hash),
                Err(e) => {
                    bag.add("password", laterite_core::i18n::Text::from(e.to_string()));
                    None
                }
            },
            None => None,
        };
        if !bag.is_empty() {
            return Err(SaveError::Invalid(bag));
        }
        let display = opt(data, "display_name").unwrap_or_else(|| {
            let seed = NewUser {
                first_name: opt(data, "first_name"),
                last_name: opt(data, "last_name"),
                ..Default::default()
            };
            let login = new
                .email
                .clone()
                .or_else(|| new.phone.clone())
                .or_else(|| new.username.clone())
                .unwrap_or_else(|| current.display_name.clone());
            display_name(&seed, &login)
        });
        let changes = ProfileChanges {
            username: Some(new.username.clone()),
            email: Some(new.email.clone()),
            phone: Some(new.phone.clone()),
            first_name: Some(opt(data, "first_name")),
            last_name: Some(opt(data, "last_name")),
            display_name: Some(display),
            locale: Some(opt(data, "locale")),
            timezone: Some(opt(data, "timezone")),
            avatar_id: None,
            notes: Some(opt(data, "notes")),
            is_mail_blocked: Some(data.get("is_mail_blocked").is_some_and(|v| is_on(v))),
        };
        store::update_profile_in(backend, cx.conn(), user_id, &changes)
            .await
            .map_err(|e| SaveError::Failed(e.to_string()))?;
        if password_hash.is_some() {
            store::set_password_hash_in(backend, cx.conn(), user_id, password_hash)
                .await
                .map_err(|e| SaveError::Failed(e.to_string()))?;
        }
        Ok(())
    }
}

fn attributes(new: &NewUser) -> [(LoginAttribute, Option<String>); 3] {
    [
        (LoginAttribute::Email, new.email.clone()),
        (LoginAttribute::Phone, new.phone.clone()),
        (LoginAttribute::Username, new.username.clone()),
    ]
}

async fn taken(
    cx: &mut SaveCx<'_>,
    attribute: LoginAttribute,
    value: &str,
    except: Option<i64>,
) -> Result<bool, SaveError> {
    let backend = cx.backend();
    store::is_taken_in(backend, cx.conn(), attribute, value, except)
        .await
        .map_err(|e| SaveError::Failed(e.to_string()))
}

fn opt(data: &HashMap<String, String>, key: &str) -> Option<String> {
    data.get(key)
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

fn is_on(value: &str) -> bool {
    matches!(value, "1" | "true" | "on")
}
