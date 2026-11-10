//! The operations an application performs on its users: register, activate,
//! sign in by password, change a profile or password, reset a password, ban,
//! deactivate, delete, merge, groups, preferences and the activity log. Every
//! change that other modules care about emits an event.

use chrono::{Duration, SecondsFormat, Utc};
use laterite_auth::password::{hash_password, verify_password};
use laterite_auth::service::PasswordPolicy;
use laterite_core::events::Events;
use laterite_core::serde_json;
use laterite_core::sqlx;
use laterite_core::{CoreError, Db};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::events;
use crate::model::{
    Activation, Actor, Credential, Group, LogEntry, LoginAttribute, NewUser, ProfileChanges,
    Registered, ResetIssued, User, GROUP_GUEST, GROUP_REGISTERED,
};
use crate::settings::UserSettings;
use crate::store::{self, NewLog, NewUserRow};

/// What can go wrong.
#[derive(Debug, thiserror::Error)]
pub enum UserError {
    #[error("registration is closed")]
    RegistrationClosed,
    #[error("{0} is required")]
    Missing(&'static str),
    #[error("{0} is already taken")]
    Taken(&'static str),
    #[error("{0}")]
    Password(String),
    #[error("no such user")]
    NotFound,
    #[error("the credentials do not match")]
    BadCredentials,
    #[error("the account is not active")]
    Inactive,
    #[error("the account is banned")]
    Banned,
    #[error("the code or token is invalid or expired")]
    BadToken,
    #[error("no such group")]
    NoGroup,
    #[error(transparent)]
    Core(#[from] CoreError),
}

impl From<sqlx::Error> for UserError {
    fn from(e: sqlx::Error) -> Self {
        Self::Core(e.into())
    }
}

impl From<laterite_auth::AuthError> for UserError {
    fn from(e: laterite_auth::AuthError) -> Self {
        Self::Password(e.to_string())
    }
}

/// A module answers whether a user owns records that must survive deletion
/// (an order, a post). When any policy says so the delete is soft.
pub trait DeletePolicy: Send + Sync + 'static {
    fn has_dependents(
        &self,
        db: &Db,
        user_id: i64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>>;
}

/// The users service.
#[derive(Clone)]
pub struct Users {
    db: Db,
    events: Events,
    settings: UserSettings,
    policy: PasswordPolicy,
}

impl Users {
    pub fn new(db: Db, events: Events, settings: UserSettings) -> Self {
        Self {
            db,
            events,
            settings,
            policy: PasswordPolicy::default(),
        }
    }

    /// The password policy to apply (default: the framework's).
    pub fn with_password_policy(mut self, policy: PasswordPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn db(&self) -> &Db {
        &self.db
    }

    pub fn settings(&self) -> &UserSettings {
        &self.settings
    }

    // --- registration --------------------------------------------------

    /// Registers a user. Checks the configured login attribute is present and
    /// unique, hashes the password when given, joins the default group, logs
    /// the event and emits `user.registered`. The activation setting decides
    /// whether the user is active at once, must confirm a code (returned in
    /// plain text for delivery), or waits for an operator.
    pub async fn register(&self, new: NewUser) -> Result<Registered, UserError> {
        if !self.settings.allow_registration && !new.is_guest {
            return Err(UserError::RegistrationClosed);
        }
        if new.is_guest && !self.settings.guests {
            return Err(UserError::RegistrationClosed);
        }
        let login = self.settings.login_attribute;
        let login_value = login_value(&new, login).ok_or(UserError::Missing(login.as_str()))?;
        {
            let mut conn = self.db.pool.acquire().await?;
            if store::is_taken_in(self.db.backend, &mut conn, login, &login_value, None).await? {
                return Err(UserError::Taken(login.as_str()));
            }
            for (attribute, value) in [
                (LoginAttribute::Email, &new.email),
                (LoginAttribute::Username, &new.username),
                (LoginAttribute::Phone, &new.phone),
            ] {
                if attribute == login {
                    continue;
                }
                if let Some(value) = value {
                    if store::is_taken_in(self.db.backend, &mut conn, attribute, value, None)
                        .await?
                    {
                        return Err(UserError::Taken(attribute.as_str()));
                    }
                }
            }
        }
        let password_hash = match &new.password {
            Some(plain) => {
                self.policy.check(plain)?;
                Some(hash_password(plain)?)
            }
            None => None,
        };
        let (activation_code, code_hash, activated_at) = if new.is_guest {
            (None, None, Some(store::now()))
        } else {
            match self.settings.activation {
                Activation::Automatic => (None, None, Some(store::now())),
                Activation::User => {
                    let code = token();
                    let hash = hash_token(&code);
                    (Some(code), Some(hash), None)
                }
                Activation::Operator => (None, None, None),
            }
        };
        let group_code = if new.is_guest {
            GROUP_GUEST
        } else {
            GROUP_REGISTERED
        };
        let group_id = store::ensure_group(&self.db, group_code, &title(group_code)).await?;
        let row = NewUserRow {
            username: new.username.clone(),
            email: new.email.clone(),
            phone: new.phone.clone(),
            first_name: new.first_name.clone(),
            last_name: new.last_name.clone(),
            display_name: display_name(&new, &login_value),
            password_hash,
            locale: new.locale.clone(),
            timezone: new.timezone.clone(),
            is_guest: new.is_guest,
            activation_code_hash: code_hash,
            activated_at,
            primary_group_id: Some(group_id),
            created_ip: new.ip.clone(),
        };
        let id = store::insert_user(&self.db, row).await?;
        store::add_membership(&self.db, id, group_id).await?;
        self.log_system(id, "user.registered", None).await?;
        self.events
            .emit(&events::Registered {
                user_id: id,
                is_guest: new.is_guest,
                ip: new.ip,
            })
            .await;
        let user = self.find(id).await?;
        if user.activated_at.is_some() {
            self.events.emit(&events::Activated { user_id: id }).await;
        }
        Ok(Registered {
            user,
            activation_code,
        })
    }

    /// Activates the user holding this code (the one `register` returned).
    pub async fn activate(&self, code: &str) -> Result<User, UserError> {
        let user = store::find_user_by_activation(&self.db, &hash_token(code))
            .await?
            .ok_or(UserError::BadToken)?;
        self.activate_id(user.id).await
    }

    /// Activates a user by id: the operator approval path.
    pub async fn activate_by_operator(&self, id: i64, actor: Actor) -> Result<User, UserError> {
        let user = self.activate_id(id).await?;
        self.log(id, "user.approved", None, Some(actor)).await?;
        Ok(user)
    }

    async fn activate_id(&self, id: i64) -> Result<User, UserError> {
        store::activate(&self.db, id).await?;
        self.log_system(id, "user.activated", None).await?;
        self.events.emit(&events::Activated { user_id: id }).await;
        self.find(id).await
    }

    /// A fresh activation code for a user who lost the first one.
    pub async fn reissue_activation(&self, id: i64) -> Result<String, UserError> {
        let user = self.find(id).await?;
        if user.activated_at.is_some() {
            return Err(UserError::BadToken);
        }
        let code = token();
        store::set_activation_code(&self.db, id, Some(hash_token(&code))).await?;
        Ok(code)
    }

    // --- lookups -------------------------------------------------------

    pub async fn find(&self, id: i64) -> Result<User, UserError> {
        store::find_user(&self.db, id)
            .await?
            .ok_or(UserError::NotFound)
    }

    pub async fn find_optional(&self, id: i64) -> Result<Option<User>, UserError> {
        Ok(store::find_user(&self.db, id).await?)
    }

    /// The user whose configured login attribute equals `value`.
    pub async fn by_login(&self, value: &str) -> Result<Option<User>, UserError> {
        Ok(store::find_user_by(&self.db, self.settings.login_attribute, value).await?)
    }

    pub async fn by_attribute(
        &self,
        attribute: LoginAttribute,
        value: &str,
    ) -> Result<Option<User>, UserError> {
        Ok(store::find_user_by(&self.db, attribute, value).await?)
    }

    // --- sign-in -------------------------------------------------------

    /// Checks a password credential. The gateway calls this; it never starts
    /// a session itself. A user without a password cannot sign in this way.
    pub async fn authenticate(&self, credential: &Credential) -> Result<User, UserError> {
        let user = self
            .by_login(&credential.login)
            .await?
            .ok_or(UserError::BadCredentials)?;
        let hash = user
            .password_hash
            .as_deref()
            .ok_or(UserError::BadCredentials)?;
        if !verify_password(&credential.password, hash)? {
            return Err(UserError::BadCredentials);
        }
        if user.banned_at.is_some() {
            return Err(UserError::Banned);
        }
        if !user.is_active() {
            return Err(UserError::Inactive);
        }
        Ok(user)
    }

    /// Records that the user was seen (the gateway and the mobile plugin call
    /// this), at most once a minute per user.
    pub async fn touch_seen(&self, id: i64, ip: Option<String>) -> Result<(), UserError> {
        if let Some(user) = store::find_user(&self.db, id).await? {
            if let Some(seen) = &user.last_seen_at {
                if let Ok(at) = chrono::DateTime::parse_from_rfc3339(seen) {
                    if Utc::now().signed_duration_since(at) < Duration::minutes(1) {
                        return Ok(());
                    }
                }
            }
            store::touch_seen(&self.db, id, ip).await?;
        }
        Ok(())
    }

    // --- profile and password -----------------------------------------

    /// Changes profile fields, checking uniqueness of any login attribute
    /// that changes, and emits `user.updated`.
    pub async fn update_profile(
        &self,
        id: i64,
        changes: ProfileChanges,
        actor: Option<Actor>,
    ) -> Result<User, UserError> {
        self.find(id).await?;
        {
            let mut conn = self.db.pool.acquire().await?;
            for (attribute, value) in [
                (LoginAttribute::Email, &changes.email),
                (LoginAttribute::Username, &changes.username),
                (LoginAttribute::Phone, &changes.phone),
            ] {
                if let Some(Some(value)) = value {
                    if store::is_taken_in(self.db.backend, &mut conn, attribute, value, Some(id))
                        .await?
                    {
                        return Err(UserError::Taken(attribute.as_str()));
                    }
                }
            }
        }
        store::update_profile(&self.db, id, &changes).await?;
        self.log(id, "user.updated", None, actor).await?;
        self.events.emit(&events::Updated { user_id: id }).await;
        self.find(id).await
    }

    /// Sets (or clears, with `None`) the password after checking the policy.
    pub async fn set_password(
        &self,
        id: i64,
        password: Option<&str>,
        actor: Option<Actor>,
    ) -> Result<(), UserError> {
        self.find(id).await?;
        let hash = match password {
            Some(plain) => {
                self.policy.check(plain)?;
                Some(hash_password(plain)?)
            }
            None => None,
        };
        store::set_password_hash(&self.db, id, hash).await?;
        store::purge_resets(&self.db, id).await?;
        self.log(id, "user.password_changed", None, actor).await?;
        Ok(())
    }

    /// Issues a reset token for the user with this login value. The token is
    /// returned in plain text for delivery and stored hashed. An unknown
    /// login returns `Ok(None)` so a caller can answer the same either way.
    pub async fn request_reset(
        &self,
        login: &str,
        channel: &str,
    ) -> Result<Option<ResetIssued>, UserError> {
        let Some(user) = self.by_login(login).await? else {
            return Ok(None);
        };
        if !user.is_active() {
            return Ok(None);
        }
        let token = token();
        let expires_at = (Utc::now() + Duration::hours(i64::from(self.settings.token_hours)))
            .to_rfc3339_opts(SecondsFormat::Micros, true);
        store::insert_reset(&self.db, user.id, channel, &hash_token(&token), &expires_at).await?;
        self.log_system(user.id, "user.reset_requested", None)
            .await?;
        Ok(Some(ResetIssued {
            user,
            token,
            expires_at,
        }))
    }

    /// Consumes a reset token and sets the new password.
    pub async fn reset(&self, token: &str, password: &str) -> Result<User, UserError> {
        let row = store::find_reset(&self.db, &hash_token(token))
            .await?
            .ok_or(UserError::BadToken)?;
        if row.used_at.is_some() || row.expires_at.as_str() < store::now().as_str() {
            return Err(UserError::BadToken);
        }
        self.policy.check(password)?;
        store::set_password_hash(&self.db, row.user_id, Some(hash_password(password)?)).await?;
        store::mark_reset_used(&self.db, row.id).await?;
        store::purge_resets(&self.db, row.user_id).await?;
        self.log(
            row.user_id,
            "user.password_reset",
            None,
            Some(Actor::user(row.user_id)),
        )
        .await?;
        self.find(row.user_id).await
    }

    // --- ban, deactivate, delete, merge -------------------------------

    pub async fn ban(
        &self,
        id: i64,
        reason: Option<String>,
        actor: Actor,
    ) -> Result<(), UserError> {
        self.find(id).await?;
        store::ban(&self.db, id, reason.clone()).await?;
        self.log(
            id,
            "user.banned",
            reason.as_ref().map(|r| serde_json::json!({ "reason": r })),
            Some(actor),
        )
        .await?;
        self.events
            .emit(&events::Banned {
                user_id: id,
                reason,
            })
            .await;
        Ok(())
    }

    pub async fn unban(&self, id: i64, actor: Actor) -> Result<(), UserError> {
        self.find(id).await?;
        store::unban(&self.db, id).await?;
        self.log(id, "user.unbanned", None, Some(actor)).await?;
        self.events.emit(&events::Unbanned { user_id: id }).await;
        Ok(())
    }

    /// The user opts out: a soft delete that also tells other modules to
    /// disable what the user published.
    pub async fn deactivate(&self, id: i64) -> Result<(), UserError> {
        self.find(id).await?;
        store::soft_delete(&self.db, id).await?;
        self.log(id, "user.deactivated", None, Some(Actor::user(id)))
            .await?;
        self.events.emit(&events::Deactivated { user_id: id }).await;
        Ok(())
    }

    /// Deletes a user: softly when `policies` say the user has dependents or
    /// the settings prefer it, otherwise for good.
    pub async fn delete(
        &self,
        id: i64,
        policies: &[std::sync::Arc<dyn DeletePolicy>],
        actor: Option<Actor>,
    ) -> Result<bool, UserError> {
        self.find(id).await?;
        let mut soft = self.settings.soft_delete;
        for policy in policies {
            if policy.has_dependents(&self.db, id).await {
                soft = true;
                break;
            }
        }
        if soft {
            store::soft_delete(&self.db, id).await?;
            self.log(id, "user.deleted", None, actor).await?;
        } else {
            store::hard_delete(&self.db, id).await?;
        }
        self.events
            .emit(&events::Deleted { user_id: id, soft })
            .await;
        Ok(soft)
    }

    pub async fn restore(&self, id: i64, actor: Actor) -> Result<(), UserError> {
        self.find(id).await?;
        store::restore(&self.db, id).await?;
        self.log(id, "user.restored", None, Some(actor)).await?;
        Ok(())
    }

    /// Merges `from` users into `into`: emits `user.merged` so other modules
    /// reassign what they own, moves the logs, then deletes the merged users
    /// for good. The leading user keeps its own attributes and groups.
    pub async fn merge(&self, into: i64, from: Vec<i64>, actor: Actor) -> Result<(), UserError> {
        self.find(into).await?;
        let from: Vec<i64> = from.into_iter().filter(|id| *id != into).collect();
        for id in &from {
            self.find(*id).await?;
        }
        self.events
            .emit(&events::Merged {
                into,
                from: from.clone(),
            })
            .await;
        for id in &from {
            store::reassign_log(&self.db, *id, into).await?;
            store::hard_delete(&self.db, *id).await?;
        }
        self.log(
            into,
            "user.merged",
            Some(serde_json::json!({ "from": from })),
            Some(actor),
        )
        .await?;
        Ok(())
    }

    /// A guest becomes a registered user: sets the login attribute and
    /// password, moves the primary group, keeps the id and history.
    pub async fn convert_guest(&self, id: i64, new: NewUser) -> Result<User, UserError> {
        let user = self.find(id).await?;
        if !user.is_guest {
            return Ok(user);
        }
        let login = self.settings.login_attribute;
        let login_value = login_value(&new, login).ok_or(UserError::Missing(login.as_str()))?;
        {
            let mut conn = self.db.pool.acquire().await?;
            if store::is_taken_in(self.db.backend, &mut conn, login, &login_value, Some(id)).await?
            {
                return Err(UserError::Taken(login.as_str()));
            }
        }
        let changes = ProfileChanges {
            username: new.username.clone().map(Some),
            email: new.email.clone().map(Some),
            phone: new.phone.clone().map(Some),
            first_name: new.first_name.clone().map(Some),
            last_name: new.last_name.clone().map(Some),
            display_name: Some(display_name(&new, &login_value)),
            ..Default::default()
        };
        store::update_profile(&self.db, id, &changes).await?;
        if let Some(plain) = &new.password {
            self.policy.check(plain)?;
            store::set_password_hash(&self.db, id, Some(hash_password(plain)?)).await?;
        }
        let registered = store::ensure_group(&self.db, GROUP_REGISTERED, "Registered").await?;
        if let Some(guest) = store::find_group_by_code(&self.db, GROUP_GUEST).await? {
            store::remove_membership(&self.db, id, guest.id).await?;
        }
        store::add_membership(&self.db, id, registered).await?;
        store::set_primary_group(&self.db, id, Some(registered)).await?;
        store::update_profile(
            &self.db,
            id,
            &ProfileChanges {
                ..Default::default()
            },
        )
        .await?;
        store::set_guest(&self.db, id, false).await?;
        self.log_system(id, "user.converted", None).await?;
        self.events.emit(&events::Updated { user_id: id }).await;
        self.find(id).await
    }

    // --- groups --------------------------------------------------------

    pub async fn groups(&self) -> Result<Vec<Group>, UserError> {
        Ok(store::list_groups(&self.db).await?)
    }

    pub async fn groups_of(&self, user_id: i64) -> Result<Vec<Group>, UserError> {
        Ok(store::user_groups(&self.db, user_id).await?)
    }

    pub async fn add_to_group(&self, user_id: i64, code: &str) -> Result<(), UserError> {
        let group = store::find_group_by_code(&self.db, code)
            .await?
            .ok_or(UserError::NoGroup)?;
        Ok(store::add_membership(&self.db, user_id, group.id).await?)
    }

    pub async fn remove_from_group(&self, user_id: i64, code: &str) -> Result<(), UserError> {
        let group = store::find_group_by_code(&self.db, code)
            .await?
            .ok_or(UserError::NoGroup)?;
        Ok(store::remove_membership(&self.db, user_id, group.id).await?)
    }

    /// Whether the user is in the group (by membership, or as the primary).
    pub async fn in_group(&self, user_id: i64, code: &str) -> Result<bool, UserError> {
        Ok(self
            .groups_of(user_id)
            .await?
            .iter()
            .any(|g| g.code == code))
    }

    pub async fn set_primary_group(&self, user_id: i64, code: &str) -> Result<(), UserError> {
        let group = store::find_group_by_code(&self.db, code)
            .await?
            .ok_or(UserError::NoGroup)?;
        store::add_membership(&self.db, user_id, group.id).await?;
        Ok(store::set_primary_group(&self.db, user_id, Some(group.id)).await?)
    }

    // --- preferences ---------------------------------------------------

    pub async fn preference(&self, user_id: i64, item: &str) -> Result<Option<String>, UserError> {
        Ok(store::get_preference(&self.db, user_id, item).await?)
    }

    pub async fn set_preference(
        &self,
        user_id: i64,
        item: &str,
        value: &str,
    ) -> Result<(), UserError> {
        Ok(store::set_preference(&self.db, user_id, item, value).await?)
    }

    pub async fn clear_preference(&self, user_id: i64, item: &str) -> Result<(), UserError> {
        Ok(store::delete_preference(&self.db, user_id, item).await?)
    }

    // --- activity log --------------------------------------------------

    /// Writes a log line attributed to an actor (or the system when `None`).
    pub async fn log(
        &self,
        user_id: i64,
        kind: &str,
        data: Option<serde_json::Value>,
        actor: Option<Actor>,
    ) -> Result<i64, UserError> {
        let is_system = actor.is_none();
        Ok(store::insert_log(
            &self.db,
            user_id,
            NewLog {
                kind: kind.to_string(),
                data,
                comment: None,
                is_comment: false,
                is_system,
                actor,
            },
        )
        .await?)
    }

    async fn log_system(
        &self,
        user_id: i64,
        kind: &str,
        data: Option<serde_json::Value>,
    ) -> Result<i64, UserError> {
        self.log(user_id, kind, data, None).await
    }

    /// A free-text note on the timeline, by an operator or the user.
    pub async fn comment(&self, user_id: i64, actor: Actor, text: &str) -> Result<i64, UserError> {
        Ok(store::insert_log(
            &self.db,
            user_id,
            NewLog {
                kind: "user.comment".to_string(),
                data: None,
                comment: Some(text.to_string()),
                is_comment: true,
                is_system: false,
                actor: Some(actor),
            },
        )
        .await?)
    }

    pub async fn timeline(&self, user_id: i64, limit: u64) -> Result<Vec<LogEntry>, UserError> {
        Ok(store::list_log(&self.db, user_id, limit).await?)
    }
}

/// The value of the configured login attribute in a registration.
fn login_value(new: &NewUser, attribute: LoginAttribute) -> Option<String> {
    let value = match attribute {
        LoginAttribute::Email => &new.email,
        LoginAttribute::Username => &new.username,
        LoginAttribute::Phone => &new.phone,
    };
    value
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// The display name: as given, else first and last name, else the login.
pub(crate) fn display_name(new: &NewUser, login: &str) -> String {
    if let Some(name) = new.display_name.as_deref().map(str::trim) {
        if !name.is_empty() {
            return name.to_string();
        }
    }
    let joined = [new.first_name.as_deref(), new.last_name.as_deref()]
        .into_iter()
        .flatten()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if joined.is_empty() {
        login.to_string()
    } else {
        joined
    }
}

fn title(code: &str) -> String {
    let mut chars = code.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// A random 32-byte token, hex encoded.
pub(crate) fn token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// The stored form of a token.
pub(crate) fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}
