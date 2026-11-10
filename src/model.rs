//! The plugin's records as Rust values.

use laterite_core::serde_json;
use serde::{Deserialize, Serialize};

/// A user of the application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub username: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub display_name: String,
    /// Present only for users who sign in with a password.
    pub password_hash: Option<String>,
    pub avatar_id: Option<i64>,
    pub locale: Option<String>,
    pub timezone: Option<String>,
    pub is_guest: bool,
    pub is_mail_blocked: bool,
    pub activated_at: Option<String>,
    pub banned_at: Option<String>,
    pub banned_reason: Option<String>,
    pub primary_group_id: Option<i64>,
    pub created_ip: Option<String>,
    pub last_ip: Option<String>,
    pub last_seen_at: Option<String>,
    pub notes: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub deleted_at: Option<String>,
}

impl User {
    /// Whether the user may sign in: activated, not banned, not deleted.
    pub fn is_active(&self) -> bool {
        self.activated_at.is_some() && self.banned_at.is_none() && self.deleted_at.is_none()
    }

    /// The name shown for the user: the display name, or the login attribute
    /// when nothing else was given.
    pub fn name(&self) -> &str {
        &self.display_name
    }
}

/// A named group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    pub id: i64,
    pub code: String,
    pub name: String,
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// The group every new registered user joins.
pub const GROUP_REGISTERED: &str = "registered";
/// The group a guest user belongs to until converted.
pub const GROUP_GUEST: &str = "guest";

/// Who performed a logged action: an operator, the user themself, another
/// kind of principal, or the system when `None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    /// The principal kind (`operator`, `user`, ...).
    pub kind: String,
    pub id: i64,
}

impl Actor {
    pub fn new(kind: impl Into<String>, id: i64) -> Self {
        Self {
            kind: kind.into(),
            id,
        }
    }

    /// The user acting on their own record.
    pub fn user(id: i64) -> Self {
        Self::new("user", id)
    }

    /// An operator acting from the admin.
    pub fn operator(id: i64) -> Self {
        Self::new("operator", id)
    }
}

/// One line of a user's activity log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: i64,
    pub user_id: i64,
    /// Dot-keyed: `user.registered`, `user.signed_in`, or a kind another module
    /// registers.
    pub kind: String,
    pub data: Option<serde_json::Value>,
    pub comment: Option<String>,
    pub is_comment: bool,
    pub is_system: bool,
    pub actor: Option<Actor>,
    pub created_at: String,
}

/// What a registration supplies. Every login attribute is optional here; the
/// service checks that the configured one is present.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NewUser {
    pub username: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub display_name: Option<String>,
    /// Plain text; hashed before it is stored. `None` for a user who signs in
    /// another way.
    pub password: Option<String>,
    pub locale: Option<String>,
    pub timezone: Option<String>,
    pub is_guest: bool,
    pub ip: Option<String>,
}

/// Profile fields a user or an operator may change after registration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileChanges {
    pub username: Option<Option<String>>,
    pub email: Option<Option<String>>,
    pub phone: Option<Option<String>>,
    pub first_name: Option<Option<String>>,
    pub last_name: Option<Option<String>>,
    pub display_name: Option<String>,
    pub locale: Option<Option<String>>,
    pub timezone: Option<Option<String>>,
    pub avatar_id: Option<Option<i64>>,
    pub notes: Option<Option<String>>,
    pub is_mail_blocked: Option<bool>,
}

/// The attribute a user signs in with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LoginAttribute {
    #[default]
    Email,
    Username,
    Phone,
}

impl LoginAttribute {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Username => "username",
            Self::Phone => "phone",
        }
    }
}

/// How a new account becomes active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Activation {
    /// Active at once.
    #[default]
    Automatic,
    /// The user confirms a code sent to their email or phone.
    User,
    /// An operator approves the account from the admin.
    Operator,
}

/// The result of a registration: the user, and the activation code to deliver
/// when the user must confirm it (plain text; the stored copy is hashed).
#[derive(Debug, Clone)]
pub struct Registered {
    pub user: User,
    pub activation_code: Option<String>,
}

/// A password-reset request that was issued: the user and the plain token to
/// deliver (the stored copy is hashed).
#[derive(Debug, Clone)]
pub struct ResetIssued {
    pub user: User,
    pub token: String,
    pub expires_at: String,
}

/// The credential a sign-in presents.
#[derive(Debug, Clone)]
pub struct Credential {
    /// The login attribute's value: an email, username or phone.
    pub login: String,
    pub password: String,
}
