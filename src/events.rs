//! The events this plugin emits, dot-keyed under `user.`.

use laterite_core::events::Event;
use serde::{Deserialize, Serialize};

/// A user registered (by themself, an operator, or as a guest).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Registered {
    pub user_id: i64,
    pub is_guest: bool,
    pub ip: Option<String>,
}

impl Event for Registered {
    const NAME: &'static str = "user.registered";
}

/// A user's account became active.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Activated {
    pub user_id: i64,
}

impl Event for Activated {
    const NAME: &'static str = "user.activated";
}

/// A user opted out and deactivated their account; other modules disable
/// what the user published.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deactivated {
    pub user_id: i64,
}

impl Event for Deactivated {
    const NAME: &'static str = "user.deactivated";
}

/// A user's profile changed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Updated {
    pub user_id: i64,
}

impl Event for Updated {
    const NAME: &'static str = "user.updated";
}

/// A user was banned; sessions and tokens should be revoked by whoever holds
/// them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Banned {
    pub user_id: i64,
    pub reason: Option<String>,
}

impl Event for Banned {
    const NAME: &'static str = "user.banned";
}

/// A ban was lifted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Unbanned {
    pub user_id: i64,
}

impl Event for Unbanned {
    const NAME: &'static str = "user.unbanned";
}

/// Users were merged into one; listeners reassign records they own from each
/// `from` user to `into`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Merged {
    pub into: i64,
    pub from: Vec<i64>,
}

impl Event for Merged {
    const NAME: &'static str = "user.merged";
}

/// A user was deleted, softly (restorable) or for good.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deleted {
    pub user_id: i64,
    pub soft: bool,
}

impl Event for Deleted {
    const NAME: &'static str = "user.deleted";
}
