//! The plugin's settings (Settings > Users): how users sign in, register and
//! become active, and what happens when they are deleted.

use laterite_admin::form::FormField;
use laterite_admin::settings::{SettingsItem, SettingsModel};
use laterite_core::t;
use serde::{Deserialize, Serialize};

use crate::model::{Activation, LoginAttribute};

/// The stored settings model. Every field has a default so an application
/// that never opens the screen behaves sensibly.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct UserSettings {
    /// The attribute a user signs in with.
    pub login_attribute: LoginAttribute,
    /// Whether the site accepts registrations.
    pub allow_registration: bool,
    /// How a new account becomes active.
    pub activation: Activation,
    /// One session at a time per user (enforced by the auth gateway).
    pub block_persistence: bool,
    /// Keep deleted users restorable when no delete policy answers.
    pub soft_delete: bool,
    /// Allow guest users (checkout-style flows).
    pub guests: bool,
    /// Mail the new user a welcome message.
    pub notify_user: bool,
    /// Mail the operators about every new user.
    pub notify_operators: bool,
    /// Hours an activation code or reset token stays valid.
    pub token_hours: u32,
}

impl Default for UserSettings {
    fn default() -> Self {
        Self {
            login_attribute: LoginAttribute::Email,
            allow_registration: true,
            activation: Activation::Automatic,
            block_persistence: false,
            soft_delete: true,
            guests: false,
            notify_user: true,
            notify_operators: false,
            token_hours: 24,
        }
    }
}

impl SettingsModel for UserSettings {
    const CODE: &'static str = "rainmill.user.settings";
}

impl UserSettings {
    /// Loads the saved settings, or the defaults when none were saved.
    pub async fn load(db: &laterite_core::Db) -> Self {
        laterite_admin::settings::store::load::<Self>(db)
            .await
            .unwrap_or_default()
    }
}

/// The permission to change these settings.
pub const PERMISSION: &str = "rainmill.user.settings";

/// The settings screen, as the module registers it.
pub fn settings_item() -> SettingsItem {
    SettingsItem::new(
        UserSettings::CODE,
        t!("Users"),
        vec![
            FormField::select(
                "login_attribute",
                t!("Sign in with"),
                vec![
                    ("email", "Email address"),
                    ("username", "Username"),
                    ("phone", "Phone number"),
                ],
            )
            .help(t!(
                "The attribute a user types to sign in. It must be unique."
            )),
            FormField::switch("allow_registration", t!("Allow registration")),
            FormField::select(
                "activation",
                t!("Activation"),
                vec![
                    ("automatic", "Automatic"),
                    ("user", "The user confirms a code"),
                    ("operator", "An operator approves the account"),
                ],
            ),
            FormField::switch("block_persistence", t!("One session at a time")),
            FormField::switch("soft_delete", t!("Keep deleted users restorable")),
            FormField::switch("guests", t!("Allow guest users")),
            FormField::switch("notify_user", t!("Send new users a welcome message")),
            FormField::switch("notify_operators", t!("Tell operators about new users")),
            FormField::text("token_hours", t!("Code validity (hours)")).help(t!(
                "How long an activation code or password reset link works."
            )),
        ],
    )
    .description(t!(
        "Sign-in, registration and activation for the application's users."
    ))
    .category(t!("Users"))
    .icon("users")
    .permission(PERMISSION)
}
