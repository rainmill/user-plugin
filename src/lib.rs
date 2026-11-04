//! Rainmill User: the users of a Laterite application.
//!
//! The framework's auth crate holds the operators who sign in to the admin.
//! This plugin holds the people who register on the site or in the app: their
//! profile, password (optional: a user who signs in by code or through a
//! provider has none), groups, preferences and an activity log. Registration,
//! activation, bans, deletion and merging are operations on [`Users`]; each
//! emits an event under `user.` so other modules react.
//!
//! The admin gets a Users section with the Users and Groups screens and a
//! settings page, each declared in a YAML file under `admin/`. Signing users
//! in is the auth gateway's job; this plugin answers its credential and
//! lookup questions.

mod admin;
pub mod events;
pub mod migrations;
pub mod model;
mod schema;
pub mod service;
pub mod settings;
pub mod store;

use laterite_core::mail::MailRegistry;
use laterite_core::module::BootCx;
use laterite_core::{CoreResult, MigrationSet, Module, ModuleId, Registry};

pub use model::{
    Activation, Actor, Credential, Group, LogEntry, LoginAttribute, NewUser, ProfileChanges,
    Registered, ResetIssued, User, GROUP_GUEST, GROUP_REGISTERED,
};
pub use service::{DeletePolicy, UserError, Users};
pub use settings::UserSettings;

/// The mail template codes this plugin registers.
pub mod mail {
    pub const WELCOME: &str = "rainmill.user::welcome";
    pub const ACTIVATE: &str = "rainmill.user::activate";
    pub const INVITE: &str = "rainmill.user::invite";
    pub const RESET: &str = "rainmill.user::reset";
    pub const VERIFY: &str = "rainmill.user::verify";
    pub const NEW_USER: &str = "rainmill.user::new_user";
}

/// This plugin's entry point. Every Laterite plugin exposes `module()`, so the
/// generated plugin manifest collects it without naming the type.
pub fn module() -> Box<dyn Module> {
    Box::new(UserModule)
}

/// The Rainmill User plugin.
pub struct UserModule;

#[laterite_core::strata::async_trait]
impl Module for UserModule {
    fn id(&self) -> ModuleId {
        ModuleId::new(migrations::MODULE_ID)
    }

    fn migrations(&self) -> MigrationSet {
        migrations::migrations()
    }

    fn register(&self, registry: &mut Registry) {
        use laterite_admin::AdminRegistry;
        for permission in admin::permissions() {
            registry.add_permission(permission);
        }
        registry.add_nav(admin::nav_section());
        registry.add_resource(admin::users_resource());
        registry.add_resource(admin::groups_resource());
        registry.add_picker_source(admin::group_picker());
        registry.add_persister(admin::persister());
        registry.add_settings(admin::settings_item());
        registry.add_mail_template(mail::WELCOME, include_str!("../mail/welcome.htm"));
        registry.add_mail_template(mail::ACTIVATE, include_str!("../mail/activate.htm"));
        registry.add_mail_template(mail::INVITE, include_str!("../mail/invite.htm"));
        registry.add_mail_template(mail::RESET, include_str!("../mail/reset.htm"));
        registry.add_mail_template(mail::VERIFY, include_str!("../mail/verify.htm"));
        registry.add_mail_template(mail::NEW_USER, include_str!("../mail/new_user.htm"));
    }

    async fn boot(&self, cx: &BootCx<'_>) -> CoreResult<()> {
        // The two groups every installation has. Idempotent: an existing code
        // is left alone, renamed or not.
        store::ensure_group(cx.db, GROUP_REGISTERED, "Registered").await?;
        store::ensure_group(cx.db, GROUP_GUEST, "Guest").await?;
        Ok(())
    }
}
