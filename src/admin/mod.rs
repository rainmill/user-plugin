//! The plugin's admin surface. The screens are data: `admin/users.yaml`,
//! `admin/groups.yaml` and `admin/settings.yaml` beside the crate, read at
//! compile time and rendered by the framework's generic handlers. Rust holds
//! what is behaviour: the permissions, the section, the group picker and the
//! user form's write handler.

mod persist;

use std::sync::Arc;

use laterite_admin::nav::NavItem;
use laterite_admin::picker::{PickerSourceReg, TableSource};
use laterite_admin::settings::SettingsItem;
use laterite_admin::{Permission, Resource, ROLE_ADMIN};
use laterite_core::t;

pub(crate) use persist::persister;

/// The permission gating the user screens.
pub const MANAGE: &str = "rainmill.user.manage";
/// The permission gating the group screens.
pub const GROUPS: &str = "rainmill.user.groups";

/// The group table, which the picker reads.
pub(crate) const GROUP_ENTITY: &str = "rainmill_user_group";
/// The registry key of the user write handler (`persist` in `users.yaml`).
pub(crate) const USER_KEY: &str = "rainmill.user.user";
/// The registry key of the group picker source (`source` in `users.yaml`).
pub(crate) const GROUP_KEY: &str = "rainmill.user.group";
/// The sidebar section both screens sit under (`under` in the files).
pub(crate) const SECTION: &str = "rainmill.user";

pub(crate) fn permissions() -> Vec<Permission> {
    vec![
        Permission::new(MANAGE, t!("Manage users"), t!("Users")).roles([ROLE_ADMIN]),
        Permission::new(GROUPS, t!("Manage user groups"), t!("Users")).roles([ROLE_ADMIN]),
        Permission::new(
            crate::settings::PERMISSION,
            t!("Manage user settings"),
            t!("Users"),
        )
        .roles([ROLE_ADMIN]),
    ]
}

pub(crate) fn nav_section() -> NavItem {
    NavItem::section(SECTION, t!("Users")).icon("users")
}

/// The Users screen, from `admin/users.yaml`.
pub(crate) fn users_resource() -> Resource {
    laterite_admin::resource!("admin/users.yaml")
}

/// The Groups screen, from `admin/groups.yaml`.
pub(crate) fn groups_resource() -> Resource {
    laterite_admin::resource!("admin/groups.yaml")
}

/// Settings > Users, from `admin/settings.yaml`.
pub(crate) fn settings_item() -> SettingsItem {
    laterite_admin::settings!("admin/settings.yaml")
}

pub(crate) fn group_picker() -> PickerSourceReg {
    PickerSourceReg::new(
        GROUP_KEY,
        Arc::new(TableSource::new(GROUP_ENTITY, "id", "name").with_hint("code")),
    )
    .require(MANAGE)
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_files_read_and_name_what_the_rust_side_registers() {
        let users = super::users_resource();
        assert_eq!(users.base_path, "/users");
        assert_eq!(
            users.form.as_ref().and_then(|f| f.persist.as_deref()),
            Some(super::USER_KEY)
        );
        assert_eq!(users.relations.len(), 1);
        assert_eq!(
            users.relations[0].pivot.as_ref().map(|p| p.source.as_str()),
            Some(super::GROUP_KEY)
        );
        let groups = super::groups_resource();
        assert_eq!(groups.base_path, "/user-groups");
        let settings = super::settings_item();
        assert_eq!(settings.code, crate::settings::CODE);
        assert_eq!(settings.fields.len(), 9);
    }
}
