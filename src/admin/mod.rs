//! The plugin's admin surface: the Users and Groups screens, their
//! permissions, the group picker and the settings screen. Contributed through
//! the module's `register`, so the framework's generic handlers render the
//! screens from these descriptors.

mod persist;

use std::sync::Arc;

use laterite_admin::form::{FormConfig, FormField, Span};
use laterite_admin::list::{ListColumn, ListConfig, ListFilter, SortDir};
use laterite_admin::nav::{NavItem, Placement};
use laterite_admin::picker::{PickerSourceReg, TableSource};
use laterite_admin::relation::{PivotConfig, RelationConfig};
use laterite_admin::{Permission, Resource, ROLE_ADMIN};
use laterite_core::t;

pub(crate) use persist::persister;

/// The permission gating the user screens.
pub const MANAGE: &str = "rainmill.user.manage";
/// The permission gating the group screens.
pub const GROUPS: &str = "rainmill.user.groups";

/// The user table, shared by the descriptors and the persister.
pub(crate) const USER_ENTITY: &str = "rainmill_user";
/// The group table.
pub(crate) const GROUP_ENTITY: &str = "rainmill_user_group";
/// The membership pivot.
pub(crate) const MEMBERSHIP_ENTITY: &str = "rainmill_user_membership";
/// The registry key of the user write handler.
pub(crate) const USER_KEY: &str = "rainmill.user.user";
/// The registry key of the group picker source.
pub(crate) const GROUP_KEY: &str = "rainmill.user.group";
/// The sidebar section both screens sit under.
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

/// The Users screen.
pub(crate) fn users_resource() -> Resource {
    Resource::new("/users", t!("Users"), users_list())
        .menu(Placement::new().under(SECTION).icon("user").order(10))
        .form(users_form())
        .relation(groups_relation())
        .permission(MANAGE)
}

/// The Groups screen.
pub(crate) fn groups_resource() -> Resource {
    Resource::new("/user-groups", t!("Groups"), groups_list())
        .menu(Placement::new().under(SECTION).icon("users").order(20))
        .form(groups_form())
        .permission(GROUPS)
}

pub(crate) fn group_picker() -> PickerSourceReg {
    PickerSourceReg::new(
        GROUP_KEY,
        Arc::new(TableSource::new(GROUP_ENTITY, "id", "name").with_hint("code")),
    )
    .require(MANAGE)
}

fn users_list() -> ListConfig {
    ListConfig::new(
        USER_ENTITY,
        t!("Users"),
        vec![
            ListColumn::new("display_name", t!("Name")).searchable(true),
            ListColumn::new("email", t!("Email")).searchable(true),
            ListColumn::new("phone", t!("Phone")).searchable(true),
            ListColumn::new("username", t!("Username"))
                .searchable(true)
                .invisible(),
            ListColumn::new("activated_at", t!("Activated")).datetime(),
            ListColumn::new("banned_at", t!("Banned"))
                .datetime()
                .invisible(),
            ListColumn::new("last_seen_at", t!("Last seen")).datetime(),
            ListColumn::new("created_at", t!("Registered")).datetime(),
            ListColumn::new("deleted_at", t!("Deleted"))
                .datetime()
                .invisible(),
        ],
    )
    .order("created_at", SortDir::Desc)
    .edit_base("/users")
    .creatable()
    .deletable()
    .filters(vec![
        ListFilter::boolean("is_guest", t!("Guest")),
        ListFilter::date("created_at", t!("Registered")),
        ListFilter::date("last_seen_at", t!("Last seen")),
    ])
}

fn users_form() -> FormConfig {
    let half = Span::columns(6);
    FormConfig::new(
        USER_ENTITY,
        t!("User"),
        "/users",
        "id",
        vec![
            FormField::text("first_name", t!("First name")).span(half),
            FormField::text("last_name", t!("Last name")).span(half),
            FormField::text("display_name", t!("Display name"))
                .help(t!("Shown in place of the first and last name when set."))
                .span(Span::FULL),
            FormField::text("email", t!("Email")).email().span(half),
            FormField::text("phone", t!("Phone"))
                .help(t!("International format, with the country code."))
                .span(half),
            FormField::text("username", t!("Username")).span(half),
            FormField::password("password", t!("Password"))
                .transient()
                .help(t!("Leave empty to keep the current password."))
                .span(half),
            FormField::text("locale", t!("Locale")).span(half),
            FormField::text("timezone", t!("Timezone")).span(half),
            FormField::switch("is_mail_blocked", t!("Block mail to this user")).span(Span::FULL),
            FormField::textarea("notes", t!("Notes")).span(Span::FULL),
        ],
    )
    .persist(USER_KEY)
}

fn groups_relation() -> RelationConfig {
    RelationConfig::belongs_to_many(
        "groups",
        t!("Groups"),
        GROUP_ENTITY,
        PivotConfig::new(MEMBERSHIP_ENTITY, "user_id", "group_id", GROUP_KEY),
        ListConfig::new(
            GROUP_ENTITY,
            t!("Groups"),
            vec![
                ListColumn::new("name", t!("Name")),
                ListColumn::new("code", t!("Code")),
            ],
        )
        .order("name", SortDir::Asc),
    )
    .permission(MANAGE)
}

fn groups_list() -> ListConfig {
    ListConfig::new(
        GROUP_ENTITY,
        t!("Groups"),
        vec![
            ListColumn::new("name", t!("Name")).searchable(true),
            ListColumn::new("code", t!("Code")).searchable(true),
            ListColumn::new("description", t!("Description")),
            ListColumn::new("created_at", t!("Created")).datetime(),
        ],
    )
    .order("name", SortDir::Asc)
    .edit_base("/user-groups")
    .creatable()
    .deletable()
}

fn groups_form() -> FormConfig {
    FormConfig::new(
        GROUP_ENTITY,
        t!("Group"),
        "/user-groups",
        "id",
        vec![
            FormField::text("name", t!("Name")).required(),
            FormField::text("code", t!("Code"))
                .required()
                .unique()
                .help(t!("A stable identifier the application refers to.")),
            FormField::textarea("description", t!("Description")),
        ],
    )
    .timestamps()
}
