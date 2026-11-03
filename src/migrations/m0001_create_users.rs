//! Create the user tables: users, groups, memberships, preferences, the
//! activity log and reset tokens. Portable SQL only: auto-increment integer
//! ids, text timestamps, and the `key_col`/`bool_col` polyfills, so the schema
//! builds on PostgreSQL, MySQL and SQLite alike.

use laterite_core::strata::*;

use crate::schema::RainmillUser as User;
use crate::schema::RainmillUserGroup as Group;
use crate::schema::RainmillUserLog as Log;
use crate::schema::RainmillUserMembership as Membership;
use crate::schema::RainmillUserPreference as Preference;
use crate::schema::RainmillUserReset as Reset;

pub struct Migration;

#[async_trait(?Send)]
impl laterite_core::Migration for Migration {
    fn name(&self) -> &str {
        "0001_create_users"
    }

    async fn up(&self, s: &mut Schema<'_>) -> CoreResult<()> {
        s.exec(
            Table::create()
                .table(Group::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(Group::Id)
                        .big_integer()
                        .not_null()
                        .auto_increment()
                        .primary_key(),
                )
                .col(key_col(Group::Code).not_null().unique_key())
                .col(ColumnDef::new(Group::Name).text().not_null())
                .col(ColumnDef::new(Group::Description).text())
                .col(ColumnDef::new(Group::CreatedAt).text().not_null())
                .col(ColumnDef::new(Group::UpdatedAt).text().not_null())
                .to_owned(),
        )
        .await?;

        s.exec(
            Table::create()
                .table(User::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(User::Id)
                        .big_integer()
                        .not_null()
                        .auto_increment()
                        .primary_key(),
                )
                .col(key_col(User::Username).unique_key())
                .col(key_col(User::Email).unique_key())
                .col(key_col(User::Phone).unique_key())
                .col(ColumnDef::new(User::FirstName).text())
                .col(ColumnDef::new(User::LastName).text())
                .col(ColumnDef::new(User::DisplayName).text().not_null())
                .col(ColumnDef::new(User::PasswordHash).text())
                .col(ColumnDef::new(User::AvatarId).big_integer())
                .col(key_col(User::Locale))
                .col(key_col(User::Timezone))
                .col(bool_col(User::IsGuest).not_null().default(0))
                .col(bool_col(User::IsMailBlocked).not_null().default(0))
                .col(key_col(User::ActivationCode))
                .col(ColumnDef::new(User::ActivatedAt).text())
                .col(ColumnDef::new(User::BannedAt).text())
                .col(ColumnDef::new(User::BannedReason).text())
                .col(ColumnDef::new(User::PrimaryGroupId).big_integer())
                .col(key_col(User::CreatedIp))
                .col(key_col(User::LastIp))
                .col(ColumnDef::new(User::LastSeenAt).text())
                .col(ColumnDef::new(User::Notes).text())
                .col(ColumnDef::new(User::CreatedAt).text().not_null())
                .col(ColumnDef::new(User::UpdatedAt).text().not_null())
                .col(ColumnDef::new(User::DeletedAt).text())
                .foreign_key(
                    ForeignKey::create()
                        .from(User::Table, User::PrimaryGroupId)
                        .to(Group::Table, Group::Id)
                        .on_delete(ForeignKeyAction::SetNull),
                )
                .to_owned(),
        )
        .await?;

        s.exec(
            Index::create()
                .name("idx_rainmill_user_activation_code")
                .table(User::Table)
                .col(User::ActivationCode)
                .to_owned(),
        )
        .await?;

        s.exec(
            Table::create()
                .table(Membership::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(Membership::Id)
                        .big_integer()
                        .not_null()
                        .auto_increment()
                        .primary_key(),
                )
                .col(ColumnDef::new(Membership::UserId).big_integer().not_null())
                .col(ColumnDef::new(Membership::GroupId).big_integer().not_null())
                .foreign_key(
                    ForeignKey::create()
                        .from(Membership::Table, Membership::UserId)
                        .to(User::Table, User::Id)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .foreign_key(
                    ForeignKey::create()
                        .from(Membership::Table, Membership::GroupId)
                        .to(Group::Table, Group::Id)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .to_owned(),
        )
        .await?;

        s.exec(
            Index::create()
                .name("idx_rainmill_user_membership_pair")
                .table(Membership::Table)
                .col(Membership::UserId)
                .col(Membership::GroupId)
                .unique()
                .to_owned(),
        )
        .await?;

        s.exec(
            Table::create()
                .table(Preference::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(Preference::Id)
                        .big_integer()
                        .not_null()
                        .auto_increment()
                        .primary_key(),
                )
                .col(ColumnDef::new(Preference::UserId).big_integer().not_null())
                .col(key_col(Preference::Item).not_null())
                .col(ColumnDef::new(Preference::Value).text())
                .col(ColumnDef::new(Preference::CreatedAt).text().not_null())
                .col(ColumnDef::new(Preference::UpdatedAt).text().not_null())
                .foreign_key(
                    ForeignKey::create()
                        .from(Preference::Table, Preference::UserId)
                        .to(User::Table, User::Id)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .to_owned(),
        )
        .await?;

        s.exec(
            Index::create()
                .name("idx_rainmill_user_preference_user_item")
                .table(Preference::Table)
                .col(Preference::UserId)
                .col(Preference::Item)
                .unique()
                .to_owned(),
        )
        .await?;

        s.exec(
            Table::create()
                .table(Log::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(Log::Id)
                        .big_integer()
                        .not_null()
                        .auto_increment()
                        .primary_key(),
                )
                .col(ColumnDef::new(Log::UserId).big_integer().not_null())
                .col(key_col(Log::Kind).not_null())
                .col(ColumnDef::new(Log::Data).text())
                .col(ColumnDef::new(Log::Comment).text())
                .col(bool_col(Log::IsComment).not_null().default(0))
                .col(bool_col(Log::IsSystem).not_null().default(0))
                .col(key_col(Log::ActorKind))
                .col(ColumnDef::new(Log::ActorId).big_integer())
                .col(ColumnDef::new(Log::CreatedAt).text().not_null())
                .foreign_key(
                    ForeignKey::create()
                        .from(Log::Table, Log::UserId)
                        .to(User::Table, User::Id)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .to_owned(),
        )
        .await?;

        s.exec(
            Index::create()
                .name("idx_rainmill_user_log_user")
                .table(Log::Table)
                .col(Log::UserId)
                .col(Log::CreatedAt)
                .to_owned(),
        )
        .await?;

        s.exec(
            Table::create()
                .table(Reset::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(Reset::Id)
                        .big_integer()
                        .not_null()
                        .auto_increment()
                        .primary_key(),
                )
                .col(ColumnDef::new(Reset::UserId).big_integer().not_null())
                .col(key_col(Reset::Channel).not_null())
                .col(key_col(Reset::TokenHash).not_null().unique_key())
                .col(ColumnDef::new(Reset::ExpiresAt).text().not_null())
                .col(ColumnDef::new(Reset::UsedAt).text())
                .col(ColumnDef::new(Reset::CreatedAt).text().not_null())
                .foreign_key(
                    ForeignKey::create()
                        .from(Reset::Table, Reset::UserId)
                        .to(User::Table, User::Id)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .to_owned(),
        )
        .await?;

        Ok(())
    }
}
