//! Table and column identifiers, as `sea-query` `Iden` enums. The enum name
//! becomes the vendor-prefixed table name in snake_case.

use laterite_core::sea_query;
use sea_query::Iden;

/// The users of the application.
#[derive(Iden)]
pub(crate) enum RainmillUser {
    Table,
    Id,
    Username,
    Email,
    Phone,
    FirstName,
    LastName,
    DisplayName,
    PasswordHash,
    AvatarId,
    Locale,
    Timezone,
    IsGuest,
    IsMailBlocked,
    ActivationCode,
    ActivatedAt,
    BannedAt,
    BannedReason,
    PrimaryGroupId,
    CreatedIp,
    LastIp,
    LastSeenAt,
    Notes,
    CreatedAt,
    UpdatedAt,
    DeletedAt,
}

/// Named groups a user belongs to.
#[derive(Iden)]
pub(crate) enum RainmillUserGroup {
    Table,
    Id,
    Code,
    Name,
    Description,
    CreatedAt,
    UpdatedAt,
}

/// The user-to-group pivot.
#[derive(Iden)]
pub(crate) enum RainmillUserMembership {
    Table,
    Id,
    UserId,
    GroupId,
}

/// A user's preferences, one row per item.
#[derive(Iden)]
pub(crate) enum RainmillUserPreference {
    Table,
    Id,
    UserId,
    Item,
    Value,
    CreatedAt,
    UpdatedAt,
}

/// The per-user activity log.
#[derive(Iden)]
pub(crate) enum RainmillUserLog {
    Table,
    Id,
    UserId,
    Kind,
    Data,
    Comment,
    IsComment,
    IsSystem,
    ActorKind,
    ActorId,
    CreatedAt,
}

/// Password reset and activation tokens, hashed.
#[derive(Iden)]
pub(crate) enum RainmillUserReset {
    Table,
    Id,
    UserId,
    Channel,
    TokenHash,
    ExpiresAt,
    UsedAt,
    CreatedAt,
}
