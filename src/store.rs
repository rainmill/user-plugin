//! Row-level reads and writes, portable across backends through `sea-query`
//! and the framework's query helpers. The service layer ([`crate::service`])
//! composes these into the operations the application calls; the admin
//! persister calls the `_in` variants inside the form's own transaction.
//!
//! Every statement is built in its own block and rendered to SQL before the
//! query awaits: a `sea-query` statement holds `Rc` identifiers and must not
//! live across an await point.

use chrono::{SecondsFormat, Utc};
use laterite_core::strata::*;
use sqlx::any::AnyRow;

use crate::model::{Actor, Group, LogEntry, LoginAttribute, ProfileChanges, User};
use crate::schema::RainmillUser as U;
use crate::schema::RainmillUserGroup as G;
use crate::schema::RainmillUserLog as L;
use crate::schema::RainmillUserMembership as M;
use crate::schema::RainmillUserPreference as P;
use crate::schema::RainmillUserReset as R;

/// The one timestamp format the framework stores: RFC 3339, UTC, microseconds.
pub fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true)
}

/// The columns an insert writes for a new user.
#[derive(Debug, Clone)]
pub struct NewUserRow {
    pub username: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub display_name: String,
    pub password_hash: Option<String>,
    pub locale: Option<String>,
    pub timezone: Option<String>,
    pub is_guest: bool,
    pub activation_code_hash: Option<String>,
    pub activated_at: Option<String>,
    pub primary_group_id: Option<i64>,
    pub created_ip: Option<String>,
}

fn user_columns() -> [U; 24] {
    [
        U::Id,
        U::Username,
        U::Email,
        U::Phone,
        U::FirstName,
        U::LastName,
        U::DisplayName,
        U::PasswordHash,
        U::AvatarId,
        U::Locale,
        U::Timezone,
        U::IsGuest,
        U::IsMailBlocked,
        U::ActivatedAt,
        U::BannedAt,
        U::BannedReason,
        U::PrimaryGroupId,
        U::CreatedIp,
        U::LastIp,
        U::LastSeenAt,
        U::Notes,
        U::CreatedAt,
        U::UpdatedAt,
        U::DeletedAt,
    ]
}

fn group_columns() -> [G; 6] {
    [
        G::Id,
        G::Code,
        G::Name,
        G::Description,
        G::CreatedAt,
        G::UpdatedAt,
    ]
}

fn user_from_row(row: &AnyRow) -> Result<User, sqlx::Error> {
    Ok(User {
        id: row.get_int("id")?,
        username: row.get_text_opt("username")?,
        email: row.get_text_opt("email")?,
        phone: row.get_text_opt("phone")?,
        first_name: row.get_text_opt("first_name")?,
        last_name: row.get_text_opt("last_name")?,
        display_name: row.get_text("display_name")?,
        password_hash: row.get_text_opt("password_hash")?,
        avatar_id: row.get_int_opt("avatar_id")?,
        locale: row.get_text_opt("locale")?,
        timezone: row.get_text_opt("timezone")?,
        is_guest: row.get_bool("is_guest")?,
        is_mail_blocked: row.get_bool("is_mail_blocked")?,
        activated_at: row.get_text_opt("activated_at")?,
        banned_at: row.get_text_opt("banned_at")?,
        banned_reason: row.get_text_opt("banned_reason")?,
        primary_group_id: row.get_int_opt("primary_group_id")?,
        created_ip: row.get_text_opt("created_ip")?,
        last_ip: row.get_text_opt("last_ip")?,
        last_seen_at: row.get_text_opt("last_seen_at")?,
        notes: row.get_text_opt("notes")?,
        created_at: row.get_text("created_at")?,
        updated_at: row.get_text("updated_at")?,
        deleted_at: row.get_text_opt("deleted_at")?,
    })
}

fn group_from_row(row: &AnyRow) -> Result<Group, sqlx::Error> {
    Ok(Group {
        id: row.get_int("id")?,
        code: row.get_text("code")?,
        name: row.get_text("name")?,
        description: row.get_text_opt("description")?,
        created_at: row.get_text("created_at")?,
        updated_at: row.get_text("updated_at")?,
    })
}

fn log_from_row(row: &AnyRow) -> Result<LogEntry, sqlx::Error> {
    let data = row
        .get_text_opt("data")?
        .and_then(|text| serde_json::from_str(&text).ok());
    let actor = match (
        row.get_text_opt("actor_kind")?,
        row.get_int_opt("actor_id")?,
    ) {
        (Some(kind), Some(id)) => Some(Actor::new(kind, id)),
        _ => None,
    };
    Ok(LogEntry {
        id: row.get_int("id")?,
        user_id: row.get_int("user_id")?,
        kind: row.get_text("kind")?,
        data,
        comment: row.get_text_opt("comment")?,
        is_comment: row.get_bool("is_comment")?,
        is_system: row.get_bool("is_system")?,
        actor,
        created_at: row.get_text("created_at")?,
    })
}

fn login_column(attribute: LoginAttribute) -> U {
    match attribute {
        LoginAttribute::Email => U::Email,
        LoginAttribute::Username => U::Username,
        LoginAttribute::Phone => U::Phone,
    }
}

// --- users -------------------------------------------------------------

pub async fn insert_user(db: &Db, row: NewUserRow) -> CoreResult<i64> {
    let mut conn = db.pool.acquire().await?;
    insert_user_in(db.backend, &mut conn, row).await
}

pub async fn insert_user_in(
    backend: DbBackend,
    conn: &mut sqlx::AnyConnection,
    row: NewUserRow,
) -> CoreResult<i64> {
    let now = now();
    let insert = {
        let mut insert = Query::insert();
        insert
            .into_table(U::Table)
            .columns([
                U::Username,
                U::Email,
                U::Phone,
                U::FirstName,
                U::LastName,
                U::DisplayName,
                U::PasswordHash,
                U::Locale,
                U::Timezone,
                U::IsGuest,
                U::IsMailBlocked,
                U::ActivationCode,
                U::ActivatedAt,
                U::PrimaryGroupId,
                U::CreatedIp,
                U::CreatedAt,
                U::UpdatedAt,
            ])
            .values_panic([
                row.username.into(),
                row.email.into(),
                row.phone.into(),
                row.first_name.into(),
                row.last_name.into(),
                row.display_name.into(),
                row.password_hash.into(),
                row.locale.into(),
                row.timezone.into(),
                row.is_guest.into(),
                false.into(),
                row.activation_code_hash.into(),
                row.activated_at.into(),
                row.primary_group_id.into(),
                row.created_ip.into(),
                now.clone().into(),
                now.into(),
            ]);
        insert.to_owned()
    };
    Ok(insert_returning_id_on(backend, &mut *conn, insert, U::Id).await?)
}

pub async fn find_user(db: &Db, id: i64) -> CoreResult<Option<User>> {
    let mut conn = db.pool.acquire().await?;
    find_user_in(db.backend, &mut conn, id).await
}

pub async fn find_user_in(
    backend: DbBackend,
    conn: &mut sqlx::AnyConnection,
    id: i64,
) -> CoreResult<Option<User>> {
    let (sql, values) = build(
        backend,
        Query::select()
            .columns(user_columns())
            .from(U::Table)
            .and_where(Expr::col(U::Id).eq(id))
            .to_owned(),
    );
    let row = bind_values(sqlx::query(&sql), values)
        .fetch_optional(&mut *conn)
        .await?;
    Ok(row.as_ref().map(user_from_row).transpose()?)
}

/// The user whose login attribute equals `value`, deleted users excluded.
pub async fn find_user_by(
    db: &Db,
    attribute: LoginAttribute,
    value: &str,
) -> CoreResult<Option<User>> {
    let (sql, values) = build(
        db.backend,
        Query::select()
            .columns(user_columns())
            .from(U::Table)
            .and_where(Expr::col(login_column(attribute)).eq(value))
            .and_where(Expr::col(U::DeletedAt).is_null())
            .to_owned(),
    );
    let row = bind_values(sqlx::query(&sql), values)
        .fetch_optional(&db.pool)
        .await?;
    Ok(row.as_ref().map(user_from_row).transpose()?)
}

/// The user holding this (hashed) activation code.
pub async fn find_user_by_activation(db: &Db, code_hash: &str) -> CoreResult<Option<User>> {
    let (sql, values) = build(
        db.backend,
        Query::select()
            .columns(user_columns())
            .from(U::Table)
            .and_where(Expr::col(U::ActivationCode).eq(code_hash))
            .and_where(Expr::col(U::DeletedAt).is_null())
            .to_owned(),
    );
    let row = bind_values(sqlx::query(&sql), values)
        .fetch_optional(&db.pool)
        .await?;
    Ok(row.as_ref().map(user_from_row).transpose()?)
}

/// Whether another user (not `except`) already holds `value` in the
/// attribute's column.
pub async fn is_taken_in(
    backend: DbBackend,
    conn: &mut sqlx::AnyConnection,
    attribute: LoginAttribute,
    value: &str,
    except: Option<i64>,
) -> CoreResult<bool> {
    let (sql, values) = {
        let mut select = Query::select();
        select
            .column(U::Id)
            .from(U::Table)
            .and_where(Expr::col(login_column(attribute)).eq(value));
        if let Some(id) = except {
            select.and_where(Expr::col(U::Id).ne(id));
        }
        build(backend, select.to_owned())
    };
    let row = bind_values(sqlx::query(&sql), values)
        .fetch_optional(&mut *conn)
        .await?;
    Ok(row.is_some())
}

/// Sets columns on one user, stamping `updated_at`.
async fn set_columns_in(
    backend: DbBackend,
    conn: &mut sqlx::AnyConnection,
    id: i64,
    pairs: Vec<(U, sea_query::Value)>,
) -> CoreResult<()> {
    let (sql, values) = {
        let mut update = Query::update();
        update.table(U::Table);
        for (column, value) in pairs {
            update.value(column, value);
        }
        update
            .value(U::UpdatedAt, Expr::val(now()))
            .and_where(Expr::col(U::Id).eq(id));
        build(backend, update.to_owned())
    };
    bind_values(sqlx::query(&sql), values)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

async fn set_columns(db: &Db, id: i64, pairs: Vec<(U, sea_query::Value)>) -> CoreResult<()> {
    let mut conn = db.pool.acquire().await?;
    set_columns_in(db.backend, &mut conn, id, pairs).await
}

pub async fn update_profile_in(
    backend: DbBackend,
    conn: &mut sqlx::AnyConnection,
    id: i64,
    changes: &ProfileChanges,
) -> CoreResult<()> {
    let mut pairs: Vec<(U, sea_query::Value)> = Vec::new();
    if let Some(v) = &changes.username {
        pairs.push((U::Username, v.clone().into()));
    }
    if let Some(v) = &changes.email {
        pairs.push((U::Email, v.clone().into()));
    }
    if let Some(v) = &changes.phone {
        pairs.push((U::Phone, v.clone().into()));
    }
    if let Some(v) = &changes.first_name {
        pairs.push((U::FirstName, v.clone().into()));
    }
    if let Some(v) = &changes.last_name {
        pairs.push((U::LastName, v.clone().into()));
    }
    if let Some(v) = &changes.display_name {
        pairs.push((U::DisplayName, v.clone().into()));
    }
    if let Some(v) = &changes.locale {
        pairs.push((U::Locale, v.clone().into()));
    }
    if let Some(v) = &changes.timezone {
        pairs.push((U::Timezone, v.clone().into()));
    }
    if let Some(v) = &changes.avatar_id {
        pairs.push((U::AvatarId, (*v).into()));
    }
    if let Some(v) = &changes.notes {
        pairs.push((U::Notes, v.clone().into()));
    }
    if let Some(v) = changes.is_mail_blocked {
        pairs.push((U::IsMailBlocked, v.into()));
    }
    if pairs.is_empty() {
        return Ok(());
    }
    set_columns_in(backend, conn, id, pairs).await
}

pub async fn update_profile(db: &Db, id: i64, changes: &ProfileChanges) -> CoreResult<()> {
    let mut conn = db.pool.acquire().await?;
    update_profile_in(db.backend, &mut conn, id, changes).await
}

pub async fn set_password_hash(db: &Db, id: i64, hash: Option<String>) -> CoreResult<()> {
    set_columns(db, id, vec![(U::PasswordHash, hash.into())]).await
}

pub async fn set_password_hash_in(
    backend: DbBackend,
    conn: &mut sqlx::AnyConnection,
    id: i64,
    hash: Option<String>,
) -> CoreResult<()> {
    set_columns_in(backend, conn, id, vec![(U::PasswordHash, hash.into())]).await
}

pub async fn set_activation_code(db: &Db, id: i64, code_hash: Option<String>) -> CoreResult<()> {
    set_columns(db, id, vec![(U::ActivationCode, code_hash.into())]).await
}

pub async fn activate(db: &Db, id: i64) -> CoreResult<()> {
    set_columns(
        db,
        id,
        vec![
            (U::ActivatedAt, now().into()),
            (U::ActivationCode, sea_query::Value::String(None)),
        ],
    )
    .await
}

pub async fn ban(db: &Db, id: i64, reason: Option<String>) -> CoreResult<()> {
    set_columns(
        db,
        id,
        vec![
            (U::BannedAt, now().into()),
            (U::BannedReason, reason.into()),
        ],
    )
    .await
}

pub async fn unban(db: &Db, id: i64) -> CoreResult<()> {
    set_columns(
        db,
        id,
        vec![
            (U::BannedAt, sea_query::Value::String(None)),
            (U::BannedReason, sea_query::Value::String(None)),
        ],
    )
    .await
}

pub async fn soft_delete(db: &Db, id: i64) -> CoreResult<()> {
    set_columns(db, id, vec![(U::DeletedAt, now().into())]).await
}

pub async fn restore(db: &Db, id: i64) -> CoreResult<()> {
    set_columns(db, id, vec![(U::DeletedAt, sea_query::Value::String(None))]).await
}

pub async fn hard_delete(db: &Db, id: i64) -> CoreResult<()> {
    let (sql, values) = build(
        db.backend,
        Query::delete()
            .from_table(U::Table)
            .and_where(Expr::col(U::Id).eq(id))
            .to_owned(),
    );
    bind_values(sqlx::query(&sql), values)
        .execute(&db.pool)
        .await?;
    Ok(())
}

pub async fn touch_seen(db: &Db, id: i64, ip: Option<String>) -> CoreResult<()> {
    let mut pairs = vec![(U::LastSeenAt, now().into())];
    if ip.is_some() {
        pairs.push((U::LastIp, ip.into()));
    }
    set_columns(db, id, pairs).await
}

pub async fn set_primary_group(db: &Db, id: i64, group_id: Option<i64>) -> CoreResult<()> {
    set_columns(db, id, vec![(U::PrimaryGroupId, group_id.into())]).await
}

pub async fn set_guest(db: &Db, id: i64, is_guest: bool) -> CoreResult<()> {
    set_columns(db, id, vec![(U::IsGuest, is_guest.into())]).await
}

// --- groups ------------------------------------------------------------

pub async fn insert_group(
    db: &Db,
    code: &str,
    name: &str,
    description: Option<&str>,
) -> CoreResult<i64> {
    let now = now();
    let insert = {
        let mut insert = Query::insert();
        insert
            .into_table(G::Table)
            .columns([G::Code, G::Name, G::Description, G::CreatedAt, G::UpdatedAt])
            .values_panic([
                code.into(),
                name.into(),
                description.into(),
                now.clone().into(),
                now.into(),
            ]);
        insert.to_owned()
    };
    Ok(insert_returning_id(db, insert, G::Id).await?)
}

/// Creates the group when no group has the code; returns its id either way.
pub async fn ensure_group(db: &Db, code: &str, name: &str) -> CoreResult<i64> {
    if let Some(group) = find_group_by_code(db, code).await? {
        return Ok(group.id);
    }
    insert_group(db, code, name, None).await
}

/// [`ensure_group`] on a borrowed connection (inside a form's transaction).
pub async fn ensure_group_in(
    backend: DbBackend,
    conn: &mut sqlx::AnyConnection,
    code: &str,
    name: &str,
) -> CoreResult<i64> {
    let (sql, values) = build(
        backend,
        Query::select()
            .column(G::Id)
            .from(G::Table)
            .and_where(Expr::col(G::Code).eq(code))
            .to_owned(),
    );
    if let Some(row) = bind_values(sqlx::query(&sql), values)
        .fetch_optional(&mut *conn)
        .await?
    {
        return Ok(row.get_int("id")?);
    }
    let now = now();
    let insert = {
        let mut insert = Query::insert();
        insert
            .into_table(G::Table)
            .columns([G::Code, G::Name, G::CreatedAt, G::UpdatedAt])
            .values_panic([code.into(), name.into(), now.clone().into(), now.into()]);
        insert.to_owned()
    };
    Ok(insert_returning_id_on(backend, &mut *conn, insert, G::Id).await?)
}

/// [`add_membership`] on a borrowed connection.
pub async fn add_membership_in(
    backend: DbBackend,
    conn: &mut sqlx::AnyConnection,
    user_id: i64,
    group_id: i64,
) -> CoreResult<()> {
    let (sql, values) = {
        let mut insert = Query::insert();
        insert
            .into_table(M::Table)
            .columns([M::UserId, M::GroupId])
            .values_panic([user_id.into(), group_id.into()])
            .on_conflict(on_conflict_ignore([M::UserId, M::GroupId]));
        build(backend, insert.to_owned())
    };
    bind_values(sqlx::query(&sql), values)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

pub async fn find_group(db: &Db, id: i64) -> CoreResult<Option<Group>> {
    let (sql, values) = build(
        db.backend,
        Query::select()
            .columns(group_columns())
            .from(G::Table)
            .and_where(Expr::col(G::Id).eq(id))
            .to_owned(),
    );
    let row = bind_values(sqlx::query(&sql), values)
        .fetch_optional(&db.pool)
        .await?;
    Ok(row.as_ref().map(group_from_row).transpose()?)
}

pub async fn find_group_by_code(db: &Db, code: &str) -> CoreResult<Option<Group>> {
    let (sql, values) = build(
        db.backend,
        Query::select()
            .columns(group_columns())
            .from(G::Table)
            .and_where(Expr::col(G::Code).eq(code))
            .to_owned(),
    );
    let row = bind_values(sqlx::query(&sql), values)
        .fetch_optional(&db.pool)
        .await?;
    Ok(row.as_ref().map(group_from_row).transpose()?)
}

pub async fn list_groups(db: &Db) -> CoreResult<Vec<Group>> {
    let (sql, values) = build(
        db.backend,
        Query::select()
            .columns(group_columns())
            .from(G::Table)
            .order_by(G::Name, Order::Asc)
            .to_owned(),
    );
    let rows = bind_values(sqlx::query(&sql), values)
        .fetch_all(&db.pool)
        .await?;
    Ok(rows
        .iter()
        .map(group_from_row)
        .collect::<Result<Vec<_>, _>>()?)
}

pub async fn add_membership(db: &Db, user_id: i64, group_id: i64) -> CoreResult<()> {
    let (sql, values) = {
        let mut insert = Query::insert();
        insert
            .into_table(M::Table)
            .columns([M::UserId, M::GroupId])
            .values_panic([user_id.into(), group_id.into()])
            .on_conflict(on_conflict_ignore([M::UserId, M::GroupId]));
        build(db.backend, insert.to_owned())
    };
    bind_values(sqlx::query(&sql), values)
        .execute(&db.pool)
        .await?;
    Ok(())
}

pub async fn remove_membership(db: &Db, user_id: i64, group_id: i64) -> CoreResult<()> {
    let (sql, values) = build(
        db.backend,
        Query::delete()
            .from_table(M::Table)
            .and_where(Expr::col(M::UserId).eq(user_id))
            .and_where(Expr::col(M::GroupId).eq(group_id))
            .to_owned(),
    );
    bind_values(sqlx::query(&sql), values)
        .execute(&db.pool)
        .await?;
    Ok(())
}

/// The groups a user belongs to, by name.
pub async fn user_groups(db: &Db, user_id: i64) -> CoreResult<Vec<Group>> {
    let (sql, values) = build(
        db.backend,
        Query::select()
            .columns([
                (G::Table, G::Id),
                (G::Table, G::Code),
                (G::Table, G::Name),
                (G::Table, G::Description),
                (G::Table, G::CreatedAt),
                (G::Table, G::UpdatedAt),
            ])
            .from(G::Table)
            .inner_join(
                M::Table,
                Expr::col((M::Table, M::GroupId)).equals((G::Table, G::Id)),
            )
            .and_where(Expr::col((M::Table, M::UserId)).eq(user_id))
            .order_by((G::Table, G::Name), Order::Asc)
            .to_owned(),
    );
    let rows = bind_values(sqlx::query(&sql), values)
        .fetch_all(&db.pool)
        .await?;
    Ok(rows
        .iter()
        .map(group_from_row)
        .collect::<Result<Vec<_>, _>>()?)
}

// --- preferences -------------------------------------------------------

pub async fn get_preference(db: &Db, user_id: i64, item: &str) -> CoreResult<Option<String>> {
    let (sql, values) = build(
        db.backend,
        Query::select()
            .column(P::Value)
            .from(P::Table)
            .and_where(Expr::col(P::UserId).eq(user_id))
            .and_where(Expr::col(P::Item).eq(item))
            .to_owned(),
    );
    let row = bind_values(sqlx::query(&sql), values)
        .fetch_optional(&db.pool)
        .await?;
    Ok(row.map(|r| r.get_text_opt("value")).transpose()?.flatten())
}

pub async fn set_preference(db: &Db, user_id: i64, item: &str, value: &str) -> CoreResult<()> {
    let now = now();
    let (sql, values) = build(
        db.backend,
        Query::update()
            .table(P::Table)
            .value(P::Value, Expr::val(value))
            .value(P::UpdatedAt, Expr::val(now.clone()))
            .and_where(Expr::col(P::UserId).eq(user_id))
            .and_where(Expr::col(P::Item).eq(item))
            .to_owned(),
    );
    let changed = bind_values(sqlx::query(&sql), values)
        .execute(&db.pool)
        .await?
        .rows_affected();
    if changed > 0 {
        return Ok(());
    }
    let (sql, values) = {
        let mut insert = Query::insert();
        insert
            .into_table(P::Table)
            .columns([P::UserId, P::Item, P::Value, P::CreatedAt, P::UpdatedAt])
            .values_panic([
                user_id.into(),
                item.into(),
                value.into(),
                now.clone().into(),
                now.into(),
            ]);
        build(db.backend, insert.to_owned())
    };
    bind_values(sqlx::query(&sql), values)
        .execute(&db.pool)
        .await?;
    Ok(())
}

pub async fn delete_preference(db: &Db, user_id: i64, item: &str) -> CoreResult<()> {
    let (sql, values) = build(
        db.backend,
        Query::delete()
            .from_table(P::Table)
            .and_where(Expr::col(P::UserId).eq(user_id))
            .and_where(Expr::col(P::Item).eq(item))
            .to_owned(),
    );
    bind_values(sqlx::query(&sql), values)
        .execute(&db.pool)
        .await?;
    Ok(())
}

// --- activity log ------------------------------------------------------

/// What one log line records.
#[derive(Debug, Clone, Default)]
pub struct NewLog {
    pub kind: String,
    pub data: Option<serde_json::Value>,
    pub comment: Option<String>,
    pub is_comment: bool,
    pub is_system: bool,
    pub actor: Option<Actor>,
}

pub async fn insert_log(db: &Db, user_id: i64, entry: NewLog) -> CoreResult<i64> {
    let (actor_kind, actor_id) = match entry.actor {
        Some(actor) => (Some(actor.kind), Some(actor.id)),
        None => (None, None),
    };
    let data = entry.data.map(|v| v.to_string());
    let insert = {
        let mut insert = Query::insert();
        insert
            .into_table(L::Table)
            .columns([
                L::UserId,
                L::Kind,
                L::Data,
                L::Comment,
                L::IsComment,
                L::IsSystem,
                L::ActorKind,
                L::ActorId,
                L::CreatedAt,
            ])
            .values_panic([
                user_id.into(),
                entry.kind.into(),
                data.into(),
                entry.comment.into(),
                entry.is_comment.into(),
                entry.is_system.into(),
                actor_kind.into(),
                actor_id.into(),
                now().into(),
            ]);
        insert.to_owned()
    };
    Ok(insert_returning_id(db, insert, L::Id).await?)
}

/// The newest `limit` lines of a user's log.
pub async fn list_log(db: &Db, user_id: i64, limit: u64) -> CoreResult<Vec<LogEntry>> {
    let (sql, values) = build(
        db.backend,
        Query::select()
            .columns([
                L::Id,
                L::UserId,
                L::Kind,
                L::Data,
                L::Comment,
                L::IsComment,
                L::IsSystem,
                L::ActorKind,
                L::ActorId,
                L::CreatedAt,
            ])
            .from(L::Table)
            .and_where(Expr::col(L::UserId).eq(user_id))
            .order_by(L::Id, Order::Desc)
            .limit(limit)
            .to_owned(),
    );
    let rows = bind_values(sqlx::query(&sql), values)
        .fetch_all(&db.pool)
        .await?;
    Ok(rows
        .iter()
        .map(log_from_row)
        .collect::<Result<Vec<_>, _>>()?)
}

/// Moves every log line of `from` onto `into` (a merge).
pub async fn reassign_log(db: &Db, from: i64, into: i64) -> CoreResult<()> {
    let (sql, values) = build(
        db.backend,
        Query::update()
            .table(L::Table)
            .value(L::UserId, Expr::val(into))
            .and_where(Expr::col(L::UserId).eq(from))
            .to_owned(),
    );
    bind_values(sqlx::query(&sql), values)
        .execute(&db.pool)
        .await?;
    Ok(())
}

// --- reset tokens ------------------------------------------------------

/// A stored reset row.
#[derive(Debug, Clone)]
pub struct ResetRow {
    pub id: i64,
    pub user_id: i64,
    pub channel: String,
    pub expires_at: String,
    pub used_at: Option<String>,
}

pub async fn insert_reset(
    db: &Db,
    user_id: i64,
    channel: &str,
    token_hash: &str,
    expires_at: &str,
) -> CoreResult<i64> {
    let insert = {
        let mut insert = Query::insert();
        insert
            .into_table(R::Table)
            .columns([
                R::UserId,
                R::Channel,
                R::TokenHash,
                R::ExpiresAt,
                R::CreatedAt,
            ])
            .values_panic([
                user_id.into(),
                channel.into(),
                token_hash.into(),
                expires_at.into(),
                now().into(),
            ]);
        insert.to_owned()
    };
    Ok(insert_returning_id(db, insert, R::Id).await?)
}

pub async fn find_reset(db: &Db, token_hash: &str) -> CoreResult<Option<ResetRow>> {
    let (sql, values) = build(
        db.backend,
        Query::select()
            .columns([R::Id, R::UserId, R::Channel, R::ExpiresAt, R::UsedAt])
            .from(R::Table)
            .and_where(Expr::col(R::TokenHash).eq(token_hash))
            .to_owned(),
    );
    let row = bind_values(sqlx::query(&sql), values)
        .fetch_optional(&db.pool)
        .await?;
    let Some(r) = row else {
        return Ok(None);
    };
    Ok(Some(ResetRow {
        id: r.get_int("id")?,
        user_id: r.get_int("user_id")?,
        channel: r.get_text("channel")?,
        expires_at: r.get_text("expires_at")?,
        used_at: r.get_text_opt("used_at")?,
    }))
}

pub async fn mark_reset_used(db: &Db, id: i64) -> CoreResult<()> {
    let (sql, values) = build(
        db.backend,
        Query::update()
            .table(R::Table)
            .value(R::UsedAt, Expr::val(now()))
            .and_where(Expr::col(R::Id).eq(id))
            .to_owned(),
    );
    bind_values(sqlx::query(&sql), values)
        .execute(&db.pool)
        .await?;
    Ok(())
}

/// Drops every outstanding reset of a user (after a successful reset or a
/// password change).
pub async fn purge_resets(db: &Db, user_id: i64) -> CoreResult<()> {
    let (sql, values) = build(
        db.backend,
        Query::delete()
            .from_table(R::Table)
            .and_where(Expr::col(R::UserId).eq(user_id))
            .to_owned(),
    );
    bind_values(sqlx::query(&sql), values)
        .execute(&db.pool)
        .await?;
    Ok(())
}
