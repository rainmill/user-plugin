# Rainmill User

A first-party [Laterite](https://github.com/lateritecmf/laterite) plugin: the
**users of your application**, as distinct from the operators who sign in to
the admin. Registration, activation (automatic, by code, or by operator
approval), password sign-in, password reset, bans, deactivation, soft and hard
deletion, guests and merging, groups, per-user preferences and an activity
log, with every change announced as an event under `user.`.

The admin gets a **Users** section with the Users and Groups screens and a
settings page (sign-in attribute, registration, activation, deletion policy,
guests, notifications). Mail templates for welcome, activation, invitation,
password reset, email verification and the operator notice are registered and
editable in Settings > Mail templates.

Signing users in is the job of the auth gateway; this plugin answers its
credential and lookup questions and records what happened in the user's log.

## Requirements

- Laterite 0.9 or later.
- Database: **any** (PostgreSQL, MySQL, or SQLite).

## Installation

```sh
lat plugin add https://github.com/rainmill/user-plugin
```

Or by hand:

```toml
[dependencies]
rainmill-user = "0.1"
```

```rust
laterite_admin::Bootstrap::new("config")
    .module(rainmill_user::UserModule)
    .serve()
    .await
```

Registration runs the plugin's migrations (the `rainmill_user*` tables) and
seeds the `registered` and `guest` groups.

## Usage

```rust
use rainmill_user::{Credential, NewUser, UserSettings, Users};

let settings = UserSettings::load(&db).await;
let users = Users::new(db.clone(), events.clone(), settings);

let registered = users
    .register(NewUser {
        email: Some("alice@acme.test".into()),
        password: Some("correct horse battery".into()),
        ..Default::default()
    })
    .await?;
// `registered.activation_code` is `Some` when the user must confirm a code.

let user = users
    .authenticate(&Credential {
        login: "alice@acme.test".into(),
        password: "correct horse battery".into(),
    })
    .await?;
```

| Setting | Default | Meaning |
|---|---|---|
| `login_attribute` | `email` | `email`, `username` or `phone` |
| `allow_registration` | on | registration open or closed |
| `activation` | `automatic` | `automatic`, `user` (confirm a code), `operator` (approve from the admin) |
| `block_persistence` | off | one session at a time |
| `soft_delete` | on | deleted users stay restorable |
| `guests` | off | allow guest users |
| `token_hours` | 24 | validity of activation codes and reset links |

## Events

`user.registered`, `user.activated`, `user.deactivated`, `user.updated`,
`user.banned`, `user.unbanned`, `user.merged`, `user.deleted`. A module that
owns records keyed by a user listens to `user.merged` to reassign them and
registers a `DeletePolicy` to keep a deletion soft.

## Development

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The test suite runs the migrations and the service on SQLite in memory;
set `LATERITE_TEST_DATABASE_URL` to run it on PostgreSQL or MySQL.

## License

MIT or Apache-2.0, at your option.
