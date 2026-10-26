//! Malo core: crypto, IMAP, index, storage, backup, integrity checks, purge and the safe viewer.
//! No HTTP or GUI code lives here.

pub mod config;
pub mod crypto;
pub mod ctx;
pub mod faults;
pub mod imap;
pub mod index;
pub mod layout;
pub mod mailview;
pub mod oauth;
pub mod purge;
pub mod rebuild;
pub mod search;
pub mod smtp;
pub mod store;
pub mod sync;
pub mod tls;
pub mod verify;
pub mod viewer;
