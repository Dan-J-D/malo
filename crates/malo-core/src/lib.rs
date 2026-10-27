//! Malo core: crypto, IMAP, index, storage, backup, integrity checks, purge and the safe viewer.
//! No HTTP or GUI code lives here.

pub mod compose;
pub mod compress;
pub mod config;
pub mod crypto;
pub mod ctx;
pub mod export;
pub mod faults;
pub mod imap;
pub mod index;
pub mod layout;
pub mod lines;
pub mod mailview;
pub mod mime;
pub mod netguard;
pub mod oauth;
pub mod objectlock;
pub mod purge;
pub mod ratelimit;
pub mod rebuild;
pub mod restore;
pub mod search;
pub mod smtp;
pub mod spam;
pub mod store;
pub mod sync;
pub mod tls;
pub mod verify;
pub mod viewer;
pub mod zipstream;
