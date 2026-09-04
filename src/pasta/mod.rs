//! PASTA (CCS 2018) 方式の分散 IdP の PoC。
//!
//! 詳細は `docs/status.md`（全体像）と `docs/implementation.md`（実装解説）を参照。
//!
//! ⚠️ 教育・議論用の実装。監査を受けていないので本番で使ってはいけない。

pub mod jwt;
pub mod protocol;
pub mod shamir;
pub mod toprf;
pub mod tsign;
