//! PASTA (CCS 2018) 方式の分散 IdP の PoC。
//!
//! 詳細は `docs/prior-art.md` と `docs/design-discussion.md` を参照。
//!
//! ⚠️ 教育・議論用の実装。監査を受けていないので本番で使ってはいけない。

pub mod jwt;
pub mod protocol;
pub mod shamir;
pub mod toprf;
pub mod tsign;
