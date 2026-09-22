//! PCAP download endpoints.
//!
//! TODO v0.2: implement position-based extraction from
//! `{PCAP_DIR}/YYYY-MM-DD/HH/MM/{TYPE}/{TYPE}_{...}.tar.zst` using the
//! `cdr_tar_part` table. For now these are stubs that return 501 so the
//! rest of the app can be exercised.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::{auth::session::SessionUser, error::AppResult, state::AppState};

pub async fn download_single(
    State(_state): State<AppState>,
    _user: SessionUser,
    Path(cdr_id): Path<u64>,
) -> AppResult<Response> {
    Ok((
        StatusCode::NOT_IMPLEMENTED,
        format!("PCAP download for CDR {cdr_id} not implemented yet (v0.2)"),
    )
        .into_response())
}

pub async fn download_batch(
    State(_state): State<AppState>,
    _user: SessionUser,
) -> AppResult<Response> {
    Ok((
        StatusCode::NOT_IMPLEMENTED,
        "Batch PCAP download not implemented yet (v0.2)",
    )
        .into_response())
}
