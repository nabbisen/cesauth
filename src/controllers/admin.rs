#![allow(clippy::missing_errors_doc)]
#![allow(clippy::unnecessary_struct_initialization)]
#![allow(clippy::unused_async)]
use crate::{
    models::{_entities::users, users::LoginParams},
    views,
};
use axum::debug_handler;
use loco_rs::prelude::*;

#[debug_handler]
pub async fn login(ViewEngine(v): ViewEngine<TeraView>) -> Result<impl IntoResponse> {
    views::admin::login(v)
}

#[debug_handler]
pub async fn login_submit(
    State(ctx): State<AppContext>,
    Json(params): Json<LoginParams>,
) -> Result<Response> {
    let user = users::Model::find_by_email(&ctx.db, &params.email).await;

    if user.is_err() {
        // return unauthorized("unauthorized!"); // todo
        return Ok(axum::response::Json("Invalid user.").into_response());
    }

    let user = user.unwrap();
    let valid = user.verify_password(&params.password);

    if !valid {
        // return unauthorized("unauthorized!"); // todo
        return Ok(axum::response::Json("Invalid email or password.").into_response());
    }

    let jwt_secret = ctx.config.get_jwt_config()?;

    let _token = user
        .generate_jwt(&jwt_secret.secret, &jwt_secret.expiration)
        .or_else(|_| unauthorized("unauthorized!"))?;

    // todo
    Ok(axum::response::Redirect::to("/members").into_response())
}

pub fn routes() -> Routes {
    Routes::new()
        .prefix("/")
        .add("/", get(login))
        .add("/", post(login_submit))
}
