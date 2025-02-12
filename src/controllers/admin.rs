#![allow(clippy::missing_errors_doc)]
#![allow(clippy::unnecessary_struct_initialization)]
#![allow(clippy::unused_async)]
use crate::{
    models::{
        _entities::users,
        users::{users::Column, Entity, LoginParams, Model, RegisterParams},
    },
    views,
    views::auth::LoginResponse,
};
use axum::debug_handler;
use loco_rs::prelude::*;
use sea_orm::{sea_query::Order, QueryOrder};

async fn load_item(ctx: &AppContext, id: i32) -> Result<Model> {
    let item = Entity::find_by_id(id).one(&ctx.db).await?;
    item.ok_or_else(|| Error::NotFound)
}

#[debug_handler]
pub async fn login(ViewEngine(v): ViewEngine<TeraView>) -> Result<impl IntoResponse> {
    views::admin::login(&v)
}

/// login submit
///
/// # Errors
/// returns auth error
#[debug_handler]
pub async fn login_submit(
    State(ctx): State<AppContext>,
    Json(params): Json<LoginParams>,
) -> Result<Response> {
    let user = users::Model::find_by_email(&ctx.db, &params.email).await;

    let Ok(user) = user else {
        return unauthorized("unauthorized!"); // todo
                                              // return Ok(axum::response::Json("Invalid user.").into_response());
    };

    let valid = user.verify_password(&params.password);

    if !valid {
        return unauthorized("unauthorized!"); // todo
                                              // return Ok(axum::response::Json("Invalid email or password.").into_response());
    }

    let jwt_secret = ctx.config.get_jwt_config()?;

    let token = user
        .generate_jwt(&jwt_secret.secret, &jwt_secret.expiration)
        .or_else(|_| unauthorized("unauthorized!"))?;

    // todo
    // format::redirect("/members")
    format::json(LoginResponse::new(&user, &token))
}

#[debug_handler]
pub async fn list(
    ViewEngine(v): ViewEngine<TeraView>,
    State(ctx): State<AppContext>,
) -> Result<Response> {
    let item = Entity::find()
        .order_by(Column::Id, Order::Desc)
        .all(&ctx.db)
        .await?;
    views::admin::list(&v, &item)
}

#[debug_handler]
pub async fn show(
    Path(id): Path<i32>,
    ViewEngine(v): ViewEngine<TeraView>,
    State(ctx): State<AppContext>,
) -> Result<Response> {
    let item = load_item(&ctx, id).await?;
    views::admin::show(&v, &item)
}

#[debug_handler]
pub async fn register(
    ViewEngine(v): ViewEngine<TeraView>,
    State(_ctx): State<AppContext>,
) -> Result<Response> {
    views::admin::register(&v)
}

#[debug_handler]
pub async fn register_submit(
    ViewEngine(v): ViewEngine<TeraView>,
    State(ctx): State<AppContext>,
    Json(params): Json<RegisterParams>,
) -> Result<Response> {
    let res = users::Model::create_with_password(&ctx.db, &params).await;

    let user = match res {
        Ok(user) => user,
        Err(err) => {
            tracing::info!(
                message = err.to_string(),
                user_email = &params.email,
                "could not register user",
            );
            return format::json(());
        }
    };

    let user = user
        .into_active_model()
        .set_email_verification_sent(&ctx.db)
        .await?;

    views::admin::show(&v, &user)
}

#[debug_handler]
pub async fn dashboard(
    _auth: auth::JWT, 
    ViewEngine(v): ViewEngine<TeraView>,
    State(_ctx): State<AppContext>,
) -> Result<Response> {
    views::admin::dashboard(&v)
}

pub fn routes() -> Routes {
    Routes::new()
        .prefix("/")
        .add("", get(login))
        .add("", post(login_submit))
        .add("list", get(list))
        .add("show", get(show))
        .add("register", get(register))
        .add("register", post(register_submit))
        .add("dashboard", get(dashboard))
}
