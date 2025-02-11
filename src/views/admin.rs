use crate::models::_entities::users;
use loco_rs::prelude::*;

/// login
///
/// # Errors
/// returns auth error
pub fn login(v: &impl ViewRenderer) -> Result<impl IntoResponse> {
    format::render().view(v, "admin/login.html", data!({}))
}

// todo: remove ?
/// login list
///
/// # Errors
/// returns db select error
pub fn list(v: &impl ViewRenderer, items: &Vec<users::Model>) -> Result<Response> {
    format::render().view(v, "admin/list.html", data!({"items": items}))
}

// todo: remove ?
/// login list
///
/// # Errors
/// returns db select error
pub fn show(v: &impl ViewRenderer, item: &users::Model) -> Result<Response> {
    format::render().view(v, "admin/show.html", data!({"item": item}))
}

// todo: remove ?
/// login list
///
/// # Errors
/// returns db insert error
pub fn register(v: &impl ViewRenderer) -> Result<Response> {
    format::render().view(v, "admin/register.html", data!({}))
}
