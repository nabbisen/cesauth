use crate::models::_entities::users;
use loco_rs::prelude::*;

pub fn login(v: impl ViewRenderer) -> Result<impl IntoResponse> {
    format::render().view(&v, "admin/login.html", data!({}))
}

// todo: remove ?
pub fn list(v: &impl ViewRenderer, items: &Vec<users::Model>) -> Result<Response> {
    format::render().view(v, "admin/list.html", data!({"items": items}))
}

// todo: remove ?
pub fn show(v: &impl ViewRenderer, item: &users::Model) -> Result<Response> {
    format::render().view(v, "admin/show.html", data!({"item": item}))
}

// todo: remove ?
pub fn register(v: &impl ViewRenderer) -> Result<Response> {
    format::render().view(v, "admin/register.html", data!({}))
}
