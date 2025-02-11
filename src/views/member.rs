use loco_rs::prelude::*;

use crate::models::_entities::members;

/// Render a list view of `members`.
///
/// # Errors
///
/// When there is an issue with rendering the view.
pub fn list(v: &impl ViewRenderer, items: &Vec<members::Model>) -> Result<Response> {
    format::render().view(v, "member/list.html", data!({"items": items}))
}

/// Render a single `member` view.
///
/// # Errors
///
/// When there is an issue with rendering the view.
pub fn show(v: &impl ViewRenderer, item: &members::Model) -> Result<Response> {
    format::render().view(v, "member/show.html", data!({"item": item}))
}

/// Render a `member` create form.
///
/// # Errors
///
/// When there is an issue with rendering the view.
pub fn create(v: &impl ViewRenderer) -> Result<Response> {
    format::render().view(v, "member/create.html", data!({}))
}

/// Render a `member` edit form.
///
/// # Errors
///
/// When there is an issue with rendering the view.
pub fn edit(v: &impl ViewRenderer, item: &members::Model) -> Result<Response> {
    format::render().view(v, "member/edit.html", data!({"item": item}))
}
