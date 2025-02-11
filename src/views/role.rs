use loco_rs::prelude::*;

use crate::models::_entities::roles;

/// Render a list view of `roles`.
///
/// # Errors
///
/// When there is an issue with rendering the view.
pub fn list(v: &impl ViewRenderer, items: &Vec<roles::Model>) -> Result<Response> {
    format::render().view(v, "role/list.html", data!({"items": items}))
}

/// Render a single `role` view.
///
/// # Errors
///
/// When there is an issue with rendering the view.
pub fn show(v: &impl ViewRenderer, item: &roles::Model) -> Result<Response> {
    format::render().view(v, "role/show.html", data!({"item": item}))
}

/// Render a `role` create form.
///
/// # Errors
///
/// When there is an issue with rendering the view.
pub fn create(v: &impl ViewRenderer) -> Result<Response> {
    format::render().view(v, "role/create.html", data!({}))
}

/// Render a `role` edit form.
///
/// # Errors
///
/// When there is an issue with rendering the view.
pub fn edit(v: &impl ViewRenderer, item: &roles::Model) -> Result<Response> {
    format::render().view(v, "role/edit.html", data!({"item": item}))
}
