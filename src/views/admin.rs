use loco_rs::prelude::*;

pub fn login(v: impl ViewRenderer) -> Result<impl IntoResponse> {
    format::render().view(&v, "admin/login.html", data!({}))
}
