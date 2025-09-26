use std::borrow::Cow;

use crate::config::DatabaseDriver;

pub fn rewrite_placeholders<'q>(sql: &'q str, driver: DatabaseDriver) -> Cow<'q, str> {
    if driver != DatabaseDriver::Postgres {
        return Cow::Borrowed(sql);
    }

    if !sql.contains('?') {
        return Cow::Borrowed(sql);
    }

    let mut result = String::with_capacity(sql.len());
    let mut index = 1;

    for ch in sql.chars() {
        if ch == '?' {
            result.push('$');
            result.push_str(&index.to_string());
            index += 1;
        } else {
            result.push(ch);
        }
    }

    Cow::Owned(result)
}
