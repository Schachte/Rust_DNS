type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;

pub mod packet;
pub mod header;
pub mod question;
pub mod record;
pub mod query;
pub mod result;

