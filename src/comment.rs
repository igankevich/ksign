use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Write;

use crate::Fingerprint;
use crate::COMMENT_PREFIX;

pub enum Comment<'a> {
    String(&'a str),
    Fingerprint(&'a str, Fingerprint),
}

impl<'a> Comment<'a> {
    pub(crate) fn write(&self, writer: &mut impl Write) -> Result<(), std::io::Error> {
        writeln!(writer, "{} {}", COMMENT_PREFIX, self)
    }
}

impl<'a> Display for Comment<'a> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Self::String(s) => f.write_str(s),
            Self::Fingerprint(s, fp) => write!(f, "{} {}", s, fp),
        }
    }
}
