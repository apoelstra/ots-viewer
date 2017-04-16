// OpenTimestamps Viewer
// Written in 2017 by
//   Andrew Poelstra <rust-ots@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Multipart Stream
//!
//! Shim to allow streaming of multipart data
//!

use std::io::Read;

use multipart::server::{Multipart, MultipartData, ReadEntryResult};
use rocket::{Request, Data, Outcome};
use rocket::data::{self, FromData};
use rocket::http::Status;

const SIZE_LIMIT: u64 = 32768;

/// A wrapper around a multipart stream
pub struct MultipartStream {
    pub stream: Box<Read>
}

impl FromData for MultipartStream {
    type Error = &'static str;

    fn from_data(request: &Request, data: Data) -> data::Outcome<Self, Self::Error> {
        let ct = match request.headers().get_one("Content-Type") {
            Some(ct) => ct,
            None => { return Outcome::Failure((Status::BadRequest, "no Content-Type in request")); }
        };
        let idx = match ct.find("boundary=") {
            Some(idx) => idx,
            None => { return Outcome::Failure((Status::BadRequest, "no boundary= in Content-Type")); }
        };
        let boundary = &ct[(idx + "boundary=".len())..];

        let mp = Multipart::with_body(data.open(), boundary);
        if let ReadEntryResult::Entry(entry) = mp.into_entry() {
            if entry.name == "file" {
                if let MultipartData::File(file) = entry.data {
                    Outcome::Success(MultipartStream {
                        stream: Box::new(file.take(SIZE_LIMIT))
                    })
                } else {
                    Outcome::Failure((Status::BadRequest, "malformed multipart data"))
                }
            } else {
                Outcome::Failure((Status::BadRequest, "malformed multipart data"))
            }
        } else {
            Outcome::Failure((Status::BadRequest, "missing multipart data"))
        }
    }
}


