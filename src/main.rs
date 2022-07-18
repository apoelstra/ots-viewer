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

//! # OpenTimestamps Viewer
//!
//! HTTP server which provides a pretty view of .ots files
//!

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]

#![feature(decl_macro)]

extern crate bitcoin;
extern crate crypto;
extern crate rocket_multipart_form_data;
extern crate opentimestamps as ots;
extern crate rocket_contrib;
#[macro_use] extern crate rocket;
#[macro_use] extern crate serde;

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::network::serialize::{deserialize, BitcoinHash};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use rocket_multipart_form_data::{MultipartFormDataOptions, MultipartFormData, MultipartFormDataField};
use ots::attestation::Attestation;
use ots::timestamp::{Step, StepData};
use ots::op::Op;
use ots::hex::Hexed;
use rocket::Data;
use rocket::http::ContentType;
use rocket::response::content;
use rocket::response::{Redirect, NamedFile};
use rocket_contrib::templates::Template;

#[derive(Debug, Serialize)]
struct DisplayedStep {
    prefix: String,
    result: String,
    reason: String,
    class: &'static str
}

#[derive(Debug, Serialize)]
struct DisplayedTimestamp {
    id: String,
    title: String,
    start_hash: String,
    digest_type: String,
    steps: Vec<DisplayedStep>
}

fn render_steps(step: &Step, vec: &mut Vec<DisplayedStep>, prev_data: &[u8], prefix: String) {
    match step.data {
        StepData::Fork => {
            vec.push(DisplayedStep {
                prefix: prefix.clone(),
                result: format!("Fork into <b>{}</b> paths", step.next.len()),
                reason: "Fork".to_owned(),
                class: "step_fork"
            });
            for (n, next) in step.next.iter().enumerate() {
                let new_prefix = if prefix.is_empty() {
                    format!("{} ", n + 1)
                } else {
                    format!("{}- {} ", prefix, n + 1)
                };
                render_steps(next, vec, prev_data, new_prefix);
            }
        }
        StepData::Op(ref op) => {
            match *op {
                Op::Sha1 | Op::Sha256 | Op::Ripemd160 |
                Op::Reverse | Op::Hexlify => {
                    vec.push(DisplayedStep {
                        prefix: prefix.clone(),
                        result: format!("<tt>{}</tt>", Hexed(&step.output)),
                        reason: format!("{}", op),
                        class: "step_op"
                    });
                }
                Op::Append(ref newdata) => {
                    vec.push(DisplayedStep {
                        prefix: prefix.clone(),
                        result: format!("<tt>{}<font color=\"green\">{}</font></tt>", Hexed(prev_data), Hexed(newdata)),
                        reason: format!("Append({}...)", Hexed(&newdata[0..3])),
                        class: "step_op"
                    });
                    // Notice valid bitcoin transactions
                    if let Ok(tx) = deserialize::<Transaction>(&step.output) {
                        vec.push(DisplayedStep {
                            prefix: prefix.clone(),
                            result: format!("Bitcoin transaction <b>{}</b>", tx.bitcoin_hash()),
                            reason: "(Parse TX)".to_owned(),
                            class: "step_parse"
                        });
                    }
                }
                Op::Prepend(ref newdata) => {
                    vec.push(DisplayedStep {
                        prefix: prefix.clone(),
                        result: format!("<tt><font color=\"green\">{}</font>{}</tt>", Hexed(newdata), Hexed(prev_data)),
                        reason: format!("Prepend({}...)", Hexed(&newdata[0..3])),
                        class: "step_op"
                    });
                }
            };
            render_steps(&step.next[0], vec, &step.output, prefix);
        }
        StepData::Attestation(ref attest) => {
            let result = match *attest {
                Attestation::Unknown { ref tag, ref data } => format!("Unknown attestation <b>{}</b>/<b>{}</b>", Hexed(tag), Hexed(data)),
                Attestation::Pending { ref uri } => format!("Pending attestation: server <b>{}</b>", uri),
                Attestation::Bitcoin { height } => {
                    let root: Vec<u8> = prev_data.iter().rev().map(|x| *x).collect();
                    format!("Merkle root <b>{}</b> of Bitcoin block <b>{}</b>", Hexed(&root), height)
                }
            };
            vec.push(DisplayedStep {
                prefix: prefix.clone(),
                result: result,
                reason: "Attestation".to_owned(),
                class: "step_attest"
            });
        }
    }
}

// File viewer
#[get("/view/<file..>")]
fn view(file: PathBuf) -> Template {
    match fs::File::open(Path::new("cache/").join(file)) {
        Ok(fh) => {
            match ots::DetachedTimestampFile::from_reader(fh) {
                Ok(dtf) => {
                    let mut steps = vec![];
                    render_steps(&dtf.timestamp.first_step, &mut steps, &dtf.timestamp.start_digest, "".to_string());
                    let display = DisplayedTimestamp {
                        id: doc_id(&dtf),
                        title: format!("Timestamp of <tt>{:?}</tt>", Hexed(&dtf.timestamp.start_digest[0..6])),
                        start_hash: format!("{}", Hexed(&dtf.timestamp.start_digest)),
                        digest_type: format!("{}", dtf.digest_type),
                        steps: steps
                    };
                    Template::render("entry", &display)
                }
                Err(e) => {
                    let mut context = HashMap::new();
                    context.insert("title", "View Timestamp".to_owned());
                    context.insert("error", format!("{}", e));
                    Template::render("error", &context)
                }
            }
        }
        Err(e) => {
            let mut context = HashMap::new();
            context.insert("title", "View Timestamp".to_owned());
            context.insert("error", format!("{}", e));
            Template::render("error", &context)
        }
    }
}

// Download
#[get("/download/<file..>")]
fn download(file: PathBuf) -> Option<content::Content<NamedFile>> {
    let octet_stream: ContentType = ContentType::new("application", "octet-stream");
    if let Ok(nf) = NamedFile::open(Path::new("cache/").join(file)) {
        Some(content::Content(octet_stream, nf))
    } else {
        None
    }
}


fn doc_id_hash_recurse(step: &Step, hasher: &mut Sha256) {
    hasher.input(&step.output);
    for next in step.next.iter() {
        doc_id_hash_recurse(next, hasher);
    }
}

/// Compute a unique filename for this timestamp
fn doc_id(dtf: &ots::DetachedTimestampFile) -> String {
    let mut output = [0; 32];
    let mut hasher = Sha256::new();
    hasher.input(&dtf.timestamp.start_digest);
    doc_id_hash_recurse(&dtf.timestamp.first_step, &mut hasher);
    hasher.result(&mut output);
    format!("{}", Hexed(&output))
}

// Upload handler
#[post("/upload", data="<ots>")]
fn upload(content_type: &ContentType, ots: Data) -> Redirect {
    let options = MultipartFormDataOptions::with_multipart_form_data_fields(
        vec![MultipartFormDataField::file("file")]
    );
    let multipart_form_data = MultipartFormData::parse(content_type, ots, options).unwrap();
    let filepath = match multipart_form_data.files.get("file") {
        Some(ref file) => &file[0].path,
        None => {
            println!("No file provided.");
            return Redirect::to("/");
        }
    };
    let fh = match fs::File::open(filepath) {
        Ok(fh) => fh,
        Err(e) => {
            println!("Failed to open uploaded file: {}", e);
            return Redirect::to("/");
        }
    };

    match ots::DetachedTimestampFile::from_reader(fh) {
        Ok(dtf) => {
            let id = doc_id(&dtf);
            match fs::File::create(Path::new("cache/").join(&id)) {
                Ok(fh) => {
                    if let Err(e) = dtf.to_writer(fh) {
                        println!("Filed to write timestamp: {}", e);
                        Redirect::to("/")
                    } else {
                        Redirect::to(format!("/view/{}", id))
                    }
                }
                Err(e) => {
                    println!("Filed to open {}: {}", id, e);
                    Redirect::to("/")
                }
            }
        }
        Err(e) => {
            // TODO somehow meaningfully show the error
            println!("Filed to parse timestamp: {}", e);
            Redirect::to("/")
        }
    }
}

// Generic static file handler
#[get("/<file..>", rank = 2)]
fn files(file: PathBuf) -> Option<NamedFile> {
    NamedFile::open(Path::new("static/").join(file)).ok()
}

// Index page
#[get("/")]
fn index() -> Template {
    let mut context = HashMap::new();
    context.insert("title", "OpenTimestamps Viewer");
    Template::render("index", &context)
}

fn main() {
    rocket::ignite()
        .attach(Template::fairing())
        .mount("/", routes![index, files, upload, download, view])
        .launch();
}

