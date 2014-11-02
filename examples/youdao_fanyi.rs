// API key：1844139492
// keyfrom：neup204

#![feature(globs, macro_rules)]

extern crate httpc;
extern crate time;
extern crate serialize;

use std::os;
use serialize::{json, Encodable, Decodable};
use httpc::*;
use std::iter::Iterator;


macro_rules! nslog {
    ($($msg:tt)*) => (
        println!("[{}]: {}", time::now().rfc822(), format!($($msg)*))
    )
}

// FIXME: how to implement optional field
#[deriving(Decodable, Encodable)]
pub struct YoudaoBasic {
//    phonetic: Option<String>,
    explains: Vec<String>,
}

#[deriving(Decodable, Encodable)]
pub struct YoudaoWeb {
    key: String,
    value: Vec<String>,
}

#[allow(non_snake_case)]
#[deriving(Decodable, Encodable)]
pub struct Youdao {
    errorCode: int,
    query: String,
    translation: Vec<String>,
    basic: YoudaoBasic,
    web: Vec<YoudaoWeb>,
}


fn main() {
    let args = os::args().slice_from(1).to_vec();
    if args.len() != 1 {
        panic!("useage: {:} word", os::self_exe_name().unwrap().display())
    }
    let word = args[0].clone();
    let params = vec![("keyfrom", "neup204"), ("key", "1844139492"),
                      ("type", "data"), ("doctype", "json"),
                      ("version", "1.1"), ("q", word.as_slice())];
    let mut url : Url = Url::parse("http://fanyi.youdao.com/openapi.do").unwrap();
    url.set_query_from_pairs(params.iter().map(|&(k, v)| (k,v)));
    nslog!("url = {}", url.to_string());
    let mut req = Request::with_url(&url);

    let mut opener = build_opener();
    let mut resp = opener.open(&mut req).unwrap();

    nslog!("http ret code={}", resp.status);
    let json_obj = json::from_reader(&mut resp).unwrap();
    //nslog!("json obj={:}", json_obj.to_str());
    let obj : Youdao = match Decodable::decode(&mut json::Decoder::new(json_obj)) {
        Ok(v) => v,
        Err(e) => panic!("error while decoding {}", e)
    };
    //nslog!("obj={}", obj);
    nslog!("code={}", obj.errorCode);
    nslog!("translation => {}", obj.translation.connect("; "));
    nslog!("[BASIC] => {}", obj.basic.explains.connect("; "));
    for item in obj.web.iter() {
        nslog!("[WEB] {} => {}", item.key, item.value.connect("; "));
    }
}
