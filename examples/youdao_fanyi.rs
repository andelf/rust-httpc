// API key：1844139492
// keyfrom：neup204

#![feature(globs, macro_rules)]

extern crate httpc;
extern crate time;
extern crate serialize;

use std::os;
use serialize::{json, Encodable, Decodable};
use httpc::*;



macro_rules! nslog {
    ($($msg:tt)*) => (
        println!("[{}]: {}", time::now().rfc822(), format!($($msg)*))
    )
}

// FIXME: how to implement optional field
#[deriving(Decodable, Encodable)]
pub struct YoudaoBasic {
//    phonetic: Option<~str>,
    explains: ~[~str],
}

#[deriving(Decodable, Encodable)]
pub struct YoudaoWeb {
    key: ~str,
    value: ~[~str],
}

#[deriving(Decodable, Encodable)]
pub struct Youdao {
    errorCode: int,
    query: ~str,
    translation: ~[~str],
    basic: YoudaoBasic,
    web: ~[YoudaoWeb],
}


fn main() {
    let args = os::args().slice_from(1).into_owned();
    if args.len() != 1 {
        fail!("useage: {:?} word", os::self_exe_name().unwrap())
    }
    let word = args[0];
    let params = vec!((~"keyfrom", ~"neup204"), (~"key", ~"1844139492"),
                      (~"type", ~"data"), (~"doctype", ~"json"),
                      (~"version", ~"1.1"), (~"q", word.into_owned()));
    let mut url : Url = from_str("http://fanyi.youdao.com/openapi.do").unwrap();
    url.query = params;
    nslog!("url = {}", url.to_str());
    let mut req = Request::with_url(&url);

    let mut opener = build_opener();
    let mut resp = opener.open(&mut req).unwrap();

    nslog!("http ret code={}", resp.status);
    let json_obj = json::from_reader(&mut resp).unwrap();
    //nslog!("json obj={:?}", json_obj.to_str());
    let obj : Youdao = match Decodable::decode(&mut json::Decoder::new(json_obj)) {
        Ok(v) => v,
        Err(e) => fail!("error while decoding {}", e)
    };
    //nslog!("obj={:?}", obj);
    nslog!("code={}", obj.errorCode);
    nslog!("translation => {}", obj.translation.connect("; "));
    nslog!("[BASIC] => {}", obj.basic.explains.connect("; "));
    for item in obj.web.iter() {
        nslog!("[WEB] {} => {}", item.key, item.value.connect("; "));
    }
}
