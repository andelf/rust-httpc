#[feature(globs)];

extern crate http;

use http::*;


fn dump_result(req: &Request, resp: &Response) {
    println!("\n======================= request result =======================");
    for (k, vs) in req.headers.iter() {
        println!("H {:?} => {:?}", k, vs)
    }

    println!("======================= response result =======================");
    println!("status = {} reason = {}", resp.status, resp.reason);
    for (k, vs) in resp.headers.iter() {
        println!("H {:?} => {:?}", k, vs)
    }
}


fn main() {
    let url : Url = from_str("http://www.baidu.com").unwrap();
    let mut req = Request::with_url(&url);

    //req.add_header("Accept-Encoding", "gzip,deflate");
    //req.method = POST;
    //req.add_header("user-agent", "Mozilla/5.0");

    let mut opener = build_opener();
    let mut resp = opener.open(&mut req).unwrap();

    dump_result(&req, &resp);


    let url : Url = from_str("http://video.baidu.com/").unwrap();
    let mut req = Request::with_url(&url);
    let mut resp = opener.open(&mut req).unwrap();

    dump_result(&req, &resp);

    assert!(resp.read_to_end().is_ok());
}
