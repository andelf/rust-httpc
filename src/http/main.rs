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
    let url : Url = from_str("http://www.google.com").unwrap();
    let mut req = Request::new_with_url(&url);

    //req.add_header("Accept-Encoding", "gzip,deflate");
    //req.method = POST;
    //req.add_header("user-agent", "Mozilla/5.0");

    let mut opener = build_opener();
    let mut resp = opener.open(&mut req).unwrap();

    dump_result(&req, &resp);

    println!("got cookies = {:?}", resp.get_headers("set-cookie"));
    match resp.get_headers("Content-Encoding").head() {
        Some(&~"gzip") => {
            let mut gzreader = compress::GzipReader::new(resp);
            println!("unzip => {:?}",  gzreader.read_to_str());
        }
        Some(&~"deflate") => {
            let mut gzreader = compress::GzipReader::new(resp);
            println!("unzip => {:?}",  gzreader.read_to_str());
        }
        None => {
            println!("content => {:?}", resp.read_to_str());
        }
        _ => unreachable!()
    }
}
