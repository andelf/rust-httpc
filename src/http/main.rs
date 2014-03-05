#[feature(globs)];
#[allow(unused_mut)];

extern crate http;

use std::str;
use http::*;

use compress::uncompress;

mod compress;
mod zlib;


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
    //let u = ~"http://flash.weather.com.cn/sk2/101010100.xml";
    //let u = ~"http://zx.bjmemc.com.cn/ashx/Data.ashx?Action=GetAQIClose1h";
    //let u = "http://www.gpsspg.com/ajax/latlng_office_maps.aspx?lat=39.91433268343&lng=116.46717705386&type=1";
    //req.add_header("Referer", "http://www.gpsspg.com/apps/maps/google_131201.htm");
    let u = "http://www.baidu.com";
    let url : Url = from_str(u).unwrap();
    let mut req = Request::new_with_url(&url);

    req.add_header("Accept-Encoding", "gzip,deflate,sdch");
    //req.method = POST;

    //req.add_header("user-agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3");

    let mut h = HTTPHandler { debug: true };
    let mut resp = h.handle(&mut req).unwrap();

    dump_result(&req, &resp);

    println!("get_headers = {:?}", resp.get_headers("set-cookie"));
    let mut gzreader = compress::GzipReader::new(resp);
    println!("unzip => {:?}",  gzreader.read_to_str());

/*    match resp.read_to_end() {
        Ok(content) => {
            let ret = compress::uncompress(content).unwrap();
            println!("uncompress => {:?}", str::from_utf8(ret.slice_to(1000)));
            // for c in content.iter() {
            //     print!("{:c}", *c as char);
            // }
            println!("DEBUG read bytes=> {}", content.len());
        }
        Err(e) => {
            println!("! read error: {:?}", e);
        }
    }*/

}
