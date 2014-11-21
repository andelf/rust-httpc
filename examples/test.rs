#![feature(globs)]
#![allow(unused_mut)]
#![feature(phase)]

#[phase(plugin, link)] extern crate log;
extern crate httpc;
extern crate test;
use test::Bencher;
use httpc::*;
use httpc::compress::*;


fn dump_result(req: &Request, resp: &Response) {
    println!("\n======================= request result =======================");
    for (k, vs) in req.headers.iter() {
        println!("H {:} => {}", k, vs)
    }

    println!("======================= response result =======================");
    println!("status = {} reason = {}", resp.status, resp.reason);
    for (k, vs) in resp.headers.iter() {
        println!("H {:} => {}", k, vs)
    }
}

#[bench]
fn bench_http_request_get_baidu(b: &mut Bencher) {
    let url : Url = Url::parse("http://www.baidu.com").unwrap();
    let mut req = Request::with_url(&url);

    let mut opener = build_opener();

    b.iter(|| {
            let mut resp = opener.open(&mut req).unwrap();
            assert!(resp.get_headers("set-cookie").len() > 0);
            assert!(resp.read_to_end().is_ok());
        });
}

#[test]
fn test_http_get() {
    let url : Url = Url::parse("http://httpbin.org/get?test=250").unwrap();
    let mut req = Request::with_url(&url);
    let mut opener = build_opener();
    let mut resp = opener.open(&mut req).unwrap();
    assert!(resp.read_to_string().unwrap().as_slice().contains("test=250"));
}

#[test]
fn test_http_user_agent() {
    let url : Url = Url::parse("http://httpbin.org/user-agent").unwrap();
    let mut req = Request::with_url(&url);
    let mut opener = build_opener();
    let mut resp = opener.open(&mut req).unwrap();
    assert!(resp.read_to_string().unwrap().as_slice().contains("Rust-httpc"));
}

#[test]
fn test_http_response_reader_eof() {
    let url : Url = Url::parse("http://www.baidu.com").unwrap();
    let mut req = Request::with_url(&url);
    let mut opener = build_opener();
    let mut resp = opener.open(&mut req).unwrap();
    assert!(resp.read_to_end().is_ok());
    assert_eq!(resp.read_to_end().unwrap(), vec!());
}


#[test]
fn test_cookie_processor() {
    let url : Url = Url::parse("http://www.baidu.com").unwrap();
    let mut req = Request::with_url(&url);

    let mut opener = build_opener();
    let mut resp = opener.open(&mut req).unwrap();

    assert!(resp.read_to_end().is_ok());
    assert!(resp.get_headers("set-cookie").len() > 0);

    let url : Url = Url::parse("http://tieba.baidu.com/").unwrap();
    let mut req = Request::with_url(&url);
    let mut resp = opener.open(&mut req).unwrap();

    assert!(req.get_headers("cookie").len() > 0);

    assert!(resp.read_to_end().is_ok());
}



#[test]
fn test_content_encoding_gzip() {
    // let url = Url::parse("http://www.vervestudios.co/projects/compression-tests/static/js/test-libs/jquery.min.js?d=1394076086888&format=gzip").unwrap();
    let url = Url::parse("http://www.baidu.com/").unwrap();
    let mut req = Request::with_url(&url);
    req.add_header("Accept-Encoding", "gzip,deflate");
    let mut opener = build_opener();
    let resp = opener.open(&mut req).unwrap();

    dump_result(&req, &resp);
    assert!(resp.get_headers("Content-Encoding")[0].as_slice().contains("gzip"));

    let mut r = GzipReader::new(resp);
    let ret = r.read_to_string();
    assert!(ret.unwrap().as_slice().contains("</html>")); // find tail
}

/* the site is un-accessable

#[test]
fn test_content_encoding_deflate_zlib() {
    let url = Url::parse("http://www.vervestudios.co/projects/compression-tests/static/js/test-libs/jquery.min.js?d=1394076086888&format=zlib").unwrap();
    let mut req = Request::with_url(&url);
    req.add_header("Accept-Encoding", "gzip,deflate");
    let mut opener = build_opener();
    let resp = opener.open(&mut req).unwrap();

    assert!(resp.get_headers("Content-Encoding").get(0).contains("deflate"));

    dump_result(&req, &resp);
    let mut r = GzipReader::new(resp);
    let ret = r.read_to_str();
    assert!(ret.unwrap().contains("jQuery JavaScript"));
}

*/

#[test]
fn test_cookie_parse() {
    let url = Url::parse("http://www.baidu.com/").unwrap();
    let mut req = Request::with_url(&url);

    let mut opener = build_opener();
    let mut resp = opener.open(&mut req).unwrap();

    let mut cj = CookieJar::new();
    dump_result(&req, &resp);
    for set_ck in resp.get_headers("set-cookie").iter() {
        let ck_opt = from_str::<Cookie>(set_ck.as_slice());
        assert!(ck_opt.is_some());
        let ck = ck_opt.unwrap();

        //println!("got cookie => {:}", ck);
        info!("expired => {:}", ck.is_expired());
        println!("header req => {:}", ck.to_header());
        //println!("header_str => {:}", ck.to_str());
        cj.set_cookie_if_ok(ck, &req);
    }
    assert!(cj.cookies_for_request(&req).len() > 0);
    // println!("CJ => {:}", cj);
    assert_eq!(resp.status, 200);
}

#[test]
fn test_http_post_request() {
    let url = Url::parse("http://httpbin.org/post").unwrap();
    let mut req = Request::with_url(&url);

    req.method = POST;
    req.add_body(b"kind=simple&type=title&word=erlang&match=mh&recordtype=01&library_id=all&x=40&y=10");

    let mut opener = build_opener();
    let mut resp = opener.open(&mut req).unwrap();

    dump_result(&req, &resp);
    // charset = gbk
    match resp.read_to_end() {
        Ok(content) => {
            for c in content.iter() {
                print!("{:}", *c as char);
            }
            println!("DEBUG read bytes=> {}", content.len());
        }
        Err(e) => {
            println!("! read error: {:}", e);
        }
    }
    assert_eq!(resp.status, 200);
}

#[test]
fn test_http_options_request() {
    let url = Url::parse("http://www.w3.org").unwrap();
    let mut req = Request::with_url(&url);
    req.method = OPTIONS;

    let mut opener = build_opener();
    let mut resp = opener.open(&mut req).unwrap();

    assert_eq!(resp.status, 200);
    assert!(resp.get_headers("Allow").len() > 0);
}

#[test]
fn test_http_head_request() {
    let url = Url::parse("http://www.w3.org").unwrap();
    let mut req = Request::with_url(&url);
    req.method = HEAD;

    let mut opener = build_opener();
    let mut resp = opener.open(&mut req).unwrap();

    // println!("resp => {:}", resp);

    println!("resp.read_to_end() => {:}", resp.read_to_end());
    assert_eq!(resp.read_to_end().unwrap().len(), 0);
    assert_eq!(resp.status, 200);
}

#[test]
fn test_weather_sug() {
    let url : Url = Url::parse("http://toy1.weather.com.cn/search?cityname=yulin&_=2").unwrap();

    let mut req = Request::with_url(&url);
    req.set_header("Referer", "http://www.weather.com.cn/");

    let mut opener = build_opener();
    let mut resp = opener.open(&mut req).unwrap();

    let content = match resp.read_to_string() {
        Ok(content) => {
            content
        }
        Err(_) =>
            "".to_string()
    };
    assert!(content.len() > 10);
    assert!(resp.status == 200);
}

#[test]
fn test_http_redirect_response_yahoo() {
    let url = Url::parse("http://www.yahoo.com.cn").unwrap();
    let mut req = Request::with_url(&url);

    let mut opener = build_opener();
    let mut resp = opener.open(&mut req).unwrap();

    // assert_eq!(resp.status, 301);
    assert!(resp.read_to_end().is_ok());
}

fn main() {

}
