#[feature(globs)];
#[allow(unused_mut)];

extern crate http;
extern crate test;

use test::BenchHarness;
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

#[bench]
fn bench_http_request_get_baidu(b: &mut BenchHarness) {
    let url : Url = from_str("http://www.baidu.com").unwrap();
    let mut req = Request::new_with_url(&url);

    let mut opener = build_opener();

    b.iter(|| {
            let mut resp = opener.open(&mut req).unwrap();
            assert!(resp.get_headers("set-cookie").len() > 0);
            assert!(resp.read_to_end().is_ok());
        });
}

#[test]
fn test_http_response_reader_eof() {
    let url : Url = from_str("http://www.baidu.com").unwrap();
    let mut req = Request::new_with_url(&url);
    let mut opener = build_opener();
    let mut resp = opener.open(&mut req).unwrap();
    assert!(resp.read_to_end().is_ok());
    assert!(resp.read_to_end().is_err());
}


#[test]
fn test_cookie_processor() {
    let url : Url = from_str("http://www.baidu.com").unwrap();
    let mut req = Request::new_with_url(&url);

    let mut opener = build_opener();
    let mut resp = opener.open(&mut req).unwrap();

    assert!(resp.read_to_end().is_ok());
    assert!(resp.get_headers("set-cookie").len() > 0);

    let url : Url = from_str("http://tieba.baidu.com/").unwrap();
    let mut req = Request::new_with_url(&url);
    let mut resp = opener.open(&mut req).unwrap();

    assert!(req.get_headers("cookie").len() > 0);

    assert!(resp.read_to_end().is_ok());
}




#[test]
fn test_content_encoding_gzip() {
    let url = from_str("http://www.vervestudios.co/projects/compression-tests/static/js/test-libs/jquery.min.js?d=1394076086888&format=gzip").unwrap();
    let mut req = Request::new_with_url(&url);
    req.add_header("Accept-Encoding", "gzip,deflate");
    let mut opener = build_opener();
    let resp = opener.open(&mut req).unwrap();

    assert!(resp.headers.get(&~"Content-Encoding").head().unwrap().contains("gzip"));

    dump_result(&req, &resp);
    let mut r = GzipReader::new(resp);
    let ret = r.read_to_str();
    assert!(ret.unwrap().contains("jQuery JavaScript"));

}

#[test]
fn test_content_encoding_deflate_zlib() {
    let url = from_str("http://www.vervestudios.co/projects/compression-tests/static/js/test-libs/jquery.min.js?d=1394076086888&format=zlib").unwrap();
    let mut req = Request::new_with_url(&url);
    req.add_header("Accept-Encoding", "gzip,deflate");
    let mut opener = build_opener();
    let resp = opener.open(&mut req).unwrap();

    assert!(resp.headers.get(&~"Content-Encoding").head().unwrap().contains("deflate"));

    dump_result(&req, &resp);
    let mut r = GzipReader::new(resp);
    let ret = r.read_to_str();
    assert!(ret.unwrap().contains("jQuery JavaScript"));
}

#[test]
fn test_cookie_parse() {
    let url = from_str("http://www.baidu.com/").unwrap();
    let mut req = Request::new_with_url(&url);

    let mut h = HTTPHandler { debug : true };
    let mut resp = h.handle(&mut req).unwrap();

    let mut cj = CookieJar::new();
    dump_result(&req, &resp);
    for set_ck in resp.headers.get(&to_header_case("set-cookie")).iter() {
        let ck_opt = from_str::<Cookie>(*set_ck);
        assert!(ck_opt.is_some());
        let ck = ck_opt.unwrap();

        //println!("got cookie => {:?}", ck);
        info!("expired => {:?}", ck.is_expired());
        println!("header req => {:?}", ck.to_header());
        //println!("header_str => {:?}", ck.to_str());
        cj.set_cookie_if_ok(ck, &req);
    }
    assert!(cj.cookies_for_request(&req).len() > 0);
    println!("CJ => {:?}", cj);
    assert_eq!(resp.status, 200);
}

#[test]
fn test_http_post_request() {
    let url = from_str("http://202.118.8.2:8080/book/queryOut.jsp").unwrap();
    let mut req = Request::new_with_url(&url);
    let mut h = HTTPHandler { debug : true };

    req.method = POST;
    req.add_body(bytes!("kind=simple&type=title&word=erlang&match=mh&recordtype=01&library_id=all&x=40&y=10"));

    let mut resp = h.handle(&mut req).unwrap();

    dump_result(&req, &resp);
    // charset = gbk
    match resp.read_to_end() {
        Ok(content) => {
            for c in content.iter() {
                print!("{:c}", *c as char);
            }
            println!("DEBUG read bytes=> {}", content.len());
        }
        Err(e) => {
            println!("! read error: {:?}", e);
        }
    }
    assert_eq!(resp.status, 200);
}

#[test]
fn test_http_options_request() {
    let url = from_str("http://www.w3.org").unwrap();
    let mut req = Request::new_with_url(&url);
    req.method = OPTIONS;
    let mut h = HTTPHandler { debug : true };
    let mut resp = h.handle(&mut req).unwrap();

    assert_eq!(resp.status, 200);
    assert!(resp.headers.find(&~"Allow").is_some());
}

#[test]
fn test_http_head_request() {
    let url = from_str("http://www.w3.org").unwrap();
    let mut req = Request::new_with_url(&url);
    req.method = HEAD;
    let mut h = HTTPHandler { debug : true };
    let mut resp = h.handle(&mut req).unwrap();

    assert_eq!(resp.read_to_end().unwrap().len(), 0);
    assert_eq!(resp.status, 200);
}

#[test]
fn test_weather_sug() {
    let url : Url = from_str("http://toy1.weather.com.cn/search?cityname=yulin&_=2").unwrap();

    let mut req = Request::new_with_url(&url);
    req.headers.find_or_insert(~"Referer", ~[~"http://www.weather.com.cn/"]);

    let mut h = HTTPHandler { debug: true };
    let mut resp = h.handle(&mut req).unwrap();

    let content = match resp.read_to_str() {
        Ok(content) => {
            content
        }
        Err(_) =>
            ~""
    };
    assert!(content.len() > 10);
    assert!(resp.status == 200);
}
