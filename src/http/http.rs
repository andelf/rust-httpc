extern crate extra;
extern crate collections;
extern crate time;

use std::io::net::addrinfo::get_host_addresses;
use std::io::net::ip::SocketAddr;
use std::io::net::tcp::TcpStream;
use std::io::{BufferedReader,BufferedWriter};
use std::io::util::{LimitReader, copy};
use std::io;
use std::io::IoResult;

use std::str;
use std::vec;

use std::fmt::{Show, Formatter, Result};

use std::logging;

// for to_ascii_lower, eq_ignore_ascii_case
use std::ascii::StrAsciiExt;
//use std::ascii::AsciiStr;
use std::num::from_str_radix;

use extra::url::{Url, query_to_str};

use collections::HashMap;

use cookie::Cookie;
pub use urlencode = extra::url::query_to_str;

pub mod cookie;

static USER_AGENT : &'static str = "Rust-http-helper/0.1dev";
static HTTP_PORT : u16 = 80;


#[deriving(Show)]
pub enum HttpMethod {
    OPTIONS,
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    TRACE,
    CONNECT,
}

#[allow(non_camel_case_types)]
pub enum HttpVersion {
    HTTP_1_1,
    HTTP_1_0,
}

impl Show for HttpVersion {
    fn fmt(&self, f: &mut Formatter) -> Result {
        match *self {
            HTTP_1_1 => f.buf.write(bytes!("HTTP/1.1")),
            HTTP_1_0 => f.buf.write(bytes!("HTTP/1.0")),
        }
    }
}

// ==================== Request
pub struct Request<'a> {
    version: HttpVersion,
    uri: Url,
    method: HttpMethod,
    headers: HashMap<~str, ~[~str]>,
    content: ~[u8],
}

impl<'a> Request<'a> {
    pub fn new_with_url(uri: &Url) -> Request {
        // fix empty path
        let mut uri = uri.clone();
        if uri.path == ~"" {
            uri.path = ~"/";
        }
        Request { version: HTTP_1_1, uri: uri, method: GET,
                  headers: HashMap::new(),
                  content: ~[]}
    }

    pub fn add_body(&mut self, body: &[u8]) {
        self.content = body.into_owned();
    }

    pub fn add_header(&mut self, key: &str, value: &str) {
        self.headers.insert_or_update_with(to_header_case(key),
                                           ~[value.into_owned()],
                                           |_k,v| v[0] = value.into_owned()) ;
    }
}

// fn header_eq(a: &str, b: &str) -> bool {
//     a.eq_ignore_ascii_case(b)
// }

fn to_header_case(key: &str) -> ~str {
    let mut ret = ~"";
    let mut flag_is_at_words_begin = true;
    for c in key.as_bytes().iter() {
        if flag_is_at_words_begin {
            ret.push_char(c.to_ascii().to_upper().to_char());
            flag_is_at_words_begin = false;
        } else {
            ret.push_char(c.to_ascii().to_lower().to_char());
        }
        if *c == '-' as u8 {
            flag_is_at_words_begin = true;
        }
    }
    ret
}

#[allow(unused_variable)]
pub trait Handler {
    fn request(&mut self, req: &mut Request) -> Option<Request> { None }
    fn response(&mut self, req: Request, resp: Response) -> Option<Response> { None }
    fn handle(&mut self, req: &mut Request) -> Option<Response> { None }

    fn handler_order() -> int { 100 }
}



pub struct HTTPHandler {
    debug: bool
}

impl Handler for HTTPHandler {
    // TODO after request: error handling
    fn request(&mut self, req: &mut Request) -> Option<Request> {
        let uri = req.uri.clone();
        let host = uri.port.map_or(req.uri.host.clone(),
                                   |p| format!("{}:{}", req.uri.host, p));
        req.headers.find_or_insert(~"Host", ~[host]);

        req.headers.find_or_insert(~"User-Agent", ~[USER_AGENT.into_owned()]);

        // not support x-gzip or x-deflate.
        req.headers.find_or_insert(~"Accept-Encoding", ~[~"identity"]);

        // not support keep-alive connection
        req.headers.find_or_insert(~"Connection", ~[~"close"]);

        match req.method {
            POST | PUT => {
                req.headers.find_or_insert(~"Content-Length", ~[req.content.len().to_str()]);
                req.headers.find_or_insert(~"Content-Type", ~[~"application/x-www-form-urlencoded"]);
            },
            _ => {
                log!(::std::logging::WARN, "POST/PUT without a content");
                req.headers.find_or_insert(~"Content-Length", ~[~"0"]);
            },
        }
        None
    }

    fn handle(&mut self, req: &mut Request) -> Option<Response> {
        // DEBUG
        self.request(req);

        let uri = req.uri.clone();

        let ips = get_host_addresses(uri.host).unwrap();
        let port = uri.port.clone().and_then(|p| from_str(p)).unwrap_or(HTTP_PORT);

        let addr = SocketAddr { ip: ips.head().unwrap().clone(), port: port };

        let stream = TcpStream::connect(addr).unwrap();
        let read_stream = stream.clone();
        let mut stream = BufferedWriter::new(stream);

        // METHOD /path HTTP/v.v
        stream.write_str(req.method.to_str());
        stream.write_char(' ');
        stream.write_str(uri.path);

        if !uri.query.is_empty() {
            stream.write_char('?');
            stream.write_str(query_to_str(&uri.query));
        }

        stream.write_str(" ");
        stream.write_str(req.version.to_str());
        stream.write_str("\r\n");

        // headers
        for (k, vs) in req.headers.iter() {
            stream.write_str(*k);
            stream.write_str(": ");
            for (i, v) in vs.iter().enumerate() {
                stream.write_str(*v);
                // FIXME: multi-value header line
                if i > 0 { stream.write_str("; "); }
            }
            stream.write_str("\r\n");
        }

        stream.write_str("\r\n");

        match req.method {
            POST | PUT => stream.write(req.content),
            _ => Ok(())
        };

        stream.flush();

        Some(Response::new_with_stream(&read_stream))
    }
}


pub struct GzipHandler {
    debug: bool
}

impl Handler for GzipHandler {
    fn response(&mut self, req: Request, resp: Response) -> Option<Response> {
        None
    }
}

pub struct CookieJar {
    // [Domain Path Name]
    cookies: HashMap<~str, HashMap<~str, HashMap<~str, Cookie>>>
}

impl CookieJar {
    pub fn new() -> CookieJar {
        CookieJar { cookies: HashMap::new() }
    }

    pub fn add_cookie_header(&self, req: &mut Request) {
    }

    pub fn set_cookie(&mut self, domain: &str, path: &str, ck: Cookie) {
        let domain = domain.into_owned();
        let path = path.into_owned();
        let name = ck.clone().name;
        let mut m1 = &mut self.cookies;
        if m1.contains_key(&domain) {
            let mut m2 = m1.find_mut(&domain).unwrap();
            if m2.contains_key(&path) {
                let mut m3 = m2.find_mut(&path).unwrap();
                m3.insert(name, ck);
            } else {
                let mut m3 = HashMap::new();
                m3.insert(name, ck);
                m2.insert(path, m3);
            }
        } else {
            let mut m3 = HashMap::new();
            m3.insert(name, ck);
            let mut m2 = HashMap::new();
            m2.insert(path, m3);
            m1.insert(domain, m2);
        }
    }
    pub fn process_response(&mut self, req: &Request, resp: &Response) {
        for set_ck in resp.headers.get(&to_header_case("set-cookie")).iter() {
            let ck_opt = from_str::<Cookie>(*set_ck);
            assert!(ck_opt.is_some());
            let ck = ck_opt.unwrap();
        }
    }

    pub fn set_cookie_if_ok(&mut self, ck: Cookie, req: &Request) {
        let domain = ck.clone().domain.unwrap_or(req.uri.clone().host);
        let path = ck.clone().path.unwrap_or(~"/");
        // TODO: add simple Cookie polocy here
        self.set_cookie(domain, path, ck);
    }


    pub fn cookies_for_request(&mut self, req: &Request) -> ~[Cookie] {
        let uri = req.uri.clone();
        let domain = uri.clone().host;
        let path = uri.clone().path;
        let m1 = &self.cookies;
        let scheme = uri.scheme.clone();
        let port = uri.port.unwrap_or(~"80");

        let mut ret = ~[];
        // find domain
        for d in m1.keys() {
            if (d.starts_with(".") && domain.ends_with(*d)) || str::eq(d, &domain) {
                let m2 = m1.find(d).unwrap();
                // find path
                for p in m2.keys() {
                    if path.starts_with(*p) {
                        // find key
                        let m3 = m2.find(p).unwrap();
                        for ck in m3.values() {
                            if ck.is_expired() { continue };
                            ret.push(ck.clone());
                        }
                    }
                }
            }
        }

        ret
    }

}



pub struct Response<'a> {
    version: HttpVersion,
    status: int,
    reason: ~str,
    headers: HashMap<~str, ~[~str]>,

    priv chunked: bool,
    priv chunked_left: Option<uint>,
    priv length: Option<uint>,
    // make sock a owned Buffer
    priv sock: ~Buffer // BufferedStream<TcpStream>
}

impl<'a> Response<'a> {
    pub fn new_with_stream(s: &'a TcpStream) -> Response {
        let mut stream = ~BufferedReader::new(s.clone());
        //let mut stream = s;
        let line = stream.read_line().unwrap(); // status line
        let segs = line.splitn(' ', 2).collect::<~[&str]>();
        //println!("DEBUG header segs {:?}", segs);
        let version = match segs[0] {
            "HTTP/1.1"                  => HTTP_1_1,
            "HTTP/1.0"                  => HTTP_1_0,
            v if v.starts_with("HTTP/") => HTTP_1_0,
            _                           => fail!("unsupported HTTP version")
        };
        let status = from_str::<int>(segs[1]).unwrap();
        let reason = segs[2].trim_right();

        println!("DEBUG HTTP version = {:?} status = {:?} reason = {:?}",
                 version, status, reason);

        let mut headers = HashMap::new();
        loop {
            let line = stream.read_line().unwrap();
            let segs = line.splitn(':', 1).collect::<~[&str]>();
            if segs.len() == 2 {
                let k = segs[0];
                let v = segs[1].trim();
                headers.insert_or_update_with(to_header_case(k), ~[v.into_owned()],
                                              |_k, ov| ov.push(v.into_owned()));
            } else {
                if [~"\r\n", ~"\n", ~""].contains(&line) {
                    break;
                }
                fail!("malformatted line");
            }
        }

        let mut chunked = false;
        for (k, v) in headers.iter() {
            if k.eq_ignore_ascii_case("transfer-encoding") {
                if v.head().unwrap().eq_ignore_ascii_case("chunked") {
                    chunked = true;
                }
                break;
            }
        }

        let mut length_opt = None;
        if !chunked {
            length_opt = match headers.find(&to_header_case("content-length")) {
                None => None,
                Some(v) => from_str::<uint>(*v.head().unwrap())
            }
        }
        println!("DEBUG chunked={} length={}", chunked, length_opt);

        Response { version: version, status: status, reason: reason.into_owned(),
                   headers: headers,
                   chunked: chunked, chunked_left: None, length: length_opt,
                   sock: stream as ~Buffer, }
    }

    pub fn get_headers(&self, header_name: &str) -> ~[~str] {
        let mut ret : ~[~str] = ~[];
        match self.headers.find(&to_header_case(header_name)) {
            Some(hdrs) => for hdr in hdrs.iter() {
                ret.push(hdr.clone())
            },
            _ => ()
        }
        ret
    }

    fn _read_next_chunk_size(&mut self) -> uint {
        let line = self.sock.read_line().unwrap();
        println!("_read_next_chunk_size, line = {:?}", line);
        let line = match line.find(';') {
            Some(i) => line.slice(0, i).into_owned(),
            None => line
        };

        match from_str_radix(line.trim_right(), 16) {
            Some(v) => v,
            None => fail!("wrong chunk size value")
        }
    }

}

impl<'a> Reader for Response<'a> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<uint> {
        // read 1 chunk or less
        //println!("DEBUG calls read()");
        if self.chunked {       // TODO: handle Gzip
            match self.chunked_left {
                Some(left) if left > 0 => {
                    let mut tbuf = vec::from_elem(left, 0u8);
                    match self.sock.read(tbuf) {
                        Ok(n) => {
                            buf.move_from(tbuf, 0, n);
                            if left - n == 0 { // this chunk ends
                                // toss the CRLF at the end of the chunk
                                assert!(self.sock.read_bytes(2).is_ok());
                                self.chunked_left = None;
                            } else {
                                self.chunked_left = Some(left - n);
                            }
                            Ok(n)
                        }
                        Err(e) => fail!("error read from sock: {}", e)
                    }
                }
                _ => {          // left == 0 or left is None
                    let chunked_left = self._read_next_chunk_size();
                    println!("1. chunked_left = {}", chunked_left);
                    if chunked_left == 0 {
                        Err(io::standard_error(io::EndOfFile))
                    } else  {
                        self.chunked_left = Some(chunked_left);
                        Ok(0)
                    }
                }
            }
        } else {
            self.sock.read(buf)
        }
    }
}




fn main() {
    //let u = ~"http://flash.weather.com.cn/sk2/101010100.xml";
    let u = ~"http://zx.bjmemc.com.cn/ashx/Data.ashx?Action=GetAQIClose1h";
    //let u = "http://www.gpsspg.com/ajax/latlng_office_maps.aspx?lat=39.91433268343&lng=116.46717705386&type=1";
    //req.add_header("Referer", "http://www.gpsspg.com/apps/maps/google_131201.htm");

    let url : Url = from_str(u).unwrap();
    let mut req = Request::new_with_url(&url);
    //req.method = POST;

    //req.add_header("user-agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3");

    let mut h = HTTPHandler { debug: true };
    let mut resp = h.handle(&mut req).unwrap();

    dump_result(&req, &resp);

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
    println!("get_headers = {:?}", resp.get_headers("set-cookie"));
}


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
fn test_post_request() {
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
fn test_options_request() {
    let url = from_str("http://www.w3.org").unwrap();
    let mut req = Request::new_with_url(&url);
    req.method = OPTIONS;
    let mut h = HTTPHandler { debug : true };
    let mut resp = h.handle(&mut req).unwrap();

    assert_eq!(resp.status, 200);
    assert!(resp.headers.find(&~"Allow").is_some());
}



//#[test]
// fn test_gzip_uncompress() {
//     let url = from_str("http://www.baidu.com").unwrap();
//     let mut req = Request::new_with_url(&url);
//     req.add_header("Accept", "*/*");
//     req.add_header("Accept-Encoding", "gzip,deflate,sdch");
//     req.add_header("User-Agent", "Mozilla/5.0");
//     let mut h = HTTPHandler { debug : true };
//     let mut resp = h.handle(&mut req).unwrap();

//     dump_result(&req, &resp);
//     let content = resp.read_to_end().unwrap();
//     //println!("| {:?}", content);
//     println!("|uncompress => {:?}", compress::zlib_uncompress(content.slice(10, content.len()-8)));


//     assert_eq!(resp.status, 200);
//     assert!(false);

// }



#[test]
fn test_head_request() {
    let url = from_str("http://www.w3.org").unwrap();
    let mut req = Request::new_with_url(&url);
    req.method = HEAD;
    let mut h = HTTPHandler { debug : true };
    let mut resp = h.handle(&mut req).unwrap();

    assert_eq!(resp.read_to_end().unwrap().len(), 0);
    assert_eq!(resp.status, 200);
}

#[test]
fn test_yahoo_redirect_response() {
    let url = from_str("http://www.yahoo.com.cn").unwrap();
    let mut req = Request::new_with_url(&url);
    //req.headers.find_or_insert(~"Accept-Encoding", ~[~"gzip,deflate,sdch"]);

    let mut h = HTTPHandler { debug: true };
    let mut resp = h.handle(&mut req).unwrap();

    assert_eq!(resp.status, 301);
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

#[test]
fn test_header_case() {
    assert_eq!(to_header_case("X-ForWard-For"), ~"X-Forward-For");
    assert_eq!(to_header_case("accept-encoding"), ~"Accept-Encoding");
}
