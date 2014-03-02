extern crate extra;
extern crate collections;
extern crate time;


use std::io::net::addrinfo::get_host_addresses;
use std::io::net::ip::SocketAddr;
use std::io::net::tcp::TcpStream;
use std::io::{BufferedReader,BufferedWriter};
use std::io;
use std::io::IoResult;

use std::vec;

use std::fmt::{Show, Formatter, Result};

// for to_ascii_lower, eq_ignore_ascii_case
use std::ascii::StrAsciiExt;
//use std::ascii::AsciiStr;
use std::num::from_str_radix;

use extra::url::{Url, query_to_str};

use collections::HashMap;

mod cookie;

static USER_AGENT : &'static str = "Rust-http-helper/0.1dev";
static HTTP_PORT : u16 = 80;


#[deriving(Show)]
pub enum HttpMethod {
      /**
     *  A request for information about the communication options
     *  available on the request/response chain
     */
    OPTIONS,
    /**
     * Retrieve whatever information (in the form of an entity)
     * is identified by the Request-URI
     */
    GET,
    /**
     * Identical to GET except that the server MUST NOT return a
     * message-body in the response
     */
    HEAD,
    /**
     * Requests that the origin server accept the entity enclosed in the
     * request as a new subordinate of the resource identified by the
     * Request-URI in the Request-Line
     */
    POST,
    /**
     * Requests that the enclosed entity be stored under the supplied Request-URI
     */
    PUT,
    /**
     * Requests that the origin server delete the resource identified
     * by the Request-URI
     */
    DELETE,
    /**
     * Requests a remote, application-layer loop- back of the request message
     */
    TRACE,
    /**
     * Reserved
     */
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
    content: Option<&'a Reader>

}

impl<'a> Request<'a> {
    pub fn new_with_url(uri: &Url) -> Request {
        // fix empty path
        let mut uri = uri.clone();
        if uri.path == ~"" {
            uri.path = ~"/";
        }
        Request { version: HTTP_1_1, uri: uri, method: GET,
                  headers: HashMap::new(), content: None}
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

#[allow(unused_must_use)]
impl Handler for HTTPHandler {
    // TODO pre request: add ness header
    // TODO after request: error handling
    fn request(&mut self, req: &mut Request) -> Option<Request> {
        let uri = req.uri.clone();
        // let mut host = uri.host.clone();
        // if !uri.port.is_none() { host.push_str(format!(":{}", uri.port.unwrap())) }
        let host = uri.port.map_or(req.uri.host.clone(),
                                   |p| format!("{}:{}", req.uri.host, p));
        req.headers.find_or_insert(~"Host", ~[host]);

        req.headers.find_or_insert(~"User-Agent", ~[USER_AGENT.into_owned()]);

        // not support x-gzip or x-deflate.
        req.headers.find_or_insert(~"Accept-Encoding", ~[~"identity"]);

        req.headers.find_or_insert(~"Connection", ~[~"close"]);

        // for (key, values) in req.headers.iter() {
        //     println!("dump HEADER {:?} => {:?}", key, values);
        // }
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
        let request_method = req.method.to_str();
        stream.write_str(request_method);
        stream.write_str(" ");
        stream.write_str(uri.path);

        if !uri.query.is_empty() {
            stream.write_char('?');
            stream.write_str(query_to_str(&uri.query));
        }

        stream.write_str(" ");
        stream.write_str(req.version.to_str());
        stream.write_char('\n');

        // headers
        for (k, vs) in req.headers.iter() {
            stream.write_str(*k);
            stream.write(bytes!(": "));
            for (i, v) in vs.iter().enumerate() {
                stream.write_str(*v);
                // FIXME: multi-value header line
                if i > 0 { stream.write(bytes!("; ")); }
            }
            stream.write(bytes!("\n"));
        }

        stream.write(bytes!("\n"));
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
        println!("DEBUG header segs {:?}", segs);
        let version = match segs[0] {
            "HTTP/1.1"                  => HTTP_1_1,
            "HTTP/1.0"                  => HTTP_1_0,
            v if v.starts_with("HTTP/") => HTTP_1_0,
            _                           => fail!("unsupported HTTP version")
        };
        let status = from_str::<int>(segs[1]).unwrap();
        let reason = segs[2].trim_right();

        println!("HTTP version = {:?} status = {:?} reason = {:?}", version, status, reason);

        let mut headers = HashMap::new();
        loop {
            let line = stream.read_line().unwrap();
            let segs = line.splitn(':', 1).collect::<~[&str]>();
            if segs.len() == 2 {
                let k = segs[0];
                let v = segs[1].trim();
                // println!("HEADER {:?} => |{:?}|", k, v);
                headers.insert_or_update_with(k.into_owned(), ~[v.into_owned()],
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
    //let u = ~"http://www.google.com/";
    //let u = ~"http://fledna.duapp.com/ip";
    //let u = ~"http://127.0.0.1:8888/fuckyou_self_and";
    //let u = ~"http://www.baidu.com";
    //let u = ~"http://weibo.com";
    //let u = ~"http://zx.bjmemc.com.cn/ashx/Data.ashx?Action=GetAQIClose1h";
    //    let u = "http://www.yahoo.com.cn";
    //let u = "http://sg.search.yahoo.com/";
    //let u = "http://www.renren.com/";
    let u = "http://www.baidu.com/#wd=http%201.1%20zlib%20uncompress&rsv_spt=1&issp=1&rsv_bp=0&ie=utf-8&tn=baiduhome_pg&rsv_sug3=1&rsv_sug4=17&rsv_sug2=0&inputT=6";

    let url : Url = from_str(u).unwrap();

    let mut req = Request::new_with_url(&url);
    // req.headers.find_or_insert(~"Accept-Encoding", ~[~"gzip,deflate,sdch"]);
    // req.headers.find_or_insert(~"Accept", ~[~"*/*"]);
    // req.headers.find_or_insert(~"User-Agent", ~[~"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.11 Safari/537.36"]);


    let mut h = HTTPHandler { debug: true };
    let mut resp = h.handle(&mut req).unwrap();

    let mut s = ~"";

    match resp.read_to_str() {
        Ok(content) => {
            s = s + content;
            println!("| {}", content);
        }
        Err(e) => {
            println!("! read error: {:?}", e);
        }
    }
    println!("DEBUG read bytes=> {}", s.len());
    dump_result(&req, &resp);
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
    let url = from_str("http://www.google.com/").unwrap();
    let mut req = Request::new_with_url(&url);
    let mut h = HTTPHandler { debug : true };
    let mut resp = h.handle(&mut req).unwrap();

    dump_result(&req, &resp);
    for set_ck in resp.headers.get(&to_header_case("set-cookie")).iter() {
        let ck_opt = from_str::<cookie::Cookie>(*set_ck);
        assert!(ck_opt.is_some());
        println!("got cookie => {:?}", ck_opt);
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

    dump_result(&req, &resp);
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
    let url = from_str("http://www.baidu.com").unwrap();
    let mut req = Request::new_with_url(&url);
    req.method = HEAD;
    let mut h = HTTPHandler { debug : true };
    let mut resp = h.handle(&mut req).unwrap();

    dump_result(&req, &resp);
    println!("| {:?}", resp.read_to_str());
    assert_eq!(resp.status, 405);
}


#[test]
fn test_yahoo_redirect_response() {
    let url = from_str("http://www.yahoo.com.cn").unwrap();
    let mut req = Request::new_with_url(&url);
    req.headers.find_or_insert(~"Accept-Encoding", ~[~"gzip,deflate,sdch"]);

    let mut h = HTTPHandler { debug: true };
    let mut resp = h.handle(&mut req).unwrap();

    let content = match resp.read_to_str() {
        Ok(content) => {
            content
        }
        Err(_) =>
            ~""
    };
    dump_result(&req, &resp);
    println!("content = {:?}", content);
    assert!(false);
}


#[test]
fn test_header_case() {
    assert_eq!(to_header_case("X-ForWard-For"), ~"X-Forward-For");
    assert_eq!(to_header_case("accept-encoding"), ~"Accept-Encoding");
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




/*
GET /fuck HTTP/1.1
Host: localhost:8088
Connection: keep-alive
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,* / *;q=0.8
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1838.2 Safari/537.36
Accept-Encoding: gzip,deflate,sdch
Accept-Language: en-US,en;q=0.8
RA-Ver: 1.7.2
RA-Sid: 0E8202A9-20131112-145528-03b634-2d1e16
*/
