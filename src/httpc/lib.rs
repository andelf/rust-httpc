#![desc = "A rust crate for http protocol"]
#![license = "MIT"]

#![crate_name = "httpc"]
#![crate_type = "lib"]

#![feature(globs, phase)]
#![allow(unused_must_use)]
#![allow(dead_code)]

#[phase(syntax, link)] extern crate log;

extern crate url;
extern crate collections;
extern crate time;
extern crate libc;
extern crate debug;

use std::io;
use std::io::net::addrinfo::get_host_addresses;
use std::io::net::ip::SocketAddr;
use std::io::net::tcp::TcpStream;
use std::io::BufferedReader;
use std::io::IoResult;

use std::vec::Vec;

use std::cmp::min;

use std::fmt::{Show, Formatter, Result};

// for to_ascii_lower, eq_ignore_ascii_case
use std::ascii::StrAsciiExt;
//use std::ascii::AsciiStr;
use std::num::from_str_radix;

use std::collections::HashMap;

/// urlencod to encode querys
pub use url::query_to_str;
/// Url implementation
pub use url::Url;

pub use cookie::Cookie;

mod zlib;

static USER_AGENT : &'static str = "Rust-http-helper/0.1dev";
static HTTP_PORT : u16 = 80;

#[deriving(PartialEq, Show)]
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
            HTTP_1_1 => write!(f, "HTTP/1.1"),
            HTTP_1_0 => write!(f, "HTTP/1.0"),
        }
    }
}

// ==================== Request
pub struct Request<'a> {
    pub version: HttpVersion,
    pub uri: Url,
    pub method: HttpMethod,
    pub headers: HashMap<String, Vec<String>>,
    pub content: Vec<u8>,
}

impl<'a> Request<'a> {
    pub fn with_url(uri: &Url) -> Request {
        // fix empty path
        let mut uri = uri.clone();
        if uri.path == "".to_string() {
            uri.path = "/".to_string();
        }
        Request { version: HTTP_1_1, uri: uri, method: GET,
                  headers: HashMap::new(),
                  content: Vec::new() }
    }

    pub fn add_body(&mut self, body: &[u8]) {
        self.content = Vec::from_slice(body);
    }

    // clean old header add new header
    pub fn set_header(&mut self, key: &str, value: &str) {
        self.headers.insert(key.to_ascii_lower(),
                            vec!(value.into_string()));
    }

    // add new header value to exist value
    pub fn add_header(&mut self, key: &str, value: &str) {
        self.headers.insert_or_update_with(key.to_ascii_lower(),
                                           vec!(value.into_string()),
                                           |_k,v| v.push(value.into_string()));
    }

    pub fn get_headers(&self, header_name: &str) -> Vec<String> {
        let mut ret : Vec<String> = Vec::new();
        match self.headers.find(&header_name.to_ascii_lower()) {
            Some(hdrs) => for hdr in hdrs.iter() {
                ret.push(hdr.clone())
            },
            _ => ()
        }
        ret
    }

    pub fn write_request(&self, w: &mut Writer) -> IoResult<()> {
        // METHOD /path HTTP/v.v
        write!(w, "{} ", self.method.to_str());

        // /path
        w.write_str(self.uri.path.as_slice());
        if !self.uri.query.is_empty() {
            w.write_char('?');
            w.write_str(query_to_str(&self.uri.query).as_slice());
        }

        write!(w, " {}", self.version.to_str());

        w.write_str("\r\n");

        // headers
        for (k, vs) in self.headers.iter() {
            w.write_str(k.as_slice());
            w.write_str(": ");
            for (i, v) in vs.iter().enumerate() {
                w.write_str(v.as_slice());
                // FIXME: multi-value header line
                if i > 0 { w.write_str("; "); }
            }
            w.write_str("\r\n");
        }

        w.write_str("\r\n");

        match self.method {
            POST | PUT => w.write(self.content.as_slice()),
            _ => Ok(())
        };

        w.flush();
        Ok(())
    }
}

pub fn to_header_case(key: &str) -> String {
    let mut ret = String::new();
    let mut flag_is_at_words_begin = true;
    for c in key.as_bytes().iter() {
        if flag_is_at_words_begin {
            ret.push_char(c.to_ascii().to_uppercase().to_char());
            flag_is_at_words_begin = false;
        } else {
            ret.push_char(c.to_ascii().to_lowercase().to_char());
        }
        if *c == '-' as u8 {
            flag_is_at_words_begin = true;
        }
    }
    ret
}

#[allow(unused_variable)]
pub trait Handler {
    fn before_request(&mut self, req: &mut Request) {}
    fn after_response(&mut self, req: &Request, resp: &mut Response) -> Option<Response> { None }
    fn redirect_request(&mut self, req: &Request, resp: &Response) -> Option<Request> { None }
    fn handle_order(&self) -> int { 100 }
}

pub struct HTTPHandler {
    debug: bool
}

impl HTTPHandler {
    pub fn new() -> HTTPHandler {
        HTTPHandler { debug: false }
    }
}

impl Handler for HTTPHandler {
    fn before_request(&mut self, req: &mut Request) {
        let uri = req.uri.clone();
        let host = uri.port.map_or(req.uri.host.clone(), |p| format!("{}:{}", req.uri.host, p));
        req.headers.find_or_insert("host".to_string(), vec!(host));

        req.headers.find_or_insert("user-agent".to_string(), vec!(USER_AGENT.into_string()));

        // partly support x-deflate.
        req.headers.find_or_insert("accept-encoding".to_string(), vec!("identity".to_string()));

        req.headers.find_or_insert("connection".to_string(), vec!("close".to_string()));

        match req.method {
            POST | PUT => {
                req.headers.find_or_insert("content-length".to_string(), vec!(req.content.len().to_str()));
                req.headers.find_or_insert("content-type".to_string(), vec!("application/x-www-form-urlencoded".to_string()));
            },
            _          => (),
        }
    }

}


// pub struct CompressHandler<'a> {
//     debug: bool
// }

// impl<'a> Handler for CompressHandler<'a> {
//     fn request(&mut self, req: &mut Request) -> Option<Request> {
//         req.set_header("Accept-Encoding", "gzip,deflate");
//         None
//     }

//     fn response(&mut self, req: &Request, resp: &mut Response) -> Option<Response> {
//         match resp.get_headers("Content-Encoding").head() {
//             Some(&"gzip".to_string()) => {
//                 let gzreader = compress::GzipReaderWrapper::new(resp.sock);
//                 let mut bufreader = io::BufferedReader::new(gzreader);
//                 resp.sock = &mut bufreader as &mut Buffer;
//             }
//             _ => ()
//         }
//         None
//     }

//     fn handle_order(&self) -> int {
//         300
//     }
// }

/// Redirect handler
pub struct HTTPRedirectHandler {
    debug: bool,
}

impl HTTPRedirectHandler {
    pub fn new() -> HTTPRedirectHandler {
        HTTPRedirectHandler { debug: true }
    }
}

impl Handler for HTTPRedirectHandler {
    fn handle_order(&self) -> int {
        300
    }

    fn redirect_request(&mut self, req: &Request, resp: &Response) -> Option<Request> {
        if [301, 302, 303, 307].contains(&resp.status) && ( req.method == GET || req.method == HEAD ) ||
            [301, 302, 303].contains(&resp.status) && req.method == POST {
            println!("need redirect!");
            let newurl = match resp.get_headers("location").last() {
                Some(u) => u.clone(),
                None => match resp.get_headers("uri").last() {
                    Some(u) => u.clone(),
                    None => fail!("Protocal error: redirect without Location header")
                }
            };
            let mut newreq = Request::with_url(&from_str(newurl.as_slice()).unwrap());
            for (k, vs) in req.headers.iter() {
                for v in vs.iter() {
                    newreq.add_header(k.as_slice(), v.as_slice());
                }
            }
            println!("new req => {:?}", newreq);
            // TODO: fix possible malformed URL
            Some(newreq)

        } else {
            None
        }
    }
}

/// Cookie handler
pub struct HTTPCookieProcessor {
    pub jar: CookieJar
}

impl HTTPCookieProcessor {
    pub fn new() -> HTTPCookieProcessor {
        HTTPCookieProcessor { jar: CookieJar::new() }
    }
}

impl Handler for HTTPCookieProcessor {
    fn before_request(&mut self, req: &mut Request) {
        for ck in self.jar.cookies_for_request(req).iter() {
            req.add_header("Cookie", ck.to_header().as_slice());
        }
    }
    fn after_response(&mut self, req: &Request, resp: &mut Response) -> Option<Response> {
        for cookie_header in resp.get_headers("set-cookie").iter() {
            let ck_opt : Option<Cookie> = from_str(cookie_header.as_slice());
            if ck_opt.is_some() {
                let ck = ck_opt.unwrap();
                self.jar.set_cookie_if_ok(ck, req);
            }
        }
        None
    }
    fn handle_order(&self) -> int {
        200
    }
}




pub struct OpenDirector {
    pub handlers: Vec<Box<Handler>>,
    pub max_redirect: int,
}

impl OpenDirector {
    pub fn new() -> OpenDirector {
        OpenDirector { handlers: vec!( box HTTPHandler::new() as Box<Handler>,
                                       box HTTPCookieProcessor::new() as Box<Handler>,
                                       box HTTPRedirectHandler::new() as Box<Handler>),
                       max_redirect: 10,
        }
    }

    pub fn add_handler(&mut self, h: Box<Handler>) {
        self.handlers.push(h);
    }

    pub fn open(&mut self, req: &mut Request) -> Option<Response> {
        if self.max_redirect == 0 {
            return None
        }

        self.handlers.sort_by(|h1,h2| h1.handle_order().cmp(&h2.handle_order()));
        for hd in self.handlers.mut_iter() {
            hd.before_request(req);
        }

        let uri = req.uri.clone();
        let port = uri.port.clone().and_then(|p| from_str(p.as_slice())).unwrap_or(HTTP_PORT);
        let ips = get_host_addresses(uri.host.as_slice()).unwrap();
        let addr = SocketAddr { ip: ips.get(0).clone(), port: port };

        let mut stream = TcpStream::connect(addr.ip.to_str().as_slice(), addr.port).unwrap();

        req.write_request(&mut stream);

        let mut resp = Response::with_stream(&stream);
        // FIXME: this is ugly
        if req.method == HEAD {
            // HEAD req has content-length response header, but no payload
            resp.eof = true;
        }

        for hd in self.handlers.mut_iter() {
            hd.after_response(req, &mut resp);
        }

        let newreq = self.handlers.mut_iter().fold(None, |ret, hd| {
                if ret.is_some() {
                    ret
                } else {
                    hd.redirect_request(req, &resp)
                }
            });
        match newreq {
            None => Some(resp),
            Some(mut req) => {
                self.max_redirect -= 1;
                self.open(&mut req)
            }
        }
    }
}

pub fn build_opener() -> OpenDirector {
    OpenDirector::new()
}


pub struct CookieJar {
    // [Domain Path Name]
    pub cookies: HashMap<String, HashMap<String, HashMap<String, Cookie>>>
}

#[allow(unused_mut)]
impl CookieJar {
    pub fn new() -> CookieJar {
        CookieJar { cookies: HashMap::new() }
    }

    pub fn set_cookie(&mut self, domain: &str, path: &str, ck: Cookie) {
        let domain = domain.into_string();
        let path = path.into_string();
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
        for set_ck in resp.get_headers("Set-Cookie".to_ascii_lower().as_slice()).iter() {
            let ck_opt: Option<Cookie> = from_str(set_ck.as_slice());
            assert!(ck_opt.is_some());
            let ck = ck_opt.unwrap();
            self.set_cookie_if_ok(ck, req);
        }
    }

    pub fn set_cookie_if_ok(&mut self, ck: Cookie, req: &Request) {
        let domain = ck.clone().domain.unwrap_or(req.uri.clone().host);
        let path = ck.clone().path.unwrap_or("/".to_string());
        // TODO: add simple Cookie polocy here
        self.set_cookie(domain.as_slice(), path.as_slice(), ck);
    }


    pub fn cookies_for_request(&mut self, req: &Request) -> Vec<Cookie> {
        let uri = req.uri.clone();
        let domain = uri.clone().host;
        let path = uri.clone().path;
        let m1 = &self.cookies;
        // TOOD: handle secure & httpOnly
        //let scheme = uri.scheme.clone();

        let mut ret = Vec::new();
        // find domain
        for d in m1.keys() {
            if (d.as_slice().starts_with(".") && domain.as_slice().ends_with(d.as_slice())) || d.eq(&domain) {
                let m2 = m1.find(d).unwrap();
                // find path
                for p in m2.keys() {
                    if path.as_slice().starts_with(p.as_slice()) {
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
    pub version: HttpVersion,
    pub status: int,
    pub reason: String,
    pub headers: HashMap<String, Vec<String>>,

    chunked: bool,
    chunked_left: Option<uint>,
    pub length: Option<uint>,
    length_left: uint,
    // make sock a owned TcpStream
    // FIXME: maybe a rust bug here
    // when using Buffer/Reader traits here, program will hangs at main() ends
    // gdb shows that epoll_wait with timeout=-1, and pthread_cond_wait()
    sock: TcpStream,
    eof: bool,
}

impl<'a> Response<'a> {
    pub fn with_stream(s: &TcpStream) -> Response {
        let mut stream = BufferedReader::with_capacity(1, s.clone());

        let line = stream.read_line().unwrap(); // status line
        let segs = line.as_slice().splitn(' ', 2).collect::<Vec<&str>>();

        let version = match *segs.get(0) {
            "HTTP/1.1"                  => HTTP_1_1,
            "HTTP/1.0"                  => HTTP_1_0,
            v if v.starts_with("HTTP/") => HTTP_1_0,
            _                           => fail!("unsupported HTTP version")
        };
        let status = from_str::<int>(*segs.get(1)).unwrap();
        let reason = segs.get(2).trim_right();

        debug!("Got HTTP Response version = {:?} status = {:?} reason = {:?}",
               version, status, reason);

        let mut headers = HashMap::new();
        loop {
            let line = stream.read_line().unwrap();
            let segs = line.as_slice().splitn(':', 1).collect::<Vec<&str>>();
            if segs.len() == 2 {
                let k = segs.get(0).trim();
                let v = segs.get(1).trim();
                headers.insert_or_update_with(k.to_ascii_lower(), vec!(v.into_string()),
                                              |_k, ov| ov.push(v.into_string()));
            } else {
                if ["\r\n".to_string(), "\n".to_string(), "".to_string()].contains(&line) {
                    break;
                }
                fail!("malformatted line");
            }
        }

        let mut chunked = false;
        for (k, v) in headers.iter() {
            if k.as_slice().eq_ignore_ascii_case("transfer-encoding") {
                if v.get(0).as_slice().eq_ignore_ascii_case("chunked") {
                    chunked = true;
                }
                break;
            }
        }

        let mut length = None;
        if !chunked {
            length = match headers.find(&"Content-Length".to_ascii_lower()) {
                None => None,
                Some(v) => from_str::<uint>(v.get(0).as_slice()),
            }
        }

        debug!("HTTP Response chunked={} length={}", chunked, length);

        Response { version: version, status: status, reason: reason.into_string(),
                   headers: headers,
                   chunked: chunked, chunked_left: None,
                   length: length, length_left: length.unwrap_or(0),
                   sock: s.clone(), eof: false }
    }

    pub fn get_headers(&self, header_name: &str) -> Vec<String> {
        let mut ret = Vec::new();
        match self.headers.find(&header_name.to_ascii_lower()) {
            Some(hdrs) => for hdr in hdrs.iter() {
                ret.push(hdr.clone())
            },
            _ => ()
        }
        ret
    }

    fn read_next_chunk_size(&mut self) -> Option<uint> {
        let mut line = String::new();
        static MAXNUM_SIZE : uint = 16; // 16 hex digits
        static HEX_CHARS : &'static [u8] = bytes!("0123456789abcdefABCDEF");
        let mut is_in_chunk_extension = false;
        loop {
            match self.sock.read_byte() {
                Ok(0x0du8)                          => {      // \r\n ends chunk size line
                    let lf = self.sock.read_byte().unwrap() as char;
                    assert_eq!(lf, '\n');
                    break;
                }
                Ok(0x0au8)                          => {      // \n ends is dangerous
                    warn!("http chunk transfer encoding format: LF without CR.");
                    break;
                }
                Ok(_) if is_in_chunk_extension      => { continue; }
                Ok(c) if HEX_CHARS.contains(&c) => { line.push_char(c as char); }
                // `;`
                Ok(0x3bu8)                          => { is_in_chunk_extension = true; }
                Ok(c)                               => {
                    fail!("malformat: reads={:?} next={:?}", line, c);
                }
                Err(_)                              => return None,
            }
        }

        if line.len() > MAXNUM_SIZE {
            fail!("http chunk transfer encoding format: size line too long: {:?}", line);
        }
        debug!("read_next_chunk_size, line={:?} value={:?}", line, from_str_radix::<uint>(line.as_slice(), 16));

        match from_str_radix(line.as_slice(), 16) {
            Some(v) => Some(v),
            None => fail!("wrong chunk size value: {:?}", line),
        }
    }
}

impl<'a> Reader for Response<'a> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<uint> {
        if self.eof {
            return Err(io::standard_error(io::EndOfFile));
        }
        if !self.chunked {
            if self.length.is_none() {
                warn!("No content length header set!");
                return self.sock.read(buf);
            }
            if self.length_left == 0 {
                self.eof = true;
                return Err(io::standard_error(io::EndOfFile));
            } else if self.length_left > 0 {
                match self.sock.read(buf) {
                    Ok(n)  => {
                        self.length_left -= n;
                        return Ok(n);
                    }
                    Err(e) => {
                        warn!("error while reading {} bytes: {:}", self.length_left, e);
                        return Err(io::standard_error(io::InvalidInput));
                    }
                }
            } else {
                unreachable!()
            }
        }

        // read one chunk or less
        match self.chunked_left {
            Some(left) => {
                let tbuf_len = min(buf.len(), left);
                let mut tbuf = Vec::from_elem(tbuf_len, 0u8);
                match self.sock.read(tbuf.as_mut_slice()) {
                    Ok(nread) => {
                        buf.move_from(tbuf.as_slice().into_owned(), 0, nread);
                        if left == nread {
                            // this chunk ends
                            // toss the CRLF at the end of the chunk
                            assert!(self.sock.read_exact(2).is_ok());
                            self.chunked_left = None;
                        } else {
                            self.chunked_left = Some(left - nread);
                        }
                        Ok(nread)
                    }
                    Err(e) => {
                        error!("error read from sock: {}", e);
                        Err(e)
                    }
                }
            }
            None => {
                let chunked_left = self.read_next_chunk_size();
                match chunked_left {
                    Some(0) => {
                        assert!(self.sock.read_exact(2).is_ok());
                        self.eof = true;
                        Err(io::standard_error(io::EndOfFile))
                    }
                    Some(_) => {
                        self.chunked_left = chunked_left;
                        self.read(buf) // recursive call once, istead of Ok(0)
                    }
                    None => {
                        self.eof = true;
                        Err(io::standard_error(io::EndOfFile))
                    }
                }
            }
        }
    }
}

// for Cookie impl
pub mod cookie;
// for GzipReader
pub mod compress;


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_header_case() {
        assert_eq!(to_header_case("X-ForWard-For"), "X-Forward-For".to_string());
        assert_eq!(to_header_case("accept-encoding"), "Accept-Encoding".to_string());
    }
}
