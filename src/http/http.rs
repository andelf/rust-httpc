#[allow(unused_must_use)]

extern crate extra;
extern crate collections;

use std::io::net::addrinfo::get_host_addresses;
use std::io::net::ip::SocketAddr;
use std::io::net::tcp::TcpStream;
use std::io::BufferedStream;
use std::io;
use std::io::IoResult;

use std::fmt::{Show, Formatter, Result};

// for to_ascii_lower, eq_ignore_ascii_case
use std::ascii::StrAsciiExt;
//use std::ascii::AsciiStr;
use std::num::from_str_radix;

use extra::url::{Url, query_to_str};

use collections::HashMap;



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
    pub fn new_with_url(uri: Url) -> Request {
        Request { version: HTTP_1_1, uri: uri,
                  method: GET, headers: HashMap::new(), content: None}
    }
}


fn header_eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

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


pub trait Opener {
    fn request(&mut self, req: &mut Request) -> Option<Request> { None }
    fn response(&mut self, req: Request, resp: Response) -> Option<Response> { None }
    fn handle(&mut self, req: &mut Request) -> Option<Response> { None }

    fn handler_order() -> int { 100 }
}

pub struct HTTPHandler {
    debug: bool
}

impl Opener for HTTPHandler {
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

        for (key, values) in req.headers.iter() {
            println!("dump HEADER {:?} => {:?}", key, values);
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
        let mut stream = BufferedStream::new(stream);

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


pub struct Response<'a> {
    version: int,
    status: int,
    reason: ~str,

    //headers: ~[(~str, ~str)],
    headers: HashMap<~str, ~[~str]>,

    priv chunked: bool,
    priv chunked_left: Option<uint>,

    priv length: Option<uint>,

    priv sock: BufferedStream<TcpStream>
}

impl<'a> Response<'a> {
    pub fn new_with_stream(s: &'a TcpStream) -> Response {
        let mut stream = BufferedStream::new(s.clone());
        //let mut stream = s;
        let line = stream.read_line().unwrap(); // status line
        let segs = line.split(' ').collect::<~[&str]>();
        let (version, status, reason) = if segs.len() == 3 {
            let ver = segs[0];
            let status = segs[1];
            let reason = segs[2];

            println!("v = {} st = {} reason = {}",
                     ver, status, reason);
            if !ver.starts_with("HTTP/") {
                println!("bad status line!");
            }
            let version = match ver {
                "HTTP/1.1" => 11,
                "HTTP/1.0" => 10,
                "HTTP/0.9" =>  9,
                _          =>  9
            };
            let status = from_str::<int>(status).unwrap();
            println!("status code = {}", status);

            if status < 100 || status > 999 {
                println!("bad status code");
            }
            (version, status, reason)
        } else {
                fail!("malformated status line")
        };

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
        println!("debug chunked={} length={}", chunked, length_opt);

        Response { version: version, status: status, reason: reason.into_owned(),
                   headers: headers,
                   chunked: chunked, chunked_left: None, length: length_opt,
                   sock: stream, }
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
        let mut ret : uint = 0;
        if self.chunked {
            if self.chunked_left.is_none() {
                let chunked_left = self._read_next_chunk_size();
                println!("1. chunked_left = {}", chunked_left);
                if chunked_left == 0 {
                    return Err(io::standard_error(io::EndOfFile));
                }
                match self.sock.read_bytes(chunked_left) {
                    Ok(bs) => buf.move_from(bs, ret, ret + chunked_left),
                    Err(_) => fail!("error read from sock")
                };
                ret += chunked_left;
                self.sock.read_bytes(2); // toss the CRLF at the end of the chunk
            }
            Ok(ret)
        } else {
            self.sock.read(buf)
        }
    }
}


fn main() {
    let u = ~"http://flash.weather.com.cn/sk2/101010100.xml";
    //let u = ~"http://www.google.com/";
    //let u = ~"http://fledna.duapp.com/ip";
    //let u = ~"http://127.0.0.1:8888/fuckyou_self_and";

    let url : Url = from_str(u).unwrap();

    let mut req = Request::new_with_url(url.clone());
    let mut h = HTTPHandler { debug: true };
    let mut resp = h.handle(&mut req).unwrap();

    let mut s = ~"";

    match resp.read_to_str() {
        Ok(content) => {
            s = s + content;
            print!("| {}", content);
        }
        Err(_) =>
            ()
    }

    println!("\n======================= result =======================");
    println!("read bytes=> {}", s.len());
    for (k, vs) in resp.headers.iter() {
        println!("H {:?} => {:?}", k, vs)
    }


    println!("****************************************");
    println!("headers eq {:?}", header_eq("Accept-Encoding", "accept-encoding"));
    println!("t: {:?}", to_header_case("X-ForWard-For"));
    println!("t: {:?}", to_header_case("accept-encoding"));
    println!("t: {:?}", to_header_case("keep-alive"));
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
