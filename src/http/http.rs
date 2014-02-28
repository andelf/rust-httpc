#[allow(unused_must_use)];

extern crate extra;

use extra::url::{Url, query_to_str};
use std::io::net::addrinfo::get_host_addresses;
use std::io::net::ip::SocketAddr;
use std::io::net::tcp::TcpStream;
use std::io::BufferedStream;
use std::io;
use std::io::IoResult;

use std::ascii::StrAsciiExt;
use std::num::from_str_radix;

static USER_AGENT : &'static str = "Rust-http-helper/0.1dev";
static HTTP_PORT : u16 = 80;
static HTTP_VERSION_STR : &'static str = "HTTP/1.1";


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

// ==================== Request
pub struct Request {
    version: int,
    headers: ~[(~str, ~str)],
    uri: Url,
    method: HttpMethod,

}

impl Request {
    pub fn new_with_url(u: Url) -> Request {
        Request { version: 11, headers: ~[],
                  uri: u, method: GET}
    }
}


pub trait Opener {
    fn open(&mut self, req: Request) -> Response;
    fn handler_order() -> int { 100 }
}

pub struct HTTPHandler {
    debug: bool
}

impl Opener for HTTPHandler {
    // TODO pre request: add ness header
    // TODO after request: error handling
    fn open(&mut self, req: Request) -> Response {
        let uri = req.uri.clone();

        let ips = get_host_addresses(uri.host).unwrap();
        let port = uri.port.clone().and_then(|p| from_str::<u16>(p)).unwrap_or(HTTP_PORT);

        let addr = SocketAddr { ip: ips.head().unwrap().clone(), port: port };

        let stream = TcpStream::connect(addr).unwrap();
        let read_stream = stream.clone();
        let mut stream = BufferedStream::new(stream);

        let request_method = req.method.to_str();

        stream.write_str(request_method);
        stream.write_str(" ");
        stream.write_str(uri.path);

        if !uri.query.is_empty() {
            stream.write_char('?');
            stream.write_str(query_to_str(&uri.query));
        }

        stream.write_str(" ");
        stream.write_str(HTTP_VERSION_STR);
        stream.write_char('\n');
        stream.write_str("Accept-Encoding: identity");
        stream.write(bytes!("\n"));

        stream.write_str("Host: ");
        stream.write_str(uri.host);
        stream.write(bytes!("\n"));

        stream.write_str("Connection: close");
        stream.write(bytes!("\n"));
        stream.write_str("User-Agent: ");
        stream.write_str(USER_AGENT);

        stream.write(bytes!("\n\n"));
        stream.flush();


        Response::new_with_stream(&read_stream)
    }
}


pub struct Response<'a> {
    version: int,
    status: int,
    reason: ~str,

    headers: ~[(~str, ~str)],

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

        let mut headers : ~[(~str,~str)] = ~[];
        loop {
            let line = stream.read_line().unwrap();
            let segs = line.splitn(':', 1).collect::<~[&str]>();
            if segs.len() == 2 {
                let k = segs[0];
                let v = segs[1].trim();
                println!("HEADER {:?} => |{:?}|", k, v);
                headers.push((k.into_owned(), v.into_owned()));
            } else {
                println!("error spliting line {:?}", line);
                if [~"\r\n", ~"\n", ~""].contains(&line) {
                    break;
                }
                fail!("malformatted line");
            }
        }

        let mut chunked = false;
        for &(ref k, ref v) in headers.iter() {
            if k.to_ascii_lower() == ~"transfer-encoding" {
                if v.to_ascii_lower() == ~"chunked" {
                    chunked = true;
                }
                break;
            }
        }

        let mut length_opt = None;
        if !chunked {
            for &(ref k, ref v) in headers.iter() {
                if k.to_ascii_lower() == ~"content-length" {
                    length_opt = from_str::<uint>(*v);
                    break;
                }
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
    let url : Url = from_str(u).unwrap();


    let req = Request::new_with_url(url.clone());
    let mut h = HTTPHandler { debug: true };
    let mut resp = h.open(req);

    let mut s = ~"";

    match resp.read_to_str() {
        Ok(content) => {
            s = s + content;
            print!("| {}", content);
        }
        Err(_) =>
            ()
    }

    println!("\n=== result ===");
    println!("read bytes=> {}", s.len());
    println!("headers => {:?}", resp.headers);


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
