# rust-http-helper

## A http client lib.

- Working in progress.
- Proof of concept.
- Code needs clean up.

## Support following:

- fundamental HTTP/1.0 HTTP/1.1 (partial)
- HTTP method: GET/POST/PUT ...
- HTTP headers (set/get)
- HTTP chunked transfer encoding
- simple HTTP CookieJar
- HTTP gzip/deflate content encoding (partial, WIP, via zlib)
- Opener + Handler structure, extensible (like python urllib2)

## What is missing

- keep-alive support
- multipart support
- https
- sdch support (no plan)
- redirect support
- cookie persistence
- timing
- logger
- ... and so on

## How to install

### build lib

    $ rustc src/http/lib.rs

### build test & run test

    $ rustc -L. --test src/http/test.rs
    $ rustc --test src/http/lib.rs
    $ ./test
    $ ./http
    $ ./http --bench

### build sample program & run

    $ rustc -L. src/http/main.rs
    $ ./main

## Simple Usage

```rust
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

    // // Support Following:
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
```
