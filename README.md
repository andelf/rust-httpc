# rust-httpc

[![Build Status](https://travis-ci.org/andelf/rust-httpc.svg?branch=master)](https://travis-ci.org/andelf/rust-httpc)

## An http client lib.

- Working in progress.
- Proof of concept.
- Code needs clean up.

## Support following:

- Fundamental HTTP/1.0 HTTP/1.1 (partial)
- HTTP method: GET/POST/PUT ...
- HTTP headers (set/get)
- HTTP chunked transfer encoding
- Simple HTTP CookieJar
- HTTP gzip/deflate content encoding (partial, via zlib, working in progress)
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

    $ rustc src/httpc/lib.rs

### build test & run test

    $ rustc --test src/httpc/lib.rs
    $ ./httpc

### build sample program & run

    $ rustc -L. src/examples/{main,test,...}.rs
    $ ./main

## Simple Usage

```rust
#[feature(globs)];

extern crate httpc;
use httpc::*;

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
