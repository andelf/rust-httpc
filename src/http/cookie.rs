extern crate time;

use std::from_str::FromStr;
use std::fmt::{Show, Formatter, Result};
use time::{Tm, now_utc, strptime, strftime};

use std::ascii::StrAsciiExt;

pub struct Cookie {
    name: ~str,
    value: ~str,
    domain: Option<~str>,
    path: Option<~str>,
    comment: Option<~str>,
    secure: bool,
    http_only: bool,
    version: int,
    max_age: int,
    created: Tm,
    expires: Option<Tm>,
}

#[deriving(Eq)]
impl Cookie {
    pub fn new_with_name_value(name: &str, value: &str) -> Cookie {
        Cookie { name: name.into_owned(), value: value.into_owned(),
                 domain: None, path: None, comment: None,
                 secure: false, http_only: false,
                 version: 0, max_age: 0, created: now_utc(),
                 expires: None }
    }
}


impl Cookie {
    fn to_header(&self) -> ~str {
        format!("{}={}", self.name, self.value)
    }
}



impl Show for Cookie {
    fn fmt(&self, f: &mut Formatter) -> Result {
        f.buf.write_str(format!("{}={}", self.name, self.value));
        if !self.expires.is_none() {
            f.buf.write_str(format!("; expires={}",
                                 strftime("%a, %d-%b-%y %H:%M:%S %Z", &self.expires.clone().unwrap())));
        }
        if !self.path.is_none() {
            f.buf.write_str(format!("; path={}", self.path.clone().unwrap()));
        }
        if !self.domain.is_none() {
            f.buf.write_str(format!("; domain={}", self.domain.clone().unwrap()));
        }
        if self.http_only {
            f.buf.write_str("; HttpOnly");
        }
        Ok(())
    }
}


impl FromStr for Cookie {
    fn from_str(s: &str) -> Option<Cookie> {
        let mut segs = s.split(';');
        let kv = segs.next().unwrap().splitn('=', 1).collect::<~[&str]>();
        let name = kv[0];
        let value = kv[1];
        let mut ck = Cookie::new_with_name_value(name, value);
        for seg in segs.collect::<~[&str]>().iter() {
            if seg.find('=').is_some() {
                let kv = seg.trim().splitn('=', 1).collect::<~[&str]>();
                match kv[0].to_ascii_lower() {
                    // TODO: GMT vs UTC
                    ~"expires" => {
                        ck.expires = match strptime(kv[1], "%a, %d-%b-%y %H:%M:%S %Z") {
                            Err(_) => match strptime(kv[1], "%a, %d-%b-%Y %H:%M:%S %Z") {
                                Err(_) => None,
                                Ok(tm) => Some(tm)
                            },
                            Ok(tm) => Some(tm)
                        }
                    }
                    ~"max-age" => { ck.max_age = from_str(kv[1]).unwrap() }
                    ~"path"    => { ck.path = Some(kv[1].into_owned()) }
                    ~"domain"  => { ck.domain = Some(kv[1].into_owned()) }
                    _ => { println!("unknown kv => {:?}", kv); }
                }
            } else {
                match seg.trim().to_ascii_lower() {
                    ~"secure" => { ck.secure = true }
                    ~"httponly" => { ck.http_only = true }
                    _ => { println!("bad http cookie seg {:?}", seg) }
                }
            }
        }
        Some(ck)
    }
}



fn main() {
    let expires = ~"Thu, 31-Dec-37 23:55:55 GMT";
    let t = strptime(expires, "%a, %d-%b-%y %H:%M:%S %Z");
    println!("tm = {:?}", t);
    println!("=> {:?}", time::strftime("%a, %d-%b-%y %H:%M:%S %Z", &now_utc()));
    let c = "BAIDUID=1AC4B89822952E9611807601CBC7FED4:FG=1; expires=Thu, 31-Dec-37 23:55:55 GMT; max-age=2147483647; path=/; domain=.baidu.com";
    println!("got ck {:?}", from_str::<Cookie>(c).to_str());
}
