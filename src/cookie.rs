extern crate time;

use std::from_str::FromStr;
use std::fmt::{Show, Formatter, Result};
use time::{Tm, now_utc, strptime, strftime};

use std::ascii::StrAsciiExt;

// TODO: how to express not provided in header line
// TODO: handle port
#[deriving(Eq, Clone)]
pub struct Cookie {
    name: ~str,
    value: ~str,
    domain: Option<~str>,
    path: Option<~str>,
    comment: Option<~str>,
    secure: bool,
    http_only: bool,
    version: int,
    created: Tm,
    expires: Option<Tm>,
}

impl Cookie {
    pub fn new_with_name_value(name: &str, value: &str) -> Cookie {
        Cookie { name: name.into_owned(), value: value.into_owned(),
                 domain: None, path: None, comment: None,
                 secure: false, http_only: false,
                 version: 0, created: now_utc(),
                 expires: None }
    }
}

impl Cookie {
    pub fn to_header(&self) -> ~str {
        format!("{}={}", self.name, self.value)
    }

    pub fn is_expired(&self) -> bool {
        let now = now_utc();
        let expires = self.expires.clone();
        //self.expires.is_some() ||
        // None return false
        expires.map_or(now.to_timespec(), |tm| tm.to_timespec()) < now.to_timespec()
    }

}



impl Show for Cookie {
    fn fmt(&self, f: &mut Formatter) -> Result {
        f.buf.write_str(format!("{}={}", self.name, self.value));
        if !self.expires.is_none() {
            f.buf.write_str(format!("; expires={}",
                                    strftime("%a, %d-%b-%Y %H:%M:%S %Z", &self.expires.clone().unwrap())));
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
                            Ok(tm) => { // 2-digits year format is buggy
                                let mut tm = tm;
                                if tm.tm_year < 1950 {
                                    tm.tm_year += 100
                                }
                                Some(tm)
                            }
                            Err(_) => match strptime(kv[1], "%a, %d-%b-%Y %H:%M:%S %Z") {
                                Err(_) => None,
                                Ok(tm) => Some(tm)
                            },

                        }
                    }
                    // max-age may override expires with a bigger val
                    ~"max-age" => {
                        let age : i64 = from_str(kv[1]).unwrap();
                        let mut ts = time::get_time();
                        ts.sec += age;
                        let tm = time::at_utc(ts);
                        ck.expires = Some(tm)
                    }
                    ~"path"    => { ck.path = Some(kv[1].into_owned()) }
                    ~"domain"  => { ck.domain = Some(kv[1].into_owned()) }
                    ~"version" => (),
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_cookie_parse_simple() {
        let header = "ASPSESSIONIDQARTTCBD=JOACNNHAPHHFCFPGOFILBMJF; path=/";
        let ck_opt = from_str::<Cookie>(header);
        assert!(ck_opt.is_some());
        let ck = ck_opt.unwrap();
        assert_eq!(ck.to_header(), ~"ASPSESSIONIDQARTTCBD=JOACNNHAPHHFCFPGOFILBMJF");
        assert_eq!(ck.path, Some(~"/"));
    }

    #[test]
    fn test_cookie_parse_normal() {
        let header = "BAIDUID=1AC4B89822952E9611807601CBC7FED4:FG=1; expires=Thu, 31-Dec-37 23:55:55 GMT; max-age=2147483647; path=/; domain=.baidu.com";
        let ck_opt = from_str::<Cookie>(header);
        assert!(ck_opt.is_some());
        let ck = ck_opt.unwrap();
        assert_eq!(ck.to_header(), ~"BAIDUID=1AC4B89822952E9611807601CBC7FED4:FG=1");
        assert!(!ck.is_expired());
    }
}
