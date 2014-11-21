extern crate time;

use std::str::FromStr;
use std::fmt::{Show, Formatter, Result};
use time::{Tm, now_utc, strptime, strftime};
use std::ascii::AsciiExt;

// TODO: how to express not provided in header line
// TODO: handle port
#[deriving(PartialEq, Clone)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub comment: Option<String>,
    pub secure: bool,
    pub http_only: bool,
    pub version: int,
    pub created: Tm,
    pub expires: Option<Tm>,
}

impl Cookie {
    pub fn new_with_name_value(name: &str, value: &str) -> Cookie {
        Cookie { name: name.into_string(), value: value.into_string(),
                 domain: None, path: None, comment: None,
                 secure: false, http_only: false,
                 version: 0, created: now_utc(),
                 expires: None }
    }
}

impl Cookie {
    pub fn to_header(&self) -> String {
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
        write!(f, "{}={}", self.name, self.value);
        if !self.expires.is_none() {
            write!(f, "; expires={}",
                   strftime("%a, %d-%b-%Y %H:%M:%S %Z", &self.expires.clone().unwrap()));
        }
        if !self.path.is_none() {
            write!(f, "; path={}", self.path.clone().unwrap());
        }
        if !self.domain.is_none() {
            write!(f, "; domain={}", self.domain.clone().unwrap());
        }
        if self.http_only {
            write!(f, "; HttpOnly");
        }
        Ok(())
    }
}


impl FromStr for Cookie {
    fn from_str(s: &str) -> Option<Cookie> {
        let mut segs = s.split(';');
        let kv = segs.next().unwrap().splitn(1, '=').collect::<Vec<&str>>();
        let name = kv[0].trim();
        let value = kv[1].trim();
        let mut ck = Cookie::new_with_name_value(name, value);
        for seg in segs.collect::<Vec<&str>>().iter() {
            if seg.find('=').is_some() {
                let kv = seg.trim().splitn(1, '=').collect::<Vec<&str>>();
                match kv[0].to_ascii_lower().as_slice() {
                    // TODO: GMT vs UTC
                    "expires" => {
                        ck.expires = match strptime(kv[1].as_slice(), "%a, %d-%b-%y %H:%M:%S %Z") {
                            Ok(tm) => { // 2-digits year format is buggy
                                let mut tm = tm;
                                if tm.tm_year < 1950 {
                                    tm.tm_year += 100
                                }
                                Some(tm)
                            }
                            Err(_) => match strptime(kv[1].as_slice(), "%a, %d-%b-%Y %H:%M:%S %Z") {
                                Err(_) => None,
                                Ok(tm) => Some(tm)
                            },

                        }
                    }
                    // max-age may override expires with a bigger val
                    "max-age" => {
                        let age : i64 = from_str(kv[1].as_slice()).unwrap();
                        let mut ts = time::get_time();
                        ts.sec += age;
                        let tm = time::at_utc(ts);
                        ck.expires = Some(tm)
                    }
                    "path"    => { ck.path = Some(kv[1].into_string()) }
                    "domain"  => { ck.domain = Some(kv[1].into_string()) }
                    "version" => (),
                    _ => { println!("unknown kv => {:}", kv); }
                }
            } else {
                match seg.trim().to_ascii_lower().as_slice() {
                    "secure" => { ck.secure = true }
                    "httponly" => { ck.http_only = true }
                    _ => { println!("bad http cookie seg {:}", seg) }
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
        assert_eq!(ck.to_header(), "ASPSESSIONIDQARTTCBD=JOACNNHAPHHFCFPGOFILBMJF".to_string());
        assert_eq!(ck.path, Some("/".to_string()));
    }

    #[test]
    fn test_cookie_parse_normal() {
        let header = "BAIDUID=1AC4B89822952E9611807601CBC7FED4:FG=1; expires=Thu, 31-Dec-37 23:55:55 GMT; max-age=2147483647; path=/; domain=.baidu.com";
        let ck_opt = from_str::<Cookie>(header);
        assert!(ck_opt.is_some());
        let ck = ck_opt.unwrap();
        assert_eq!(ck.to_header(), "BAIDUID=1AC4B89822952E9611807601CBC7FED4:FG=1".to_string());
        assert!(!ck.is_expired());
    }
}
