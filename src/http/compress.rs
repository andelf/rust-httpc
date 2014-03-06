#[feature(globs)];


use std::libc::{c_char, c_ulong, c_int};
use std::c_str::CString;
use std::cast;
use std::vec;
use std::str;
use std::ptr;
use std::io;
use std::io::IoResult;
use std::mem::{size_of, init};
use std::intrinsics;

use zlib;
mod zlib;


static Z_OK           : c_int = 0;
static Z_STREAM_END   : c_int = 1;
static Z_NEED_DICT    : c_int = 2;
static Z_ERRNO        : c_int = -1;
static Z_STREAM_ERROR : c_int = -2;
static Z_DATA_ERROR   : c_int = -3;
static Z_MEM_ERROR    : c_int = -4;
static Z_BUF_ERROR    : c_int = -5;
static Z_VERSION_ERROR : c_int = -6;


/*
#define Z_NO_FLUSH      0
#define Z_PARTIAL_FLUSH 1
#define Z_SYNC_FLUSH    2
#define Z_FULL_FLUSH    3
#define Z_FINISH        4
#define Z_BLOCK         5
#define Z_TREES         6
*/

static Z_NO_FLUSH : c_int = 0;

pub fn uncompress(src: &[u8]) -> Option<~[u8]> {
    let src = src.clone();      // to owned
    let mut buf = [0u8, ..65535];
    let dst_len = 65535 as c_ulong;

    let mut strm = unsafe { init::<zlib::z_stream>() };

    unsafe {
        let ver = zlib::zlibVersion();
        let ret = zlib::inflateInit2_(&mut strm, 47, ver, size_of::<zlib::z_stream>() as i32);
        assert_eq!(ret, Z_OK);
        for ch in src.chunks(256) { // chunks to test how zlib treat multiple chunk
            strm.next_in = cast::transmute(&ch[0]);
            strm.avail_in = ch.len() as u32;
            strm.next_out = cast::transmute(&buf[0]);
            strm.avail_out = dst_len as u32;

            let ret = zlib::inflate(&mut strm, Z_NO_FLUSH);
            if ret != 0 && ret != 1 { fail!("bad ret code: {}", ret) }
        }
        zlib::inflateEnd(&mut strm);

    }

    let mut ret = vec::from_elem(strm.total_out as uint, 0u8);
    unsafe { ret.copy_memory(buf.slice(0, strm.total_out as uint)) };
    Some(ret)
}

fn main() {
    unsafe {
        let ver = zlib::zlibVersion();
        let mut strm = init::<zlib::z_stream>();
        let ret = zlib::inflateInit2_(&mut strm, 47, ver, size_of::<zlib::z_stream>() as i32);

        println!("ret = {:?}", ret);

        println!("version = {:?}", CString::new(zlib::zlibVersion(), false).as_str());
    }
    uncompress(bytes!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
}




// for http gzip/deflate
pub struct GzipReader<R> {
    priv inner: R,
    priv zs: zlib::z_stream,
    priv buf: ~[u8],
    priv buf_len: uint,
}


impl<R:Reader> GzipReader<R> {
    pub fn new(r: R) -> GzipReader<R> {
        static cap : uint = 65536;
        let mut strm = unsafe { init::<zlib::z_stream>() };
        let ret = unsafe {
            zlib::inflateInit2_(&mut strm, 47, zlib::zlibVersion(), size_of::<zlib::z_stream>() as i32)
        };
        assert_eq!(ret, Z_OK);
        let mut buf = vec::with_capacity(cap);
        unsafe { buf.set_len(cap); }
        GzipReader { inner: r, zs: strm, buf: buf, buf_len: 0 }
    }
}

impl<R:Reader> Reader for GzipReader<R> {
     fn read(&mut self, buf: &mut [u8]) -> IoResult<uint> {
        let out_len = buf.len();
        let mut tbuf = vec::from_elem(out_len, 0u8);
        let mut strm = &mut self.zs;

        if self.buf_len != 0 {
            strm.next_in = unsafe { cast::transmute(&self.buf[0]) };
            strm.avail_in = self.buf_len as u32;
        } else {
           match self.inner.read(tbuf) {
                Ok(n) if n > 0 => unsafe {
                    strm.next_in = cast::transmute(&tbuf[0]);
                    strm.avail_in = n as u32;
                },
                Ok(0)          => return Ok(0),
                Err(e)         => {
                    if e.kind == io::EndOfFile {
                        assert_eq!(unsafe { zlib::inflateEnd(strm) }, Z_OK);
                    }
                    return Err(e);
                },
                _ => unreachable!()
            }
        }
        strm.next_out = unsafe { cast::transmute(&buf[0]) };
        strm.avail_out = out_len as u32;

        let ret = unsafe { zlib::inflate(strm, Z_NO_FLUSH) };
        let writen : uint = out_len - strm.avail_out as uint;

        if ret != Z_OK && ret != Z_STREAM_END { fail!("bad ret code: {}", ret) }

        if strm.avail_in != 0 { // out buf too small
            // strm.next_in will move to current ptr
            unsafe {
                ptr::copy_memory::<c_char>(cast::transmute(&self.buf[0]),
                                           cast::transmute(strm.next_in),
                                           strm.avail_in as uint);
            }
            self.buf_len = strm.avail_in as uint;
        } else {
            self.buf_len = 0;
        }

        Ok(writen)
    }
}
