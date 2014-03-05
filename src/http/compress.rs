#[feature(globs)];


use std::libc::{c_char, c_ulong, c_int};
use std::c_str::CString;
use std::cast;
use std::vec;
use std::str;
use std::io;
use std::io::IoResult;
use std::mem::{size_of, init};

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

        for ch in src.chunks(256) {
            strm.next_in = cast::transmute(&ch[0]);
            strm.avail_in = ch.len() as u32;
            strm.next_out = cast::transmute(&buf[0]);
            strm.avail_out = dst_len as u32;

            let ret = zlib::inflate(&mut strm, Z_NO_FLUSH);
            println!("inflate ret = {:?}", ret);
            println!("total_out => {:?}", strm.total_out);
            println!("avail_out => {:?}", strm.avail_out);
            assert_eq!(strm.avail_in, 0);
        }
            // if ret != 0 && ret != 1 { fail!("bad ret code: {}", ret) }
        let ret = zlib::inflateEnd(&mut strm);
        println!("ret = {}", ret);
        println!("total_out => {:?}", strm.total_out);
        println!("avail_out => {:?}", strm.avail_out);

        println!("debug => {:?}", strm);

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



pub struct GzipReader<R> {
    priv inner: R,
    priv zs: zlib::z_stream
}

impl<R:Reader> GzipReader<R> {
    pub fn new(r: R) -> GzipReader<R> {
        let mut strm = unsafe { init::<zlib::z_stream>() };
        let ret = unsafe {
            zlib::inflateInit2_(&mut strm, 47, zlib::zlibVersion(), size_of::<zlib::z_stream>() as i32)
        };
        assert_eq!(ret, 0);
        GzipReader { inner: r, zs: strm  }
    }
}

impl<R:Reader> Reader for GzipReader<R> {

     fn read(&mut self, buf: &mut [u8]) -> IoResult<uint> {
        let buf_len = buf.len();
        let mut tbuf = vec::from_elem(buf_len / 2, 0u8);
        let tbuf_len = buf_len / 2;
        let mut strm = &mut self.zs;
        match self.inner.read(tbuf) {
            Ok(n) if n > 0 => unsafe {
                strm.next_in = cast::transmute(&tbuf[0]);
                strm.avail_in = n as u32;
                strm.next_out = cast::transmute(&buf[0]);
                strm.avail_out = buf_len as u32;

                let ret = zlib::inflate(strm, Z_NO_FLUSH);
                println!("inflate ret = {:?}", ret);
                println!("total_out => {:?}", strm.total_out);
                println!("avail_out => {:?}", strm.avail_out);

                if ret != 0 && ret != 1 { fail!("bad ret code: {}", ret) }
                println!("ret = {}", ret);
                println!("debug => {:?}", strm);
                // TODO: handle this condition: if buf too small, this fails.
                assert_eq!(strm.avail_in, 0);
                let writen : uint = buf_len - strm.avail_out as uint; //
                Ok(writen)
            },
            Ok(_) => {
                Ok(0)
            }
            Err(e) => {
                if e.kind == io::EndOfFile {
                    Err(io::standard_error(io::EndOfFile))
                } else {
                    Err(e)
                }
            }
        }
    }
}
