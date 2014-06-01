/*!
Compress library. wrapper from zlib.
 */

use libc::{c_char, c_int};
use std::vec::Vec;
use std::ptr;
use std::io;
use std::io::IoResult;
use std::mem;
use zlib;

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

/// for http gzip/deflate
pub struct GzipReader<R> {
    inner: R,
    zs: zlib::z_stream,
    buf: Vec<u8>,
    buf_len: uint,
    eof: bool,
}


impl<R:Reader> GzipReader<R> {
    pub fn new(r: R) -> GzipReader<R> {
        static cap : uint = 65536;
        let mut strm = unsafe { mem::zeroed::<zlib::z_stream>() };
        let ret = unsafe {
            zlib::inflateInit2_(&mut strm, 47, zlib::zlibVersion(), mem::size_of::<zlib::z_stream>() as i32)
        };
        assert_eq!(ret, Z_OK);
        let mut buf = Vec::with_capacity(cap);
        unsafe { buf.set_len(cap); }
        GzipReader { inner: r, zs: strm, buf: buf, buf_len: 0, eof: false }
    }
}

impl<R:Reader> Reader for GzipReader<R> {
     fn read(&mut self, buf: &mut [u8]) -> IoResult<uint> {
        let out_len = buf.len();
        let mut tbuf = Vec::from_elem(out_len, 0u8);
        let strm = &mut self.zs;

        if self.buf_len != 0 {
            strm.next_in = self.buf.as_mut_ptr() as *mut i8;
            strm.avail_in = self.buf_len as u32;
        } else {
           match self.inner.read(tbuf.as_mut_slice()) {
                Ok(n) if n > 0 => {
                    strm.next_in = tbuf.as_mut_ptr() as *mut i8;
                    strm.avail_in = n as u32;
                },
                Ok(0)          => return Ok(0),
                Err(e)         => {
                    if !self.eof && e.kind == io::EndOfFile {
                        assert_eq!(unsafe { zlib::inflateEnd(strm) }, Z_OK);
                        self.eof = true;
                    }
                    return Err(e);
                },
                _ => unreachable!()
            }
        }
        strm.next_out = unsafe { mem::transmute(&buf[0]) };
        strm.avail_out = out_len as u32;

        let ret = unsafe { zlib::inflate(strm, Z_NO_FLUSH) };
        let writen : uint = out_len - strm.avail_out as uint;

        if ret != Z_OK && ret != Z_STREAM_END { fail!("bad ret code: {}", ret) }

        if strm.avail_in != 0 { // out buf too small
            // strm.next_in will move to current ptr
            unsafe {
                ptr::copy_memory::<c_char>(mem::transmute(self.buf.as_mut_ptr()),
                                           mem::transmute(strm.next_in),
                                           strm.avail_in as uint);
            }
            self.buf_len = strm.avail_in as uint;
        } else {
            self.buf_len = 0;
        }

        Ok(writen)
    }
}

// duplicated code :(
pub struct GzipReaderWrapper<'a> {
    inner: &'a mut Buffer,
    zs: zlib::z_stream,
    buf: Vec<u8>,
    buf_len: uint,
    eof: bool,
}


impl<'a> GzipReaderWrapper<'a> {
    pub fn new(r: &'a mut Buffer) -> GzipReaderWrapper {
        static cap : uint = 65536;
        let mut strm = unsafe { mem::zeroed::<zlib::z_stream>() };
        let ret = unsafe {
            zlib::inflateInit2_(&mut strm, 47, zlib::zlibVersion(), mem::size_of::<zlib::z_stream>() as i32)
        };
        assert_eq!(ret, Z_OK);
        let mut buf = Vec::with_capacity(cap);
        unsafe { buf.set_len(cap); }
        GzipReaderWrapper { inner: r, // &mut r as &'a mut Reader,
                            zs: strm, buf: buf, buf_len: 0, eof: false }
    }
}

impl<'a> Reader for GzipReaderWrapper<'a> {
     fn read(&mut self, buf: &mut [u8]) -> IoResult<uint> {
        let out_len = buf.len();
        let mut tbuf = Vec::from_elem(out_len, 0u8);
        let strm = &mut self.zs;

        if self.buf_len != 0 {
            strm.next_in = self.buf.as_mut_ptr() as *mut i8;
            strm.avail_in = self.buf_len as u32;
        } else {
           match self.inner.read(tbuf.as_mut_slice()) {
                Ok(n) if n > 0 => {
                    strm.next_in = tbuf.as_mut_ptr() as *mut i8;
                    strm.avail_in = n as u32;
                },
                Ok(0)          => return Ok(0),
                Err(e)         => {
                    if !self.eof && e.kind == io::EndOfFile {
                        assert_eq!(unsafe { zlib::inflateEnd(strm) }, Z_OK);
                        self.eof = true;
                    }
                    return Err(e);
                },
                _ => unreachable!()
            }
        }
        strm.next_out = unsafe { mem::transmute(&buf[0]) };
        strm.avail_out = out_len as u32;

        let ret = unsafe { zlib::inflate(strm, Z_NO_FLUSH) };
        let writen : uint = out_len - strm.avail_out as uint;

        if ret != Z_OK && ret != Z_STREAM_END { fail!("bad ret code: {}", ret) }

        if strm.avail_in != 0 { // out buf too small
            // strm.next_in will move to current ptr
            unsafe {
                ptr::copy_memory::<c_char>(mem::transmute(self.buf.as_mut_ptr()),
                                           mem::transmute(strm.next_in),
                                           strm.avail_in as uint);
            }
            self.buf_len = strm.avail_in as uint;
        } else {
            self.buf_len = 0;
        }

        Ok(writen)
    }
}





#[cfg(test)]
mod test {
    use std::io;
    use super::GzipReader;

    #[test]
    fn test_gzip_reader() {
        let gz_file_content = ~[0x1f, 0x8b, 0x08, 0x08, 0x49, 0x06, 0x1a, 0x53, 0x00, 0x03,
                                0x66, 0x75, 0x63, 0x6b, 0x00, 0x4b, 0x2b, 0x4d, 0xce, 0xe6,
                                0x02, 0x00, 0x55, 0x0b, 0xfc, 0xa0, 0x05, 0x00, 0x00, 0x00];
        let src = io::BufReader::new(gz_file_content);
        let mut dst = GzipReader::new(src);
        assert_eq!(dst.read_to_str().unwrap(), "fuck\n".to_string());
    }

    #[test]
    fn test_gzip_reader_read_after_eof() {
        let gz_file_content = ~[0x1f, 0x8b, 0x08, 0x08, 0x49, 0x06, 0x1a, 0x53, 0x00, 0x03,
                                0x66, 0x75, 0x63, 0x6b, 0x00, 0x4b, 0x2b, 0x4d, 0xce, 0xe6,
                                0x02, 0x00, 0x55, 0x0b, 0xfc, 0xa0, 0x05, 0x00, 0x00, 0x00];
        let src = io::BufReader::new(gz_file_content);
        let mut dst = GzipReader::new(src);
        assert_eq!(dst.read_to_str().unwrap(), "fuck\n".to_string());
        assert_eq!(dst.read_to_str().unwrap(), "".to_string());
    }
}
