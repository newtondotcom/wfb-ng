use std::ptr;

use wfb_ng::zfex::{self, ZfexStatusCode};

struct AlignedBuffer {
    ptr: *mut u8,
    size: usize,
}

impl AlignedBuffer {
    fn new(size: usize) -> Self {
        let mut out: *mut libc::c_void = std::ptr::null_mut();
        let rc = unsafe { libc::posix_memalign(&mut out, zfex::ZFEX_SIMD_ALIGNMENT, size) };
        assert_eq!(rc, 0);
        Self {
            ptr: out as *mut u8,
            size,
        }
    }
}

impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        unsafe {
            libc::free(self.ptr as *mut _);
        }
    }
}

fn main() {
    println!("FEC acceleration: {}", zfex::ZFEX_OPT);
    let k = 8;
    let n = 12;
    let block_size = 4095usize;

    let fec = zfex::fec_new(k, n).expect("fec_new");
    let mut blocks: Vec<AlignedBuffer> = (0..n)
        .map(|_| {
            let size = (block_size + zfex::ZFEX_SIMD_ALIGNMENT - 1)
                & !(zfex::ZFEX_SIMD_ALIGNMENT - 1);
            AlignedBuffer::new(size)
        })
        .collect();

    for i in 0..k {
        unsafe {
            ptr::write_bytes(blocks[i].ptr, i as u8, block_size);
        }
    }

    let in_blocks: Vec<*const u8> = blocks.iter().take(k).map(|b| b.ptr).collect();
    let out_blocks: Vec<*mut u8> = blocks.iter().skip(k).map(|b| b.ptr).collect();
    let rc = zfex::fec_encode_simd(&fec, &in_blocks, &out_blocks, block_size);
    assert_eq!(rc, ZfexStatusCode::Ok);

    let mut block_dec_in: Vec<*const u8> = vec![ptr::null(); k];
    let mut block_dec_out: Vec<*mut u8> = Vec::new();
    let mut index: Vec<u32> = vec![0; k];

    for i in 0..k {
        if i < 2 * k - n {
            block_dec_in[i] = blocks[i].ptr;
            index[i] = i as u32;
        } else {
            block_dec_in[i] = blocks[i + n - k].ptr;
            index[i] = (i + n - k) as u32;
            block_dec_out.push(blocks[i].ptr);
            unsafe {
                ptr::write_bytes(blocks[i].ptr, 0, block_size);
            }
        }
    }

    let rc = zfex::fec_decode_simd(&fec, &mut block_dec_in, &block_dec_out, &mut index, block_size);
    assert_eq!(rc, ZfexStatusCode::Ok);

    for i in 0..k {
        for j in 0..block_size {
            let val = unsafe { *blocks[i].ptr.add(j) };
            assert_eq!(val, i as u8);
        }
    }
}

