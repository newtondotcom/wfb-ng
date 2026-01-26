use std::mem;
use std::ptr;
use std::sync::Once;

pub type Gf = u8;

pub const ZFEX_SIMD_ALIGNMENT: usize = 16;
pub const ZFEX_STRIDE: usize = 8192;

#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZfexStatusCode {
    Ok = 0,
    BadInputBlockAlignment = 1,
    BadOutputBlockAlignment = 2,
    NullPointerInput = 3,
    DecodeInvalidBlockIndex = 4,
}

pub const ZFEX_OPT: &str = "noaccel";

#[derive(Clone)]
pub struct Fec {
    pub k: u16,
    pub n: u16,
    pub enc_matrix: Vec<Gf>,
}

static INIT: Once = Once::new();

static mut GF_EXP: [Gf; 510] = [0; 510];
static mut GF_LOG: [i32; 256] = [0; 256];
static mut INVERSE: [Gf; 256] = [0; 256];
static mut GF_MUL_TABLE: [[Gf; 256]; 256] = [[0; 256]; 256];

fn init_fec() {
    INIT.call_once(|| unsafe {
        generate_gf();
        init_mul_table();
    });
}

#[inline]
fn modnn(mut x: i32) -> Gf {
    while x >= 255 {
        x -= 255;
        x = (x >> 8) + (x & 255);
    }
    x as Gf
}

unsafe fn init_mul_table() {
    for i in 0..256 {
        for j in 0..256 {
            let idx = modnn(GF_LOG[i] + GF_LOG[j]);
            GF_MUL_TABLE[i][j] = GF_EXP[idx as usize];
        }
    }

    for j in 0..256 {
        GF_MUL_TABLE[0][j] = 0;
        GF_MUL_TABLE[j][0] = 0;
    }
}

unsafe fn generate_gf() {
    let pp = b"101110001";
    let mut mask: Gf = 1;
    GF_EXP[8] = 0;
    for i in 0..8 {
        GF_EXP[i] = mask;
        GF_LOG[GF_EXP[i] as usize] = i as i32;
        if pp[i] == b'1' {
            GF_EXP[8] ^= mask;
        }
        mask <<= 1;
    }

    GF_LOG[GF_EXP[8] as usize] = 8;
    mask = 1 << 7;
    for i in 9..255 {
        if GF_EXP[i - 1] >= mask {
            GF_EXP[i] = GF_EXP[8] ^ ((GF_EXP[i - 1] ^ mask) << 1);
        } else {
            GF_EXP[i] = GF_EXP[i - 1] << 1;
        }
        GF_LOG[GF_EXP[i] as usize] = i as i32;
    }

    GF_LOG[0] = 255;
    for i in 0..255 {
        GF_EXP[i + 255] = GF_EXP[i];
    }

    INVERSE[0] = 0;
    INVERSE[1] = 1;
    for i in 2..=255 {
        let idx = 255 - GF_LOG[i] as usize;
        INVERSE[i] = GF_EXP[idx];
    }
}

#[inline]
unsafe fn gf_mul(x: Gf, y: Gf) -> Gf {
    GF_MUL_TABLE[x as usize][y as usize]
}

unsafe fn addmul(dst: *mut Gf, src: *const Gf, c: Gf, sz: usize) {
    if c == 0 {
        return;
    }
    for i in 0..sz {
        let val = gf_mul(*src.add(i), c);
        *dst.add(i) ^= val;
    }
}

unsafe fn matmul(src: *const Gf, b: *const Gf, c: *mut Gf, rows: u16, cols: u16, n: u16) {
    for row in 0..rows {
        for col in 0..cols {
            let mut acc: Gf = 0;
            for k in 0..n {
                let a = *src.add((row as usize) * (n as usize) + k as usize);
                let bval = *b.add((k as usize) * (cols as usize) + col as usize);
                acc ^= gf_mul(a, bval);
            }
            *c.add((row as usize) * (cols as usize) + col as usize) = acc;
        }
    }
}

unsafe fn invert_mat(src: *mut Gf, k: u16) {
    let k_usize = k as usize;
    let mut tmp = vec![0u8; k_usize * k_usize];
    let mut dst = vec![0u8; k_usize * k_usize];

    for i in 0..k_usize {
        for j in 0..k_usize {
            tmp[i * k_usize + j] = *src.add(i * k_usize + j);
            dst[i * k_usize + j] = if i == j { 1 } else { 0 };
        }
    }

    for i in 0..k_usize {
        if tmp[i * k_usize + i] == 0 {
            for j in (i + 1)..k_usize {
                if tmp[j * k_usize + i] != 0 {
                    for col in 0..k_usize {
                        tmp.swap(i * k_usize + col, j * k_usize + col);
                        dst.swap(i * k_usize + col, j * k_usize + col);
                    }
                    break;
                }
            }
        }

        let pivot = tmp[i * k_usize + i];
        if pivot != 1 {
            let inv = INVERSE[pivot as usize];
            for col in 0..k_usize {
                tmp[i * k_usize + col] = gf_mul(tmp[i * k_usize + col], inv);
                dst[i * k_usize + col] = gf_mul(dst[i * k_usize + col], inv);
            }
        }

        for row in 0..k_usize {
            if row == i {
                continue;
            }
            let c = tmp[row * k_usize + i];
            if c != 0 {
                for col in 0..k_usize {
                    tmp[row * k_usize + col] ^= gf_mul(c, tmp[i * k_usize + col]);
                    dst[row * k_usize + col] ^= gf_mul(c, dst[i * k_usize + col]);
                }
            }
        }
    }

    for i in 0..(k_usize * k_usize) {
        *src.add(i) = dst[i];
    }
}

unsafe fn invert_vdm(src: *mut Gf, k: u16) {
    if k == 1 {
        return;
    }

    let mut c = vec![0u8; k as usize];
    let mut b = vec![0u8; k as usize];
    let mut p = vec![0u8; k as usize];

    for i in 0..k as usize {
        c[i] = 0;
        p[i] = *src.add(1 + i * k as usize);
    }

    c[k as usize - 1] = p[0];
    for i in 1..k as usize {
        let p_i = p[i];
        for j in (k as usize - 1 - (i - 1))..(k as usize - 1) {
            c[j] ^= gf_mul(p_i, c[j + 1]);
        }
        c[k as usize - 1] ^= p_i;
    }

    for row in 0..k as usize {
        let xx = p[row];
        let mut t: Gf = 1;
        b[k as usize - 1] = 1;
        for i in (1..k as usize).rev() {
            b[i - 1] = c[i] ^ gf_mul(xx, b[i]);
            t = gf_mul(xx, t) ^ b[i - 1];
        }
        for col in 0..k as usize {
            *src.add(col * k as usize + row) = gf_mul(INVERSE[t as usize], b[col]);
        }
    }
}

pub fn fec_new(k: u16, n: u16) -> Result<Fec, ZfexStatusCode> {
    if k == 0 || n == 0 || n >= 256 || k > n {
        return Err(ZfexStatusCode::NullPointerInput);
    }
    init_fec();

    let mut enc_matrix = vec![0u8; (n as usize) * (k as usize)];
    let mut tmp_m = vec![0u8; (n as usize) * (k as usize)];

    tmp_m[0] = 1;
    for col in 1..k as usize {
        tmp_m[col] = 0;
    }
    for row in 0..(n - 1) {
        let base = (row as usize + 1) * k as usize;
        for col in 0..k as usize {
            let idx = modnn((row as i32) * (col as i32));
            unsafe {
                tmp_m[base + col] = GF_EXP[idx as usize];
            }
        }
    }

    unsafe {
        invert_vdm(tmp_m.as_mut_ptr(), k);
        matmul(
            tmp_m.as_ptr().add((k as usize) * (k as usize)),
            tmp_m.as_ptr(),
            enc_matrix.as_mut_ptr().add((k as usize) * (k as usize)),
            n - k,
            k,
            k,
        );
    }

    for i in 0..(k as usize * k as usize) {
        enc_matrix[i] = 0;
    }
    for col in 0..k as usize {
        enc_matrix[col * k as usize + col] = 1;
    }

    Ok(Fec { k, n, enc_matrix })
}

pub fn fec_free(_fec: Fec) -> ZfexStatusCode {
    ZfexStatusCode::Ok
}

pub fn fec_encode_simd(
    code: &Fec,
    inpkts: &[*const Gf],
    fecs: &[*mut Gf],
    sz: usize,
) -> ZfexStatusCode {
    for ix in 0..code.k as usize {
        if (inpkts[ix] as usize) % ZFEX_SIMD_ALIGNMENT != 0 {
            return ZfexStatusCode::BadInputBlockAlignment;
        }
    }
    for ix in 0..(code.n - code.k) as usize {
        if (fecs[ix] as usize) % ZFEX_SIMD_ALIGNMENT != 0 {
            return ZfexStatusCode::BadOutputBlockAlignment;
        }
    }

    let k = code.k as usize;
    let n = code.n as usize;
    for offset in (0..sz).step_by(ZFEX_STRIDE) {
        let stride = if sz - offset < ZFEX_STRIDE {
            sz - offset
        } else {
            ZFEX_STRIDE
        };

        for i in 0..(n - k) {
            let fecnum = i + k;
            unsafe {
                ptr::write_bytes(fecs[i].add(offset), 0, stride);
                let p = code.enc_matrix.as_ptr().add(fecnum * k);
                for j in 0..k {
                    addmul(
                        fecs[i].add(offset),
                        inpkts[j].add(offset),
                        *p.add(j),
                        stride,
                    );
                }
            }
        }
    }

    ZfexStatusCode::Ok
}

fn shuffle(pkt: &mut [*const Gf], index: &mut [u32], k: usize) -> ZfexStatusCode {
    let mut i = 0;
    while i < k {
        if index[i] >= k as u32 || index[i] == i as u32 {
            i += 1;
        } else {
            let c = index[i] as usize;
            if index[c] == c as u32 {
                return ZfexStatusCode::DecodeInvalidBlockIndex;
            }
            index.swap(i, c);
            pkt.swap(i, c);
        }
    }
    ZfexStatusCode::Ok
}

fn build_decode_matrix_into_space(code: &Fec, index: &[u32], k: u16, matrix: &mut [Gf]) {
    let k_usize = k as usize;
    for i in 0..k_usize {
        let row = &mut matrix[i * k_usize..(i + 1) * k_usize];
        if index[i] < k as u32 {
            row.fill(0);
            row[i] = 1;
        } else {
            let src = &code.enc_matrix[(index[i] as usize) * k_usize..(index[i] as usize + 1) * k_usize];
            row.copy_from_slice(src);
        }
    }
    unsafe {
        invert_mat(matrix.as_mut_ptr(), k);
    }
}

pub fn fec_decode_simd(
    code: &Fec,
    inpkts: &mut [*const Gf],
    outpkts: &[*mut Gf],
    index: &mut [u32],
    sz: usize,
) -> ZfexStatusCode {
    let k = code.k as usize;
    let shuffle_rc = shuffle(inpkts, index, k);
    if shuffle_rc != ZfexStatusCode::Ok {
        return shuffle_rc;
    }

    let mut m_dec = vec![0u8; k * k];
    build_decode_matrix_into_space(code, index, code.k, &mut m_dec);

    for col in 0..k {
        if (inpkts[col] as usize) % ZFEX_SIMD_ALIGNMENT != 0 {
            return ZfexStatusCode::BadInputBlockAlignment;
        }
    }

    let mut outix = 0;
    for row in 0..k {
        if index[row] >= code.k as u32 {
            if (outpkts[outix] as usize) % ZFEX_SIMD_ALIGNMENT != 0 {
                return ZfexStatusCode::BadOutputBlockAlignment;
            }
            unsafe {
                ptr::write_bytes(outpkts[outix], 0, sz);
                for col in 0..k {
                    addmul(
                        outpkts[outix],
                        inpkts[col],
                        m_dec[row * k + col],
                        sz,
                    );
                }
            }
            outix += 1;
        }
    }

    ZfexStatusCode::Ok
}

