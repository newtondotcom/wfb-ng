use std::ptr;
use std::sync::{Once, OnceLock};

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

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum SimdKind {
    None,
    Ssse3,
    Neon,
}

pub fn zfex_opt() -> &'static str {
    match simd_kind() {
        SimdKind::Ssse3 => "SSSE3",
        SimdKind::Neon => "NEON",
        SimdKind::None => "noaccel",
    }
}

#[derive(Clone)]
pub struct Fec {
    pub k: u16,
    pub n: u16,
    pub enc_matrix: Vec<Gf>,
}

static INIT: Once = Once::new();

#[repr(align(16))]
#[derive(Copy, Clone)]
struct Align16<T>(T);

static mut GF_EXP: [Gf; 510] = [0; 510];
static mut GF_LOG: [i32; 256] = [0; 256];
static mut INVERSE: [Gf; 256] = [0; 256];
static mut GF_MUL_TABLE: [Align16<[Gf; 256]>; 256] = [Align16([0; 256]); 256];
static mut GF_MUL_TABLE_16: [Align16<[Gf; 16]>; 256] = [Align16([0; 16]); 256];

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
            GF_MUL_TABLE[i].0[j] = GF_EXP[idx as usize];
        }
    }

    for j in 0..256 {
        GF_MUL_TABLE[0].0[j] = 0;
        GF_MUL_TABLE[j].0[0] = 0;
    }

    for i in 0..256 {
        for j in 0..16 {
            GF_MUL_TABLE_16[i].0[j] = GF_MUL_TABLE[i].0[j << 4];
        }
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
    GF_MUL_TABLE[x as usize].0[y as usize]
}

unsafe fn addmul_scalar(dst: *mut Gf, src: *const Gf, c: Gf, sz: usize) {
    if c == 0 {
        return;
    }
    for i in 0..sz {
        let val = gf_mul(*src.add(i), c);
        *dst.add(i) ^= val;
    }
}

fn simd_kind() -> SimdKind {
    static SIMD_KIND: OnceLock<SimdKind> = OnceLock::new();
    *SIMD_KIND.get_or_init(|| {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if std::arch::is_x86_feature_detected!("ssse3") {
                return SimdKind::Ssse3;
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            if std::arch::is_aarch64_feature_detected!("neon") {
                return SimdKind::Neon;
            }
        }
        #[cfg(target_arch = "arm")]
        {
            if std::arch::is_arm_feature_detected!("neon") {
                return SimdKind::Neon;
            }
        }
        SimdKind::None
    })
}

#[inline]
fn is_aligned(ptr: *const Gf) -> bool {
    (ptr as usize) % ZFEX_SIMD_ALIGNMENT == 0
}

unsafe fn addmul(dst: *mut Gf, src: *const Gf, c: Gf, sz: usize) {
    if c == 0 {
        return;
    }
    if sz >= ZFEX_SIMD_ALIGNMENT && is_aligned(dst) && is_aligned(src) {
        match simd_kind() {
            SimdKind::Ssse3 => {
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                unsafe {
                    addmul_ssse3(dst, src, c, sz);
                    return;
                }
            }
            SimdKind::Neon => {
                #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
                unsafe {
                    addmul_neon(dst, src, c, sz);
                    return;
                }
            }
            SimdKind::None => {}
        }
    }
    addmul_scalar(dst, src, c, sz);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "ssse3")]
unsafe fn addmul_ssse3(dst: *mut Gf, src: *const Gf, c: Gf, sz: usize) {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::*;

    let vmul_lo = _mm_load_si128(GF_MUL_TABLE[c as usize].0.as_ptr() as *const __m128i);
    let vmul_hi = _mm_load_si128(GF_MUL_TABLE_16[c as usize].0.as_ptr() as *const __m128i);
    let mask = _mm_set1_epi8(0x0f as i8);
    let mut i = 0usize;
    while i + 16 <= sz {
        let vsrc = _mm_load_si128(src.add(i) as *const __m128i);
        let vdst = _mm_load_si128(dst.add(i) as *const __m128i);
        let vsrc_lo = _mm_and_si128(vsrc, mask);
        let vsrc_hi = _mm_and_si128(_mm_srli_epi16(vsrc, 4), mask);
        let mul_lo = _mm_shuffle_epi8(vmul_lo, vsrc_lo);
        let mul_hi = _mm_shuffle_epi8(vmul_hi, vsrc_hi);
        let to_xor = _mm_xor_si128(mul_lo, mul_hi);
        _mm_store_si128(dst.add(i) as *mut __m128i, _mm_xor_si128(vdst, to_xor));
        i += 16;
    }
    if i < sz {
        addmul_scalar(dst.add(i), src.add(i), c, sz - i);
    }
}

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
#[target_feature(enable = "neon")]
unsafe fn addmul_neon(dst: *mut Gf, src: *const Gf, c: Gf, sz: usize) {
    #[cfg(target_arch = "aarch64")]
    use std::arch::aarch64::*;
    #[cfg(target_arch = "arm")]
    use std::arch::arm::*;

    let mask = vdupq_n_u8(0x0f);
    let vmul_lo = vld1q_u8(GF_MUL_TABLE[c as usize].0.as_ptr());
    let vmul_hi = vld1q_u8(GF_MUL_TABLE_16[c as usize].0.as_ptr());
    let mut i = 0usize;
    while i + 16 <= sz {
        let vsrc = vld1q_u8(src.add(i));
        let vdst = vld1q_u8(dst.add(i));
        let vsrc_lo = vandq_u8(vsrc, mask);
        let vsrc_hi = vshrq_n_u8(vsrc, 4);

        #[cfg(target_arch = "aarch64")]
        let to_xor = {
            let mul_lo = vqtbl1q_u8(vmul_lo, vsrc_lo);
            let mul_hi = vqtbl1q_u8(vmul_hi, vsrc_hi);
            veorq_u8(mul_lo, mul_hi)
        };

        #[cfg(target_arch = "arm")]
        let to_xor = {
            let tbl_lo = uint8x8x2_t {
                0: vget_low_u8(vmul_lo),
                1: vget_high_u8(vmul_lo),
            };
            let tbl_hi = uint8x8x2_t {
                0: vget_low_u8(vmul_hi),
                1: vget_high_u8(vmul_hi),
            };
            let lo_low = vtbl2_u8(tbl_lo, vget_low_u8(vsrc_lo));
            let lo_high = vtbl2_u8(tbl_lo, vget_high_u8(vsrc_lo));
            let hi_low = vtbl2_u8(tbl_hi, vget_low_u8(vsrc_hi));
            let hi_high = vtbl2_u8(tbl_hi, vget_high_u8(vsrc_hi));
            let low = veor_u8(lo_low, hi_low);
            let high = veor_u8(lo_high, hi_high);
            vcombine_u8(low, high)
        };

        let res = veorq_u8(vdst, to_xor);
        vst1q_u8(dst.add(i), res);
        i += 16;
    }
    if i < sz {
        addmul_scalar(dst.add(i), src.add(i), c, sz - i);
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

