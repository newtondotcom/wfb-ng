use std::mem;
use std::ptr;

use libc;

pub const IEEE80211_RADIOTAP_TSFT: i32 = 0;
pub const IEEE80211_RADIOTAP_FLAGS: i32 = 1;
pub const IEEE80211_RADIOTAP_RATE: i32 = 2;
pub const IEEE80211_RADIOTAP_CHANNEL: i32 = 3;
pub const IEEE80211_RADIOTAP_FHSS: i32 = 4;
pub const IEEE80211_RADIOTAP_DBM_ANTSIGNAL: i32 = 5;
pub const IEEE80211_RADIOTAP_DBM_ANTNOISE: i32 = 6;
pub const IEEE80211_RADIOTAP_LOCK_QUALITY: i32 = 7;
pub const IEEE80211_RADIOTAP_TX_ATTENUATION: i32 = 8;
pub const IEEE80211_RADIOTAP_DB_TX_ATTENUATION: i32 = 9;
pub const IEEE80211_RADIOTAP_DBM_TX_POWER: i32 = 10;
pub const IEEE80211_RADIOTAP_ANTENNA: i32 = 11;
pub const IEEE80211_RADIOTAP_DB_ANTSIGNAL: i32 = 12;
pub const IEEE80211_RADIOTAP_DB_ANTNOISE: i32 = 13;
pub const IEEE80211_RADIOTAP_RX_FLAGS: i32 = 14;
pub const IEEE80211_RADIOTAP_TX_FLAGS: i32 = 15;
pub const IEEE80211_RADIOTAP_RTS_RETRIES: i32 = 16;
pub const IEEE80211_RADIOTAP_DATA_RETRIES: i32 = 17;
pub const IEEE80211_RADIOTAP_MCS: i32 = 19;
pub const IEEE80211_RADIOTAP_AMPDU_STATUS: i32 = 20;
pub const IEEE80211_RADIOTAP_VHT: i32 = 21;
pub const IEEE80211_RADIOTAP_TIMESTAMP: i32 = 22;
pub const IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE: i32 = 29;
pub const IEEE80211_RADIOTAP_VENDOR_NAMESPACE: i32 = 30;
pub const IEEE80211_RADIOTAP_EXT: i32 = 31;

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ieee80211RadiotapHeader {
    pub it_version: u8,
    pub it_pad: u8,
    pub it_len: u16,
    pub it_present: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RadiotapAlignSize {
    pub align: u8,
    pub size: u8,
}

#[repr(C)]
pub struct Ieee80211RadiotapNamespace {
    pub align_size: *const RadiotapAlignSize,
    pub n_bits: i32,
    pub oui: u32,
    pub subns: u8,
}

unsafe impl Sync for Ieee80211RadiotapNamespace {}

#[repr(C)]
pub struct Ieee80211RadiotapVendorNamespaces {
    pub ns: *const Ieee80211RadiotapNamespace,
    pub n_ns: i32,
}

#[repr(C)]
pub struct Ieee80211RadiotapIterator {
    pub _rtheader: *mut Ieee80211RadiotapHeader,
    pub _vns: *const Ieee80211RadiotapVendorNamespaces,
    pub current_namespace: *const Ieee80211RadiotapNamespace,

    pub _arg: *mut u8,
    pub _next_ns_data: *mut u8,
    pub _next_bitmap: *mut u32,

    pub this_arg: *mut u8,
    pub this_arg_index: i32,
    pub this_arg_size: i32,

    pub is_radiotap_ns: i32,

    pub _max_length: i32,
    pub _arg_index: i32,
    pub _bitmap_shifter: u32,
    pub _reset_on_ext: i32,
}

const RTAP_NAMESPACE_SIZES: [RadiotapAlignSize; 23] = [
    RadiotapAlignSize { align: 8, size: 8 }, // TSFT
    RadiotapAlignSize { align: 1, size: 1 }, // FLAGS
    RadiotapAlignSize { align: 1, size: 1 }, // RATE
    RadiotapAlignSize { align: 2, size: 4 }, // CHANNEL
    RadiotapAlignSize { align: 2, size: 2 }, // FHSS
    RadiotapAlignSize { align: 1, size: 1 }, // DBM_ANTSIGNAL
    RadiotapAlignSize { align: 1, size: 1 }, // DBM_ANTNOISE
    RadiotapAlignSize { align: 2, size: 2 }, // LOCK_QUALITY
    RadiotapAlignSize { align: 2, size: 2 }, // TX_ATTENUATION
    RadiotapAlignSize { align: 2, size: 2 }, // DB_TX_ATTENUATION
    RadiotapAlignSize { align: 1, size: 1 }, // DBM_TX_POWER
    RadiotapAlignSize { align: 1, size: 1 }, // ANTENNA
    RadiotapAlignSize { align: 1, size: 1 }, // DB_ANTSIGNAL
    RadiotapAlignSize { align: 1, size: 1 }, // DB_ANTNOISE
    RadiotapAlignSize { align: 2, size: 2 }, // RX_FLAGS
    RadiotapAlignSize { align: 2, size: 2 }, // TX_FLAGS
    RadiotapAlignSize { align: 1, size: 1 }, // RTS_RETRIES
    RadiotapAlignSize { align: 1, size: 1 }, // DATA_RETRIES
    RadiotapAlignSize { align: 0, size: 0 }, // index 18 unused
    RadiotapAlignSize { align: 1, size: 3 }, // MCS
    RadiotapAlignSize { align: 4, size: 8 }, // AMPDU_STATUS
    RadiotapAlignSize { align: 2, size: 12 }, // VHT
    RadiotapAlignSize { align: 8, size: 12 }, // TIMESTAMP
];

static RADIOTAP_NS: Ieee80211RadiotapNamespace = Ieee80211RadiotapNamespace {
    align_size: RTAP_NAMESPACE_SIZES.as_ptr(),
    n_bits: RTAP_NAMESPACE_SIZES.len() as i32,
    oui: 0,
    subns: 0,
};

#[inline]
fn get_unaligned_le16(ptr: *const u8) -> u16 {
    let val = unsafe { ptr::read_unaligned(ptr as *const u16) };
    u16::from_le(val)
}

#[inline]
fn get_unaligned_le32(ptr: *const u8) -> u32 {
    let val = unsafe { ptr::read_unaligned(ptr as *const u32) };
    u32::from_le(val)
}

pub fn ieee80211_get_radiotap_len(data: *const u8) -> i32 {
    let hdr = data as *const Ieee80211RadiotapHeader;
    unsafe { get_unaligned_le16(ptr::addr_of!((*hdr).it_len) as *const u8) as i32 }
}

pub unsafe fn ieee80211_radiotap_iterator_init(
    iterator: *mut Ieee80211RadiotapIterator,
    radiotap_header: *mut Ieee80211RadiotapHeader,
    max_length: i32,
    vns: *const Ieee80211RadiotapVendorNamespaces,
) -> i32 {
    if max_length < mem::size_of::<Ieee80211RadiotapHeader>() as i32 {
        return -libc::EINVAL;
    }

    if (*radiotap_header).it_version != 0 {
        return -libc::EINVAL;
    }

    if max_length < get_unaligned_le16(ptr::addr_of!((*radiotap_header).it_len) as *const u8) as i32
    {
        return -libc::EINVAL;
    }

    (*iterator)._rtheader = radiotap_header;
    (*iterator)._max_length =
        get_unaligned_le16(ptr::addr_of!((*radiotap_header).it_len) as *const u8) as i32;
    (*iterator)._arg_index = 0;
    (*iterator)._bitmap_shifter =
        get_unaligned_le32(ptr::addr_of!((*radiotap_header).it_present) as *const u8);
    (*iterator)._arg = (radiotap_header as *mut u8).add(mem::size_of::<Ieee80211RadiotapHeader>());
    (*iterator)._reset_on_ext = 0;
    (*iterator)._next_bitmap =
        ptr::addr_of_mut!((*radiotap_header).it_present).add(1);
    (*iterator)._vns = vns;
    (*iterator).current_namespace = &RADIOTAP_NS as *const _;
    (*iterator).is_radiotap_ns = 1;

    if (*iterator)._bitmap_shifter & (1u32 << IEEE80211_RADIOTAP_EXT) != 0 {
        if (*iterator)._arg as usize
            - (*iterator)._rtheader as usize
            + mem::size_of::<u32>()
            > (*iterator)._max_length as usize
        {
            return -libc::EINVAL;
        }

        while get_unaligned_le32((*iterator)._arg) & (1u32 << IEEE80211_RADIOTAP_EXT) != 0 {
            (*iterator)._arg = (*iterator)._arg.add(mem::size_of::<u32>());
            if (*iterator)._arg as usize
                - (*iterator)._rtheader as usize
                + mem::size_of::<u32>()
                > (*iterator)._max_length as usize
            {
                return -libc::EINVAL;
            }
        }

        (*iterator)._arg = (*iterator)._arg.add(mem::size_of::<u32>());
    }

    (*iterator).this_arg = (*iterator)._arg;
    0
}

unsafe fn find_ns(iterator: *mut Ieee80211RadiotapIterator, oui: u32, subns: u8) {
    (*iterator).current_namespace = ptr::null();

    if (*iterator)._vns.is_null() {
        return;
    }

    let vns = &*(*iterator)._vns;
    for i in 0..vns.n_ns {
        let ns = &*vns.ns.add(i as usize);
        if ns.oui != oui {
            continue;
        }
        if ns.subns != subns {
            continue;
        }

        (*iterator).current_namespace = ns as *const _;
        break;
    }
}

pub unsafe fn ieee80211_radiotap_iterator_next(
    iterator: *mut Ieee80211RadiotapIterator,
) -> i32 {
    loop {
        let mut hit = false;
        let align: i32;
        let mut size = 0;

        if ((*iterator)._arg_index % 32) == IEEE80211_RADIOTAP_EXT
            && ((*iterator)._bitmap_shifter & 1) == 0
        {
            return -libc::ENOENT;
        }

        if (*iterator)._bitmap_shifter & 1 != 0 {
            match (*iterator)._arg_index % 32 {
                IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE | IEEE80211_RADIOTAP_EXT => {
                    align = 1;
                    size = 0;
                }
                IEEE80211_RADIOTAP_VENDOR_NAMESPACE => {
                    align = 2;
                    size = 6;
                }
                _ => {
                    if (*iterator).current_namespace.is_null()
                        || (*iterator)._arg_index >= (*(*iterator).current_namespace).n_bits
                    {
                        if (*iterator).current_namespace == &RADIOTAP_NS as *const _ {
                            return -libc::ENOENT;
                        }
                        align = 0;
                    } else {
                        let entry =
                            &*(*(*iterator).current_namespace).align_size.add((*iterator)._arg_index as usize);
                        align = entry.align as i32;
                        size = entry.size as i32;
                    }
                }
            }

            if align == 0 {
                (*iterator)._arg = (*iterator)._next_ns_data;
                (*iterator).current_namespace = ptr::null();
            } else {
                let pad = ((*iterator)._arg as usize - (*iterator)._rtheader as usize)
                    & ((align as usize) - 1);
                if pad != 0 {
                    (*iterator)._arg = (*iterator)._arg.add((align as usize) - pad);
                }

                if (*iterator)._arg_index % 32 == IEEE80211_RADIOTAP_VENDOR_NAMESPACE {
                    if (*iterator)._arg as usize + size as usize
                        - (*iterator)._rtheader as usize
                        > (*iterator)._max_length as usize
                    {
                        return -libc::EINVAL;
                    }
                    let oui = ((*iterator)._arg.read() as u32) << 16
                        | ((*iterator)._arg.add(1).read() as u32) << 8
                        | (*iterator)._arg.add(2).read() as u32;
                    let subns = (*iterator)._arg.add(3).read();

                    find_ns(iterator, oui, subns);

                    let vnslen = get_unaligned_le16((*iterator)._arg.add(4)) as i32;
                    (*iterator)._next_ns_data =
                        (*iterator)._arg.add(size as usize + vnslen as usize);
                    if (*iterator).current_namespace.is_null() {
                        size += vnslen;
                    }
                }

                (*iterator).this_arg_index = (*iterator)._arg_index;
                (*iterator).this_arg = (*iterator)._arg;
                (*iterator).this_arg_size = size;

                (*iterator)._arg = (*iterator)._arg.add(size as usize);

                if (*iterator)._arg as usize - (*iterator)._rtheader as usize
                    > (*iterator)._max_length as usize
                {
                    return -libc::EINVAL;
                }

                match (*iterator)._arg_index % 32 {
                    IEEE80211_RADIOTAP_VENDOR_NAMESPACE => {
                        (*iterator)._reset_on_ext = 1;
                        (*iterator).is_radiotap_ns = 0;
                        (*iterator).this_arg_index = IEEE80211_RADIOTAP_VENDOR_NAMESPACE;
                        if (*iterator).current_namespace.is_null() {
                            hit = true;
                        }
                    }
                    IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE => {
                        (*iterator)._reset_on_ext = 1;
                        (*iterator).current_namespace = &RADIOTAP_NS as *const _;
                        (*iterator).is_radiotap_ns = 1;
                    }
                    IEEE80211_RADIOTAP_EXT => {
                        (*iterator)._bitmap_shifter =
                            get_unaligned_le32((*iterator)._next_bitmap as *const u8);
                        (*iterator)._next_bitmap = (*iterator)._next_bitmap.add(1);
                        if (*iterator)._reset_on_ext != 0 {
                            (*iterator)._arg_index = 0;
                        } else {
                            (*iterator)._arg_index += 1;
                        }
                        (*iterator)._reset_on_ext = 0;
                    }
                    _ => {
                        hit = true;
                    }
                }
            }
        }

        (*iterator)._bitmap_shifter >>= 1;
        (*iterator)._arg_index += 1;

        if hit {
            return 0;
        }
    }
}

