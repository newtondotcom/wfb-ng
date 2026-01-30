use std::mem;

pub const CMD_SET_FEC: u8 = 1;
pub const CMD_SET_RADIO: u8 = 2;
pub const CMD_GET_FEC: u8 = 3;
pub const CMD_GET_RADIO: u8 = 4;

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct CmdSetFec {
    pub k: u8,
    pub n: u8,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct CmdSetRadio {
    pub stbc: u8,
    pub ldpc: bool,
    pub short_gi: bool,
    pub bandwidth: u8,
    pub mcs_index: u8,
    pub vht_mode: bool,
    pub vht_nss: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union CmdReqUnion {
    pub cmd_set_fec: CmdSetFec,
    pub cmd_set_radio: CmdSetRadio,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct CmdReq {
    pub req_id: u32,
    pub cmd_id: u8,
    pub u: CmdReqUnion,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct CmdGetFec {
    pub k: u8,
    pub n: u8,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct CmdGetRadio {
    pub stbc: u8,
    pub ldpc: bool,
    pub short_gi: bool,
    pub bandwidth: u8,
    pub mcs_index: u8,
    pub vht_mode: bool,
    pub vht_nss: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union CmdRespUnion {
    pub cmd_get_fec: CmdGetFec,
    pub cmd_get_radio: CmdGetRadio,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct CmdResp {
    pub req_id: u32,
    pub rc: u32,
    pub u: CmdRespUnion,
}

impl CmdReq {
    pub fn zeroed() -> Self {
        unsafe { mem::zeroed() }
    }
}

impl CmdResp {
    pub fn zeroed() -> Self {
        unsafe { mem::zeroed() }
    }
}

