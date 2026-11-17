//! CP_CONTEXT_AIR_02: fixed segments, one live context, unchanged scratch meaning.
pub const PERM: usize = 0;
pub const CTX: usize = 320;
pub const CONTEXT: usize = 82;
pub const BALANCE: usize = 402;
pub const WORK_NOTE: usize = 403;
pub const WORK_KEY: usize = 423;
pub const WORK_ORIGIN: usize = 428;
pub const WORK_CM: usize = 436;
pub const CURRENT: usize = 444;
pub const SIBLING: usize = 452;
pub const BRANCH: usize = 460;
pub const RANGE_A: usize = 461;
pub const RANGE_D: usize = 512;
pub const LEFT: usize = 563;
pub const RIGHT: usize = 571;
pub const WIDTH: usize = 579;
pub const PP_NODE: usize = 0; // 40 live depth selectors; no input duplication.
pub const PP_KEEP: usize = 40;
pub const PP_INPUT_START: usize = 41;
pub const PP_NOTE_START: usize = 42;
pub const PP_ZERO_TAIL: usize = 43;
pub const PP_ZERO_ALL: usize = 44;
pub const PP_AMOUNT_SIGN: usize = 45;
pub const PP_FEE: usize = 46;
// 49..79 remain zero; 47/48 are credit range/positive flags.
pub const PP_NOTE: usize = 80;
pub const PP_INPUT: usize = 84;
pub const PP_ROLE: usize = 86;
pub const PP_RANGE: usize = 106;
pub const PP_INDEX: usize = 111;
pub const PP_DEPTH: usize = 113;
pub const PP_WIDTH: usize = 114;
pub const HEIGHT: usize = 512;
pub const PP_CREDIT: usize = 47;
pub const PP_CREDIT_POS: usize = 48;
pub const fn rb(role: usize, block: usize) -> usize {
    PP_ROLE + 4 * (role - 1) + block
}
pub const fn note(j: usize) -> usize {
    CTX + j
}
pub const fn key(j: usize) -> usize {
    CTX + 20 + j
}
pub const fn origin(j: usize) -> usize {
    CTX + 25 + j
}
pub const fn cm(j: usize) -> usize {
    CTX + 33 + j
}
pub const fn index() -> usize {
    CTX + 41
}
pub const fn bit(d: usize) -> usize {
    CTX + 42 + d
}
