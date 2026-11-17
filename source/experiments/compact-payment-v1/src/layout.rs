//! Explicit columns; actual symbolic count/degree is measured only after compilation.
pub const PERM: usize = 0;
pub const CTX: usize = 320;
pub const CONTEXT: usize = 204;
pub const WORK_NOTE: usize = 524;
pub const WORK_KEY: usize = 544;
pub const WORK_ORIGIN: usize = 549;
pub const WORK_CM: usize = 557;
pub const CURRENT: usize = 565;
pub const SIBLING: usize = 573;
pub const BRANCH: usize = 581;
pub const RANGE_A: usize = 582;
pub const RANGE_D: usize = 633;
pub const LEFT: usize = 684;
pub const RIGHT: usize = 692;
pub const WIDTH: usize = 700;
pub const PP_NODE: usize = 0;
pub const PP_NOTE: usize = 80;
pub const PP_INPUT: usize = 84;
pub const PP_ROLE: usize = 86;
pub const PP_RANGE: usize = 106;
pub const PP_INDEX: usize = 111;
pub const PP_DEPTH: usize = 113;
pub const PP_WIDTH: usize = 114;
pub const CTX_NOTES: usize = 0;
pub const CTX_KEYS: usize = 80;
pub const CTX_ORIGINS: usize = 90;
pub const CTX_CM: usize = 106;
pub const CTX_INDICES: usize = 122;
pub const CTX_BITS: usize = 124;
pub const REAL_ROWS: usize = 356;
pub const fn rb(role: usize, block: usize) -> usize {
    PP_ROLE + 4 * (role - 1) + block
}
pub const fn note(j: usize, field: usize) -> usize {
    CTX + CTX_NOTES + 20 * j + field
}
pub const fn key(i: usize, field: usize) -> usize {
    CTX + CTX_KEYS + 5 * i + field
}
pub const fn origin(i: usize, field: usize) -> usize {
    CTX + CTX_ORIGINS + 8 * i + field
}
pub const fn cm(i: usize, field: usize) -> usize {
    CTX + CTX_CM + 8 * i + field
}
pub const fn index(i: usize) -> usize {
    CTX + CTX_INDICES + i
}
pub const fn bit(i: usize, d: usize) -> usize {
    CTX + CTX_BITS + 40 * i + d
}
