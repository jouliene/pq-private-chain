//! Public-data-only research boundary; protocol and hash-profile semantics are unchanged.
//! Installed OpenSSL 3.0.13 ABI; local library/provider provenance is an operator gate.
use std::{ffi::{c_char,c_int,c_uint,c_void},ptr};
#[cfg(not(all(target_os="linux",target_arch="x86_64")))]
compile_error!("This source proposal only pins the inspected Linux x86-64 ABI");
#[repr(C)] struct LibCtx { _opaque: [u8;0] }
#[repr(C)] struct Provider { _opaque: [u8;0] }
#[repr(C)] struct Md { _opaque: [u8;0] }
#[repr(C)] struct MdCtx { _opaque: [u8;0] }
#[link(name="crypto")]
unsafe extern "C" {
    fn OPENSSL_version_major()->c_uint;
    fn OPENSSL_version_minor()->c_uint;
    fn OPENSSL_version_patch()->c_uint;
    fn OSSL_LIB_CTX_new()->*mut LibCtx;
    fn OSSL_LIB_CTX_free(ctx:*mut LibCtx);
    fn OSSL_PROVIDER_load(ctx:*mut LibCtx,name:*const c_char)->*mut Provider;
    fn OSSL_PROVIDER_unload(provider:*mut Provider)->c_int;
    fn EVP_MD_fetch(ctx:*mut LibCtx,algorithm:*const c_char,properties:*const c_char)->*mut Md;
    fn EVP_MD_free(md:*mut Md);
    fn EVP_MD_get0_provider(md:*const Md)->*const Provider;
    fn EVP_MD_get_size(md:*const Md)->c_int;
    fn EVP_MD_get_block_size(md:*const Md)->c_int;
    fn EVP_MD_is_a(md:*const Md,name:*const c_char)->c_int;
    fn EVP_MD_CTX_new()->*mut MdCtx;
    fn EVP_MD_CTX_free(ctx:*mut MdCtx);
    // params is always NULL; no foreign OSSL_PARAM layout is constructed.
    fn EVP_DigestInit_ex2(ctx:*mut MdCtx,md:*const Md,params:*const c_void)->c_int;
    fn EVP_DigestUpdate(ctx:*mut MdCtx,data:*const c_void,count:usize)->c_int;
    fn EVP_DigestFinal_ex(ctx:*mut MdCtx,out:*mut u8,size:*mut c_uint)->c_int;
}
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum Error { Length, Version, ContextAllocation, ProviderLoad, DigestFetch,
    DigestIdentity, DigestAllocation, Init, Update, Final, OutputLength, ProviderUnload }
/// Stack-local ownership only: no shared provider, cached verdict, or global state.
struct Session { lib:*mut LibCtx, provider:*mut Provider, md:*mut Md, ctx:*mut MdCtx }
impl Session {
    fn new()->Result<Self,Error> {
        // SAFETY: zero-argument installed OpenSSL ABI calls; expected ELF is an
        // operator/build gate, not authenticated by this version tuple.
        if unsafe{(OPENSSL_version_major(),OPENSSL_version_minor(),OPENSSL_version_patch())} != (3,0,13) {
            return Err(Error::Version)
        }
        let mut s=Self{lib:ptr::null_mut(),provider:ptr::null_mut(),md:ptr::null_mut(),ctx:ptr::null_mut()};
        // SAFETY: each returned owner is checked before use and released in Drop.
        // All C strings are static NUL-terminated, all context pointers are owned.
        unsafe {
            s.lib=OSSL_LIB_CTX_new();if s.lib.is_null(){return Err(Error::ContextAllocation)}
            s.provider=OSSL_PROVIDER_load(s.lib,c"default".as_ptr());
            if s.provider.is_null(){return Err(Error::ProviderLoad)}
            s.md=EVP_MD_fetch(s.lib,c"SHA3-512".as_ptr(),c"provider=default".as_ptr());
            if s.md.is_null(){return Err(Error::DigestFetch)}
            if EVP_MD_get0_provider(s.md)!=s.provider.cast_const() || EVP_MD_get_size(s.md)!=64 ||
                EVP_MD_get_block_size(s.md)!=72 || EVP_MD_is_a(s.md,c"SHA3-512".as_ptr())!=1 {
                return Err(Error::DigestIdentity)
            }
            s.ctx=EVP_MD_CTX_new();if s.ctx.is_null(){return Err(Error::DigestAllocation)}
            if EVP_DigestInit_ex2(s.ctx,s.md,ptr::null())!=1{return Err(Error::Init)}
        }
        Ok(s)
    }
    fn update(&mut self,b:&[u8])->Result<(),Error> {
        // SAFETY: borrowed slice lives for this synchronous call; even empty
        // input has a valid non-null pointer and count zero. No retained input.
        if unsafe{EVP_DigestUpdate(self.ctx,b.as_ptr().cast(),b.len())}!=1{return Err(Error::Update)}
        Ok(())
    }
    fn finish(mut self)->Result<[u8;64],Error> {
        let mut out=[0u8;64];let mut n=0u32;
        // SAFETY: size checked at fetch, output is 64 writable bytes and length
        // is a writable C unsigned int on the explicitly selected ABI.
        if unsafe{EVP_DigestFinal_ex(self.ctx,out.as_mut_ptr(),&mut n)}!=1{return Err(Error::Final)}
        if n!=64{return Err(Error::OutputLength)}
        self.close()?;Ok(out)
    }
    fn close(&mut self)->Result<(),Error> {
        // SAFETY: release in dependency order; replace pointers before releasing
        // so fallback Drop cannot double-free. Unload failure prevents success.
        unsafe {
            if !self.ctx.is_null(){EVP_MD_CTX_free(std::mem::replace(&mut self.ctx,ptr::null_mut()))}
            if !self.md.is_null(){EVP_MD_free(std::mem::replace(&mut self.md,ptr::null_mut()))}
            let ok=if self.provider.is_null(){true}else{
                OSSL_PROVIDER_unload(std::mem::replace(&mut self.provider,ptr::null_mut()))==1
            };
            if !self.lib.is_null(){OSSL_LIB_CTX_free(std::mem::replace(&mut self.lib,ptr::null_mut()))}
            if !ok{return Err(Error::ProviderUnload)}
        }
        Ok(())
    }
}
impl Drop for Session {
    fn drop(&mut self){let _=self.close();} // Preserve primary failure; never retry a hash.
}
fn framed(tag:&[u8],b:&[u8],suffix:&[u8])->Result<[u8;64],Error>{
    let n=u32::try_from(b.len()).map_err(|_|Error::Length)?;
    let len=u16::try_from(tag.len()).map_err(|_|Error::Length)?;
    let mut s=Session::new()?;
    // Exactly the original five update calls, including the empty PROOF suffix.
    s.update(&len.to_le_bytes())?;s.update(tag)?;s.update(&n.to_le_bytes())?;
    s.update(b)?;s.update(suffix)?;s.finish()
}
pub fn proof(public_proof:&[u8])->Result<[u8;64],Error>{framed(b"PQPC/CP3/PROOF",public_proof,&[])}
pub fn body(public_prefix:&[u8],proof_digest:&[u8;64])->Result<[u8;64],Error>{framed(b"PQPC/CP3/BODY",public_prefix,proof_digest)}
/// Probe-only raw KAT/rate-boundary entry; do not expose through the ledger API.
pub(crate) fn diagnostic_raw(public:&[u8],chunk:usize)->Result<[u8;64],Error>{
    if chunk==0{return Err(Error::Length)}
    let mut s=Session::new()?;for b in public.chunks(chunk){s.update(b)?}s.finish()
}
