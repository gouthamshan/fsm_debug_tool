#!/usr/bin/env python3
"""Parse Windows minidump (MDMP) files - stdlib only. Extract exception code/address,
crashing thread, module at exception address, module list, and readable strings around crash."""
import gzip, pathlib, re, struct, sys

EXCEPTION_NAMES={0xE06D7363:"C++ EH (MSVC)",0xC0000005:"ACCESS_VIOLATION",0xC0000096:"PRIV_INSTRUCTION",0xC000001D:"ILLEGAL_INSTRUCTION",0xC000008C:"FLOAT_DIVIDE",0xC000008D:"FLOAT_OVERFLOW",0xC000008E:"FLOAT_UNDERFLOW",0xC000008F:"FLOAT_INEXACT",0xC0000090:"FLOAT_INVALID",0xC0000091:"FLOAT_STACK_CHECK",0xC0000092:"FLOAT_DENORMAL",0xC0000093:"FLOAT_OVERFLOW2",0xC0000094:"INT_DIVIDE_BY_ZERO",0xC0000095:"INT_OVERFLOW",0xC0000096:"INT_INVALID_OP",0xC00000FD:"STACK_OVERFLOW",0xC0000025:"NONCONTINUABLE",0xC0000026:"INVALID_DISPOSITION",0xC000008C:"EXCEPTION_FLOAT_DIVIDE_BY_ZERO",0x80000003:"BREAKPOINT",0x80000004:"SINGLE_STEP",0x406D1388:"THREAD_NAME",11:"SIGSEGV (signal 11)",6:"SIGABRT (signal 6)",15:"SIGTERM (signal 15)",7:"SIGBUS (signal 7)",4:"SIGILL (signal 4)",8:"SIGFPE (signal 8)"}

def u32(d,o): return struct.unpack_from("<I",d,o)[0]
def u64(d,o): return struct.unpack_from("<Q",d,o)[0]

def parse(path: pathlib.Path):
    raw=path.read_bytes()
    if raw[:2]==b'\x1f\x8b': raw=gzip.decompress(raw)
    if raw[:4]!=b'MDMP': return {"file":path.name,"error":"not MDMP, magic="+raw[:8].hex(),"size":len(raw)}
    sig,ver,nstreams,dir_rva,checksum,ts,flags=struct.unpack_from("<4sIIIIIQ",raw,0)
    streams={}
    for i in range(nstreams):
        off=dir_rva+i*12
        st,sz,rva=struct.unpack_from("<III",raw,off)
        streams.setdefault(st,[]).append((rva,sz))
    info={"file":path.name,"size":len(raw),"streams":sorted(streams.keys()),"timestamp":ts}
    # Exception stream type 6
    if 6 in streams:
        rva,sz=streams[6][0]
        tid,align=struct.unpack_from("<II",raw,rva)
        code, eflags, erec, eaddr, nparams, unused = struct.unpack_from("<IIQQII",raw,rva+8)
        params=[u64(raw,rva+8+32+j*8) for j in range(min(nparams,4))]
        info.update({"crash_thread":tid,"exception_code":hex(code),"exception_name":EXCEPTION_NAMES.get(code,"UNKNOWN"),"exception_addr":hex(eaddr),"params":[hex(p) for p in params]})
    # Module list type 5
    modules=[]
    if 5 in streams:
        rva,sz=streams[5][0]
        count=u32(raw,rva)
        off=rva+4
        for i in range(count):
            base=u64(raw,off); size=u32(raw,off+8); name_rva=u32(raw,off+20)
            # module name is UTF-16LE at name_rva
            name=""
            if name_rva and name_rva < len(raw):
                end=raw.find(b'\x00\x00',name_rva)
                if end!=-1:
                    try: name=raw[name_rva:end].decode('utf-16le',errors='replace')
                    except: pass
            modules.append((base,size,name))
            off+=100
        info["modules"]=modules
        if "exception_addr" in info:
            ea=int(info["exception_addr"],16)
            for base,size,name in modules:
                if base <= ea < base+size:
                    info["crash_module"]=name
                    info["crash_offset"]=hex(ea-base)
                    break
    # Thread list type 3
    if 3 in streams:
        rva,sz=streams[3][0]
        info["thread_count"]=u32(raw,rva)
    # Misc / System info type 15, etc ignored
    # Search for tcmalloc / invalid pointer strings in whole dump
    strs=re.findall(rb'[ -~]{6,}', raw)
    txt=[s.decode() for s in strs]
    hits=[s for s in txt if any(k in s for k in ("tcmalloc","invalid pointer","Attempt to free","SIGSEGV","segfault","Received signal"))]
    info["crash_strings"]=hits[:10]
    # last log-like strings containing Nov / 2026 timestamps near end
    logstrs=[s for s in txt if "2026-" in s or "Nov " in s]
    info["last_log_strings"]=logstrs[-5:]
    return info

def main():
    for arg in sys.argv[1:]:
        p=pathlib.Path(arg)
        files=[p] if p.is_file() else sorted(p.glob("*.minidump.gz"))+sorted(p.rglob("*.minidump.gz"))
        for f in files:
            print("\n===",f)
            info=parse(f)
            for k,v in info.items():
                if k=="modules":
                    print(" modules:",len(v))
                    for b,s,n in v:
                        print(f"   {hex(b)} +{s} {n}")
                else:
                    print(f" {k}: {v}")

if __name__=="__main__": main()
