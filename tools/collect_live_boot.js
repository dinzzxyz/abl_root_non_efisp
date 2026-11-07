#!/usr/bin/env node
"use strict";
// Read-only: block devices are opened with "r"; no mounts, writes, reboots or OEM commands.
// Output can contain private device/log data. Keep raw captures outside the public repo.
// node collect_live_boot.js probe
// node collect_live_boot.js capture toolsfv|logfs|xbl_sc_logs
if(process.argv[2]==="capture") {

const fs=require("node:fs"),zlib=require("node:zlib"),crypto=require("node:crypto");
const name=process.argv[3],sizes={toolsfv:1048576,logfs:8388608,xbl_sc_logs:131072};
if(!Object.hasOwn(sizes,name))throw Error("Only toolsfv, logfs or xbl_sc_logs are supported");
const path="/dev/block/by-name/"+name;
if(!fs.statSync(path).isBlockDevice())throw Error("Expected a named block device");
const fd=fs.openSync(path,"r");
try {
 let size=sizes[name];
 if(name==="logfs"){
  const header=Buffer.alloc(512);if(fs.readSync(fd,header,0,512,0)!==512)throw Error("Short BPB");
  const bps=header.readUInt16LE(11),total=header.readUInt16LE(19)||header.readUInt32LE(32);
  size=bps*total;if(![512,1024,2048,4096].includes(bps)||size<512||size>sizes.logfs)throw Error("Invalid or out-of-bounds BPB");
 }
 const bytes=Buffer.alloc(size);let at=0;
 while(at<size){const n=fs.readSync(fd,bytes,at,size-at,at);if(!n)throw Error("Short partition read");at+=n;}
 const packed=zlib.gzipSync(bytes),sha256=crypto.createHash("sha256").update(bytes).digest("hex");
 console.log("LIVE_CAPTURE_META "+JSON.stringify({name,size,sha256,gzip_bytes:packed.length}));
 console.log("BEGIN_LIVE_GZIP");const encoded=packed.toString("base64");
 for(let i=0;i<encoded.length;i+=4096)console.log(encoded.slice(i,i+4096));
 console.log("END_LIVE_GZIP");
} finally { fs.closeSync(fd); }

} else if(!process.argv[2]||process.argv[2]==="probe") {

const fs=require("node:fs"),crypto=require("node:crypto"),cp=require("node:child_process");
const hash=b=>crypto.createHash("sha256").update(b).digest("hex");
const report={schema:1,kind:"read-only live boot probe",uid:process.getuid(),captured_utc:new Date().toISOString(),partitions:[],paths:[],kernel_lines:[]};
for(const name of ["toolsfv","logfs","uefivarstore","xbl_sc_logs","blackbox"]){
 const p="/dev/block/by-name/"+name;
 try{const real=fs.realpathSync(p),fd=fs.openSync(p,"r"),buf=Buffer.alloc(4096);let n;try{n=fs.readSync(fd,buf,0,buf.length,0);}finally{fs.closeSync(fd);}const b=buf.subarray(0,n);report.partitions.push({name,path:p,real_path:real,read_bytes:n,prefix_sha256:hash(b),first32_hex:b.subarray(0,32).toString("hex"),all_zero:b.every(x=>x===0),all_ff:b.every(x=>x===255),fvh_offsets:[...b.toString("latin1").matchAll(/_FVH/g)].map(x=>x.index),ascii_runs:(b.toString("latin1").match(/[\x20-\x7e]{8,}/g)||[]).slice(0,12).map(x=>x.slice(0,140))});}catch(e){report.partitions.push({name,error:e.code||e.message});}
}
for(const p of ["/sys/kernel/uefi_log","/sys/kernel/uefi_log/uefi_log","/proc/uefi_log","/sys/firmware/efi","/sys/fs/pstore","/proc/last_kmsg"]){
 try{const st=fs.statSync(p);report.paths.push({path:p,type:st.isDirectory()?"directory":"file",entries:st.isDirectory()?fs.readdirSync(p).slice(0,80):undefined});}catch(e){report.paths.push({path:p,error:e.code||e.message});}
}
for(const p of ["/proc/bootconfig","/proc/cmdline"]){
 try{const text=fs.readFileSync(p,"utf8");const tokens=p.endsWith("cmdline")?text.split(/\s+/):text.split(/\n/);report.paths.push({path:p,selected:tokens.filter(x=>/^(?:androidboot\.)?(?:verifiedbootstate|vbmeta\.device_state|flash\.locked|secureboot|slot_suffix|bootloader|efi|uefi|pil)(?:\s|=|\.)/.test(x.trim())).slice(0,40)});}catch(e){report.paths.push({path:p,error:e.code||e.message});}
}
try{const text=cp.execFileSync("dmesg",[],{encoding:"utf8",maxBuffer:8*1024*1024,timeout:10000});const lines=text.split("\n");report.kernel_lines=lines.filter(x=>/uefi|\befi\b|\bPIL\b|LinuxLoader|\bBDS\b|efisp|toolsfv|logfs|bootloader|verified.?boot|secure.?boot|authentication.*fail/i.test(x)).slice(0,160);report.kernel_total_lines=lines.length;}catch(e){report.kernel_error=e.code||e.message;}
console.log(JSON.stringify(report));

} else { throw Error("Expected probe or capture NAME"); }
