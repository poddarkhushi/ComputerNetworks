const tls=require('tls'); const [port,n,host]=process.argv.slice(2); let i=0;
function go(){ if(i++>=+n) return; const s=tls.connect({port:+port,host:'127.0.0.1',servername:host,rejectUnauthorized:false});
 s.on('error',()=>{}); s.on('close',()=>setTimeout(go,10)); setTimeout(()=>s.destroy(),800);} go();
