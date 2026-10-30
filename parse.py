import sys, glob, collections
EXT = {0:"server_name",10:"supported_groups",13:"sig_algs",16:"alpn",21:"padding",41:"psk",43:"versions",45:"psk_modes",51:"key_share",65037:"ech"}
GRP = {0x11ec:"X25519MLKEM768",0x001d:"X25519",0x0017:"P-256",0x0018:"P-384",0x0201:"MLKEM768",0x11eb:"SecP256r1MLKEM768"}
def parse(b):
    rec_len = int.from_bytes(b[3:5],"big"); p = 5+4+2+32
    sid = b[p]; p += 1+sid
    cs = int.from_bytes(b[p:p+2],"big"); p += 2+cs
    comp = b[p]; p += 1+comp
    elen = int.from_bytes(b[p:p+2],"big"); p += 2; end = p+elen
    exts=[]; sni=None; ks=[]
    while p < end:
        t = int.from_bytes(b[p:p+2],"big"); l = int.from_bytes(b[p+2:p+4],"big")
        exts.append((EXT.get(t,str(t)), p, l))
        if t==0: sni=(p, p+4+l)   # byte range of the whole SNI extension in the TCP stream
        if t==51:
            q=p+6
            while q < p+4+l:
                g=int.from_bytes(b[q:q+2],"big"); kl=int.from_bytes(b[q+2:q+4],"big"); ks.append((GRP.get(g,hex(g)),kl)); q+=4+kl
        p += 4+l
    return dict(total=5+rec_len, exts=exts, sni=sni, ks=ks)
for d in sorted(glob.glob("caps/*")):
    rs=[parse(open(f,"rb").read()) for f in sorted(glob.glob(d+"/*.bin"))]
    orders=collections.Counter(tuple(e[0] for e in r["exts"]) for r in rs)
    print(f"== {d}: n={len(rs)} total bytes={sorted(set(r['total'] for r in rs))}")
    print("   key shares:", rs[0]["ks"])
    print("   distinct extension orders:", len(orders))
    print("   order[0]:", " > ".join(next(iter(orders))))
    for mss in (1460,1448,1400,1360):
        past=sum(1 for r in rs if r["sni"] and r["sni"][1] > mss)
        print(f"   MSS {mss}: SNI not fully in segment 1 in {past}/{len(rs)}; ClientHello needs {-(-rs[0]['total']//mss)} segment(s)")
    print("   SNI byte range (first 5):", [r["sni"] for r in rs[:5]])
