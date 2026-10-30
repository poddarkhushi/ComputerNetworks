# Scale analysis for the 2,000-handshake Chromium run.
import glob, collections, math, csv, sys
sys.argv=["x"]; exec(open("parse.py").read().split("for d in sorted")[0])
rs=[parse(open(f,"rb").read()) for f in sorted(glob.glob("caps/chromium_2000/*.bin"))]
n=len(rs)
def ci(k,n):  # Wilson 95%
    z=1.96; p=k/n; d=1+z*z/n; c=(p+z*z/(2*n))/d; h=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/d; return (100*(c-h),100*(c+h))
print("n =",n)
print("total ClientHello bytes: min",min(r["total"] for r in rs),"max",max(r["total"] for r in rs))
print("key shares:",collections.Counter(tuple(r["ks"]) for r in rs).most_common(2))
orders=collections.Counter(tuple(e[0] for e in r["exts"]) for r in rs)
print("distinct extension orders:",len(orders),"of",n)
print("distinct SNI start offsets:",len(set(r["sni"][0] for r in rs)))
ks_before=sum(1 for r in rs if [e[0] for e in r["exts"]].index("key_share")<[e[0] for e in r["exts"]].index("server_name"))
print(f"key_share before server_name: {ks_before}/{n} = {100*ks_before/n:.1f}%  CI95 {ci(ks_before,n)[0]:.1f}-{ci(ks_before,n)[1]:.1f}")
rows=[]
for mss in (1460,1448,1400,1360,1280):
    in1=sum(1 for r in rs if r["sni"][1]<=mss)
    strad=sum(1 for r in rs if r["sni"][0]<mss<r["sni"][1])
    in2=sum(1 for r in rs if r["sni"][0]>=mss)
    segs=collections.Counter(-(-r["total"]//mss) for r in rs)
    lo,hi=ci(n-in1,n)
    print(f"MSS {mss}: SNI fully seg1 {in1}, straddles boundary {strad}, fully seg2 {in2} | not-in-seg1 {100*(n-in1)/n:.1f}% (CI95 {lo:.1f}-{hi:.1f}) | segments {dict(segs)}")
    s2=[r["sni"][0]-mss for r in rs if r["sni"][0]>=mss]
    if s2: print(f"   when in seg2: bytes into seg2 before SNI: min {min(s2)} median {sorted(s2)[len(s2)//2]} max {max(s2)}")
    rows.append([mss,n,in1,strad,in2])
with open("scale_summary.csv","w",newline="") as f:
    w=csv.writer(f); w.writerow(["mss","n","sni_fully_seg1","sni_straddles","sni_fully_seg2"]); w.writerows(rows)
# extensions count before SNI (parser depth needed in seg 1)
dep=collections.Counter([e[0] for e in r["exts"]].index("server_name") for r in rs)
print("extensions preceding SNI (count: freq):",dict(sorted(dep.items())))
