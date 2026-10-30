package main
import ("crypto/tls";"net";"os";"strconv";"time")
func main(){ n,_:=strconv.Atoi(os.Args[2]); host:=os.Args[3]
 for i:=0;i<n;i++{ c,err:=net.Dial("tcp","127.0.0.1:"+os.Args[1]); if err!=nil{continue}
  t:=tls.Client(c,&tls.Config{ServerName:host,InsecureSkipVerify:true}); t.SetDeadline(time.Now().Add(time.Second)); t.Handshake(); c.Close() } }
