
cd gen_cert
go run *.go
即可一键生成以下所有文件：
```
ca.pem, ca.key
server.pem, server.key
client.pem, client.key
```
ca.pem 是自签名的。
server.pem 和 client.pem 也是由ca.key 签名的，即有ca颁发的证书。

+ server_client 目录：单向验证，客户端验证服务器的证书，服务器没有验证客户端的合法性。
+ mutual 目录： 双向验证，避免中间人攻击。

learn by:
https://golang.org/src/crypto/tls/generate_cert.go
