package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

var (
	serverDomain = flag.String("domain", "localhost", "server domain, eg: baidu.com")
)
var ca_template = x509.Certificate{
	SerialNumber: big.NewInt(1),
	Subject: pkix.Name{
		Country:            []string{"CN"},
		Organization:       []string{"Easy"},
		OrganizationalUnit: []string{"Easy"},
		Province:           []string{"beijing"},
		CommonName:         "ca_company",
		Locality:           []string{"beijing"},
	},
	NotBefore: time.Now(),
	NotAfter:  time.Now().AddDate(100, 0, 0),

	KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature |
		x509.KeyUsageCertSign,

	ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, //ExtKeyUsageServerAuth
	EmailAddresses:        []string{"ca_email@qq.com"},
	BasicConstraintsValid: true,
	IsCA:                  true,
}

//ca_template.ExtKeyUsage 的设置要注意
//由于ca 即给服务器的证书签名，也给客户端的证书签名，所以就是设置ExtKeyUsageAny
//如果设置ExtKeyUsageServerAuth，双向认证时，服务器校验客户端的证书时，提示:
//tls: failed to verify client's certificate: x509: certificate specifies an incompatible key usage
//跟一下源码/usr/local/go/src/crypto/tls/handshake_server.go  processCertsFromClient
///usr/local/go/src/crypto/x509/verify.go
/*
	// If any key usage is acceptable then we're done.
	for _, usage := range keyUsages {
		if usage == ExtKeyUsageAny {
			return candidateChains, nil
		}
	}
*/

var ser_template = x509.Certificate{
	SerialNumber: big.NewInt(1),
	Subject: pkix.Name{
		Country:            []string{"CN"},
		Organization:       []string{"Easy"},
		OrganizationalUnit: []string{"Easy"},
		Province:           []string{"beijing"},
		CommonName:         "ser_company",
		Locality:           []string{"beijing"},
	},
	NotBefore: time.Now(),
	NotAfter:  time.Now().AddDate(100, 0, 0),

	KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature |
		x509.KeyUsageCertSign,
	ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	EmailAddresses:        []string{"ser_email@qq.com"},
	BasicConstraintsValid: true,
	IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	//在DNSNames里添加服务器的域名,或者通过flag domain 来添加,否则client 验证服务器证书失败
	//比如"myserver.com" 和 "myserver1.com" 的host 都是127.0.0.1
	//client 连接"myserver.com"成功，连接"myserver1.com"失败。
	DNSNames: []string{"myserver.com"},
	//IsCA:                  true,
}

var cli_template = x509.Certificate{
	SerialNumber: big.NewInt(1),
	Subject: pkix.Name{
		Country:            []string{"CN"},
		Organization:       []string{"Easy"},
		OrganizationalUnit: []string{"Easy"},
		Province:           []string{"beijing"},
		CommonName:         "client_company",
		Locality:           []string{"beijing"},
	},
	NotBefore: time.Now(),
	NotAfter:  time.Now().AddDate(100, 0, 0),

	KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature |
		x509.KeyUsageCertSign,
	ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, //ExtKeyUsageClientAuth
	EmailAddresses:        []string{"cli_email@qq.com"},
	BasicConstraintsValid: true,
	//IsCA:                  true,
}

func ssContain(ss []string, target string) bool {
	for _, s := range ss {
		if s == target {
			return true
		}
	}
	return false
}

func main() {
	flag.Parse()
	if !ssContain(ser_template.DNSNames, *serverDomain) {
		ser_template.DNSNames = append(ser_template.DNSNames, *serverDomain)
	}
	log.Printf("server cert domain:%v", ser_template.DNSNames)

	//生成CA
	ca_pem, ca_key, err := GenCertSelfSigned(ca_template)
	if err != nil {
		panic(err)
	}

	//pem key 还原成 RSA PRIVATE, 用于给服务器和客户端的证书签名
	keyBlock, _ := pem.Decode(ca_key)
	CaPraKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		panic(err)
	}

	//gen server cert , and signed by ca_cert
	ser_pem, ser_key, err := GenCertSignedByCa(ser_template, ca_template, CaPraKey)
	if err != nil {
		panic(err)
	}

	//gen server cert , and signed by ca_cert
	client_pem, client_key, err := GenCertSignedByCa(cli_template, ca_template, CaPraKey)
	if err != nil {
		panic(err)
	}

	//save all
	SaveToFile("ca.pem", ca_pem)
	SaveToFile("ca.key", ca_key)
	SaveToFile("server.pem", ser_pem)
	SaveToFile("server.key", ser_key)
	SaveToFile("client.pem", client_pem)
	SaveToFile("client.key", client_key)
}

func SaveToFile(name string, data []byte) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open %s for writing: %v", name, err)
		return err
	}
	defer f.Close()
	n, err := f.Write(data)
	if err != nil || n != len(data) {
		log.Fatalf("Failed  write %s, err:%v, n:%d", name, err, n)
		return err
	}
	return nil
}
