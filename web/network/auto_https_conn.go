package network

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"sync"
	"crypto/tls"
    "crypto/x509"
    "io/ioutil"
    "log"
)

type AutoHttpsConn struct {
	net.Conn

	firstBuf []byte
	bufStart int

	readRequestOnce sync.Once
}

func NewAutoHttpsConn(conn net.Conn) net.Conn {
	return &AutoHttpsConn{
		Conn: conn,
	}
}


func StartMTLSServer() {
    // 读取 CA 证书
    caCert, err := ioutil.ReadFile("/etc/ssl/certs/ca.crt")
    if err != nil {
        log.Fatalf("读取 CA 证书失败: %v", err)
    }
    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)

    // 加载服务器证书和密钥
    serverCert, err := tls.LoadX509KeyPair("/etc/ssl/certs/server.crt", "/etc/ssl/private/server.key")
    if err != nil {
        log.Fatalf("加载服务器证书失败: %v", err)
    }

    // 配置 mTLS
    tlsConfig := &tls.Config{
        ClientAuth:   tls.RequireAndVerifyClientCert,
        Certificates: []tls.Certificate{serverCert},
        ClientCAs:    caCertPool,
    }

    server := &http.Server{
        Addr:      "127.0.0.1:8443", // 使用 HTTPS 端口
        TLSConfig: tlsConfig,
    }

    log.Println("启动 mTLS 服务器，监听 127.0.0.1:8443")
    err = server.ListenAndServeTLS("", "")
    if err != nil {
        log.Fatalf("服务器启动失败: %v", err)
    }
}

func (c *AutoHttpsConn) readRequest() bool {
	c.firstBuf = make([]byte, 2048)
	n, err := c.Conn.Read(c.firstBuf)
	c.firstBuf = c.firstBuf[:n]
	if err != nil {
		return false
	}
	reader := bytes.NewReader(c.firstBuf)
	bufReader := bufio.NewReader(reader)
	request, err := http.ReadRequest(bufReader)
	if err != nil {
		return false
	}
	resp := http.Response{
		Header: http.Header{},
	}
	resp.StatusCode = http.StatusTemporaryRedirect
	location := fmt.Sprintf("https://%v%v", request.Host, request.RequestURI)
	resp.Header.Set("Location", location)
	resp.Write(c.Conn)
	c.Close()
	c.firstBuf = nil
	return true
}

func (c *AutoHttpsConn) Read(buf []byte) (int, error) {
	c.readRequestOnce.Do(func() {
		c.readRequest()
	})

	if c.firstBuf != nil {
		n := copy(buf, c.firstBuf[c.bufStart:])
		c.bufStart += n
		if c.bufStart >= len(c.firstBuf) {
			c.firstBuf = nil
		}
		return n, nil
	}

	return c.Conn.Read(buf)
}
