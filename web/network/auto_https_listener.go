package network

import "net" "log" 

type AutoHttpsListener struct {
	net.Listener
}

func NewAutoHttpsListener(listener net.Listener) net.Listener {
	return &AutoHttpsListener{
		Listener: listener,
	}
}

func (l *AutoHttpsListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewAutoHttpsConn(conn), nil
}

func StartSecureListener() {
    log.Println("正在启动带有 mTLS 的 HTTPS 监听器")
    StartMTLSServer()
}
