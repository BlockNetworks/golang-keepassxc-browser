package keepassxc_browser

import (
	"fmt"
	"net"
	"time"
)

type PosixConnection struct {
	c *net.UnixConn
}

func (conn *PosixConnection) Connect(address string) (err error) {
	if conn.c, err = net.DialUnix("unix", nil,
		&net.UnixAddr{Name: address, Net: "unix"}); err != nil {
		return err
	}
	return err
}

func (conn *PosixConnection) Close() {
	if conn.c != nil {
		conn.c.Close()
	}
}

func (conn *PosixConnection) Send(message []byte) (err error) {
	if conn.c == nil {
		return fmt.Errorf("No connection established")
	}
	_, err = conn.c.Write(message)
	return err
}

func (conn *PosixConnection) Recv(bufsize int, timeout int) (ret []byte, err error) {
	if conn.c == nil {
		return nil, fmt.Errorf("No connection established")
	}

	ret = make([]byte, bufsize)
	if timeout > 0 {
		conn.c.SetReadDeadline(time.Now().Add(time.Duration(time.Second * time.Duration(timeout))))
	}
	n, err := conn.c.Read(ret)
	if err != nil {
		return nil, err
	}
	//slog.LOG_DEBUGF("Recv n: %d ret: %v\n", n, ret[:n])
	//slog.LOG_DEBUGF("Recv n: %d ret: %s\n", n, ret[:n])

	return ret[:n], err
}
