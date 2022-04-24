package keepassxc_browser

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"time"
)

type StdinoutConnection struct {
	in  *bufio.Reader
	out *bufio.Writer
}

func (conn *StdinoutConnection) Connect(address string) (err error) {
	conn.in = bufio.NewReader(os.Stdin)
	conn.out = bufio.NewWriter(os.Stdout)

	return err
}

func (conn *StdinoutConnection) Close() {
	conn.out.Flush()
}

func (conn *StdinoutConnection) Send(message []byte) (err error) {
	if conn.out == nil {
		return fmt.Errorf("No connection established")
	}

	//messagelen := make([]byte, 4)
	//binary.LittleEndian.PutUint32(messagelen, uint32(len(message)))
	//msg := append(messagelen, message...)
	//_, err = conn.out.Write(msg)
	_, err = conn.out.Write(message)
	if err != nil {
		return err
	}

	return conn.out.Flush()
}

func (conn *StdinoutConnection) Recv(bufsize int, timeout int) (ret []byte, err error) {
	if conn.in == nil {
		return nil, fmt.Errorf("No connection established")
	}

	blen := make([]byte, 4)
	if timeout > 0 {
		os.Stdout.SetReadDeadline(time.Now().Add(time.Duration(time.Second * time.Duration(timeout))))
	}
	_, err = conn.in.Read(blen)
	if err != nil {
		return blen, err
	}

	rlen := binary.LittleEndian.Uint32(blen)
	ret = make([]byte, rlen)
	n, err := conn.in.Read(ret)
	if err != nil {
		return ret, err
	}
	//slog.LOG_DEBUGF("Recv n: %d ret: %v\n", n, ret)
	//slog.LOG_DEBUGF("Recv n: %d ret: %s\n", n, ret)
	if n != int(rlen) {
		return ret, fmt.Errorf("Incomplete message: n=%d rlen=%d", n, rlen)
	}

	return ret, err
}
