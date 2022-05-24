package keepassxc_browser

import (
	"fmt"
	"os"
	"path"
	"runtime"
)

type KpXcProxy struct {
	conn ConnectionI
}

func (k *KpXcProxy) HandleReq(breq []byte) (res []byte, err error) {

	if err = k.conn.Send(breq); err != nil {
		return res, err
	}

	if res, err = k.conn.Recv(BufSize, 0); err != nil {
		return res, err
	}

	return res, err
}

func NewKpXcProxy() (ret *KpXcProxy, err error) {
	serv := new(KpXcProxy)
	var serverAddress string

	tmpDir := os.Getenv("TMPDIR")
	if tmpDir != "" {
		tmpDir = path.Join(tmpDir, SocketName)
	}

	xdgRuntimeDir := os.Getenv(("XDG_RUNTIME_DIR"))
	if xdgRuntimeDir != "" {
		xdgRuntimeDir = path.Join(xdgRuntimeDir, SocketName)
	}

	oss := runtime.GOOS
	switch oss {
	case "linux":
		serv.conn = &PosixConnection{}
		if _, err = os.Stat(tmpDir); err == nil {
			serverAddress = tmpDir
			break
		}
		if _, err := os.Stat(xdgRuntimeDir); err == nil {
			serverAddress = xdgRuntimeDir
			break
		}
		return serv, fmt.Errorf("Unable to locate keepassxc socket")
	default:
		return serv, fmt.Errorf("Operating System: '%s' not supported", oss)
	}

	if err = serv.conn.Connect(serverAddress); err != nil {
		return serv, err
	}
	ret = serv

	return ret, err
}
