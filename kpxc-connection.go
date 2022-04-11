package keepassxc_browser

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"runtime"

	"github.com/jamesruan/sodium"
)

const SocketName string = "org.keepassxc.KeePassXC.BrowserServer"
const BufSize int = 1024 * 1024

type ConnectionI interface {
	Connect(string) error
	Close()
	Send([]byte) error
	Recv(int) ([]byte, error)
}

type msgBaseTransport struct {
	action
	Nonce    string `json:"nonce"`
	ClientId string `json:"clientID"`
	nonce    sodium.BoxNonce
}

type MsgTransport struct {
	msgBaseTransport
	Message string `json:"message"`
}

type PubKeyReqest struct {
	msgBaseTransport
	PubKey string `json:"publicKey"`
}

type PubKeyResponse struct {
	msgBaseTransport
	Version string `json:"version"`
	PubKey  string `json:"publicKey"`
	Success bool   `json:"success"`
}

type Connection struct {
	serverAddress string
	conn          ConnectionI
}

func (c *Connection) sendReq(req interface{}, res interface{}) (err error) {
	jreq, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if err = c.conn.Send(jreq); err != nil {
		return err
	}

	jres, err := c.conn.Recv(BufSize)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(jres, res); err != nil {
		return err
	}

	return err
}

func (c *Connection) Connect() error {
	return c.conn.Connect(c.serverAddress)
}

func (c *Connection) Close() {
	c.conn.Close()
}

func (c *Connection) ChangePublicKeys(identity *Identity) (err error) {
	treq := identity.GetSignedMsgTransport("change-public-keys")
	req := &PubKeyReqest{
		msgBaseTransport: *treq,
		PubKey:           identity.GetPubKey(),
	}
	res := &PubKeyResponse{}
	if err = c.sendReq(req, res); err != nil {
		return err
	}
	fmt.Printf("Response: %v\n", res)

	return err
}

func NewConnection() (conn *Connection, err error) {
	conn = new(Connection)

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
		conn.conn = &PosixConnection{}
		if _, err = os.Stat(tmpDir); err == nil {
			conn.serverAddress = tmpDir
			return conn, err
		}
		if _, err := os.Stat(xdgRuntimeDir); err == nil {
			conn.serverAddress = xdgRuntimeDir
			return conn, err
		}
		return nil, fmt.Errorf("Unable to locate keepassxc socket")
	default:
		return nil, fmt.Errorf("Operating System: '%s' not supported", oss)
	}
}
