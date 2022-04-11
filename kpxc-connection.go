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
	Success string `json:"success"`
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

func (c *Connection) sendMsg(msg map[string]interface{}) (res map[string]interface{}, err error) {
	jmsg, err := json.Marshal(msg)
	if err != nil {
		return res, err
	}
	if err = c.conn.Send(jmsg); err != nil {
		return res, err
	}

	jres, err := c.conn.Recv(BufSize)
	if err != nil {
		return res, err
	}

	res = make(map[string]interface{})
	if err = json.Unmarshal(jres, &res); err != nil {
		return res, err
	}
	fmt.Printf("sendMsg: res: %v\n", res)

	if !ValidateNonce(msg, res) {
		return res, fmt.Errorf("Nonce mismatch")
	}

	return res, err
}

func (c *Connection) sendEncMsg(identity *Identity, msg map[string]interface{}, req map[string]interface{}) (res map[string]interface{}, err error) {
	nonce, err := ParseNonce(msg)
	if err != nil {
		return res, err
	}

	jreq, err := json.Marshal(req)
	if err != nil {
		return res, err
	}
	if msg["message"], err = identity.Encrypt(nonce, jreq); err != nil {
		return res, err
	}

	if res, err = c.sendMsg(msg); err != nil {
		return res, err
	}
	if _, ok := res["message"]; !ok {
		return res, fmt.Errorf("No message")
	}
	var eresMsg string
	var ok bool
	if eresMsg, ok = res["message"].(string); !ok {
		return res, fmt.Errorf("Broken message")
	}
	nonce, err = ParseNonce(res)
	if err != nil {
		return res, err
	}
	resMsg, err := identity.Decrypt(nonce, eresMsg)
	if err != nil {
		return res, err
	}

	res = make(map[string]interface{})
	err = json.Unmarshal(resMsg, &res)

	return res, err
}

func (c *Connection) Connect() error {
	return c.conn.Connect(c.serverAddress)
}

func (c *Connection) Close() {
	c.conn.Close()
}

func (c *Connection) ChangePublicKeys(identity *Identity) (err error) {
	msg := identity.GetSignedMessage("change-public-keys")
	msg["publicKey"] = identity.GetPubKey()

	res, err := c.sendMsg(msg)
	if err != nil {
		return err
	}

	if !IsSuccess(res) {
		return fmt.Errorf("Error exchanging keys")
	}
	if _, ok := res["publicKey"]; !ok {
		return fmt.Errorf("Error exchanging keys")
	}
	if pubKey, ok := res["publicKey"].(string); !ok {
		return fmt.Errorf("Error exchanging keys")
	} else {
		identity.SetServerPubKey(pubKey)
	}
	fmt.Printf("res: %v\n", res)

	return err
}

func (c *Connection) Associate(identity *Identity) (err error) {
	msg := identity.GetSignedMessage("associate")
	req := make(map[string]interface{})
	req["action"] = "associate"
	req["key"] = identity.GetPubKey()
	req["idkey"] = identity.GetIdKey()
	res, err := c.sendEncMsg(identity, msg, req)
	if err != nil {
		return err
	}
	identity.AId = res["id"].(string)

	fmt.Printf("res: %v\n", res)

	return err
}

func (c *Connection) GetLogins(identity *Identity, url string) (err error) {
	msg := identity.GetSignedMessage("get-logins")
	req := make(map[string]interface{})
	req["action"] = "get-logins"
	req["url"] = url
	keys := make([]map[string]interface{}, 1)
	key1 := make(map[string]interface{})
	key1["id"] = identity.AId
	key1["key"] = identity.GetPubKey()
	keys[0] = key1
	req["keys"] = keys
	res, err := c.sendEncMsg(identity, msg, req)
	if err != nil {
		return err
	}

	fmt.Printf("res: %v\n", res)

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
