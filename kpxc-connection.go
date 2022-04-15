package keepassxc_browser

import (
	"bytes"
	"encoding/base64"
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
	Recv(int, int) ([]byte, error)
}

type RequestI interface {
	GetTimeout() int
}

type BaseRequest struct {
	Action
	Nonce     string `json:"nonce,omitempty"`
	ClientId  string `json:"clientID,omitempty"`
	RequestId string `json:"requestID,omitempty"`
	nonce     sodium.BoxNonce
	timeout   int
}

func (br *BaseRequest) GetTimeout() int {
	return br.timeout
}

type BaseResponse struct {
	Action
	Nonce     string `json:"nonce,omitempty"`
	ClientId  string `json:"clientID,omitempty"`
	Success   string `json:"success,omitempty"`
	Error     string `json:"error,omitempty"`
	ErrorCode string `json:"errorCode,omitempty"`
	Version   string `json:"version,omitempty"`
	nonce     sodium.BoxNonce
}

func (br *BaseResponse) ValidateNonce(cnonce sodium.BoxNonce) bool {
	var err error
	if len(br.nonce.Bytes) == 0 {
		if br.nonce.Bytes, err = base64.StdEncoding.DecodeString(br.Nonce); err != nil {
			return false
		}
	}

	cnonce.Next()
	if bytes.Compare(cnonce.Bytes, br.nonce.Bytes) == 0 {
		return true
	}

	return false
}

func (br *BaseResponse) ParseNonce() (err error) {
	br.nonce.Bytes, err = base64.StdEncoding.DecodeString(br.Nonce)
	return err
}

type PubKeyRequest struct {
	BaseRequest
	MsgPublicKey
}

type PubKeyResponse struct {
	BaseResponse
	MsgPublicKey
}

type EncRequest struct {
	BaseRequest
	Message interface{} `json:"message"`
}

type EncResponse struct {
	BaseResponse
	Message string `json:"message"`
}

type Connection struct {
	serverAddress string
	conn          ConnectionI
}

func (c *Connection) sendRequest(req RequestI, res interface{}) (err error) {
	jreq, err := json.Marshal(req)
	if err != nil {
		return err
	}

	if err = c.conn.Send(jreq); err != nil {
		return err
	}

	jres, err := c.conn.Recv(BufSize, req.GetTimeout())
	if err != nil {
		return err
	}
	fmt.Printf("jres: %v\n", string(jres))

	if err = json.Unmarshal(jres, &res); err != nil {
		return err
	}

	return err
}

func (c *Connection) sendEncRequest(identity *Identity, reqAction string, reqId string, req RequestI, res interface{}) (err error) {
	breq := BaseRequest{}
	breq.timeout = req.GetTimeout()
	identity.SignRequest(reqAction, &breq)

	if reqId != "" {
		breq.RequestId = reqId
	}

	jreq, err := json.Marshal(req)
	if err != nil {
		return err
	}
	ereq := EncRequest{
		breq,
		"",
	}

	if ereq.Message, err = identity.Encrypt(breq.nonce, jreq); err != nil {
		return err
	}

	bres := EncResponse{}
	if err = c.sendRequest(&ereq, &bres); err != nil {
		return err
	}
	fmt.Printf("bres: %v\n", bres)

	if bres.Error != "" {
		return fmt.Errorf("Error sending request: %s (code: %s)", bres.Error, bres.ErrorCode)
	}
	if err = bres.ParseNonce(); err != nil {
		return err
	}
	if !bres.ValidateNonce(breq.nonce) {
		return fmt.Errorf("Nonce mismatch")
	}

	resMsg, err := identity.Decrypt(bres.nonce, bres.Message)
	if err != nil {
		return err
	}
	fmt.Printf("resMsg: %v\n", string(resMsg))

	if v, ok := res.(Action); ok {
		fmt.Printf("Action Action: %s\n", v.ActionName)
	}
	err = json.Unmarshal(resMsg, &res)

	return err
}

func (c *Connection) Connect() error {
	return c.conn.Connect(c.serverAddress)
}

func (c *Connection) Close() {
	c.conn.Close()
}

func (c *Connection) ChangePublicKeys(identity *Identity) (err error) {
	breq := BaseRequest{}
	identity.SignRequest("change-public-keys", &breq)

	msg := PubKeyRequest{
		breq,
		MsgPublicKey{identity.GetPubKey()},
	}

	res := PubKeyResponse{}
	if err = c.sendRequest(&msg, &res); err != nil {
		return err
	}

	if res.Error != "" || res.Success != "true" {
		return fmt.Errorf("Error exchanging keys: %s (code: %s)", res.Error, res.ErrorCode)
	}
	if !res.ValidateNonce(msg.nonce) {
		return fmt.Errorf(("Nonce mismatch"))
	}
	fmt.Printf("res: %v\n", res)

	identity.SetServerPubKey(res.PubKey)

	return err
}

func (c *Connection) Associate(identity *Identity) (err error) {
	req := MsgReqAssociate{
		Action: Action{"associate"},
		Key:    identity.GetPubKey(),
		IdKey:  identity.GetIdKey(),
	}

	res := MsgResAssociate{}
	if err := c.sendEncRequest(identity, "associate", "", &req, &res); err != nil {
		return err
	}
	if res.Success != "true" {
		return fmt.Errorf("Error associate: %s (code: %s)", res.Error, res.ErrorCode)
	}
	fmt.Printf("res: %v\n", res)

	identity.AId = res.Id

	return err
}

func (c *Connection) TestAssociate(identity *Identity) (err error) {
	req := MsgReqTestAssociate{
		Action: Action{"test-associate"},
		Id:     identity.AId,
		Key:    identity.GetIdKey(),
	}

	res := MsgResAssociate{}
	if err := c.sendEncRequest(identity, "test-associate", "", &req, &res); err != nil {
		return err
	}
	if res.Success != "true" {
		return fmt.Errorf("Error test-associate: %s (code: %s)", res.Error, res.ErrorCode)
	}
	fmt.Printf("res: %v\n", res)

	return err
}

func (c *Connection) GeneratePassword(identity *Identity, timeout int) (err error) {
	req := BaseRequest{}
	req.ActionName = "generate-password"
	req.RequestId = GenerateRequestID()
	req.timeout = timeout

	res := MsgResGeneratePassword{}
	if err := c.sendEncRequest(identity, "generate-password", req.RequestId, &req, &res); err != nil {
		return err
	}

	if res.Success != "true" {
		return fmt.Errorf("Error GeneratePassword")
	}
	fmt.Printf("res: %v\n", res)

	return err
}

func (c *Connection) GetLogins(identity *Identity, url string) (err error) {
	req := MsgReqGetLogins{
		Action: Action{"get-logins"},
		Url:    url,
		Keys: []key{
			key{
				Id:  identity.AId,
				Key: identity.GetIdKey(),
			},
		},
	}
	fmt.Printf("reqGetLogins: %v\n", req)
	fmt.Printf("reqGetLogins key: %v\n", []byte(identity.GetIdKey()))

	res := MsgResGetLogins{}
	if err := c.sendEncRequest(identity, "get-logins", "", &req, &res); err != nil {
		return err
	}
	if res.Success != "true" {
		return fmt.Errorf("Error associate: %s (code: %s)", res.Error, res.ErrorCode)
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
