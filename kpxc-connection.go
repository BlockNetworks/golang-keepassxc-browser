package keepassxc_browser

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"runtime"
	"strconv"

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

type ReqI interface {
	GetAction() string
	SetAction(string)
	GetTimeout() int
	SetTimeout(int)
	GetClientId() string
	SetClientId(string)
	GetRequestId() string
	SetRequestId(string)
	GetNonce() (sodium.BoxNonce, error)
	SetNonce(sodium.BoxNonce)
	GetReq() interface{}
	SetReq(interface{})
}

type req struct {
	ActionName string `json:"action"`
	Nonce      string `json:"nonce"`
	ClientId   string `json:"clientID"`
	RequestId  string `json:"requestID,omitempty"`
	timeout    int
	nonce      sodium.BoxNonce
	data       interface{}
}

func (r *req) GetAction() string           { return r.ActionName }
func (r *req) SetAction(action string)     { r.ActionName = action }
func (r *req) GetTimeout() int             { return r.timeout }
func (r *req) SetTimeout(timeout int)      { r.timeout = timeout }
func (r *req) GetClientId() string         { return r.ClientId }
func (r *req) SetClientId(clientId string) { r.ClientId = clientId }
func (r *req) GetRequestId() string        { return r.RequestId }
func (r *req) SetRequestId(reqId string)   { r.RequestId = reqId }
func (r *req) GetReq() interface{}         { return r.data }
func (r *req) SetReq(data interface{})     { r.data = data }

func (r *req) GetNonce() (nonce sodium.BoxNonce, err error) {
	if len(r.nonce.Bytes) == 0 {
		r.nonce.Bytes, err = base64.StdEncoding.DecodeString(r.Nonce)
	}

	return r.nonce, err
}
func (r *req) SetNonce(nonce sodium.BoxNonce) {
	r.Nonce = base64.StdEncoding.EncodeToString(nonce.Bytes)
	r.nonce = nonce
}

type ResI interface {
	GetAction() string
	GetClientId() string
	GetRequestId() string
	GetNonce() (sodium.BoxNonce, error)
	IsSuccess() bool
	GetError() string
	GetErrorCode() int
	GetVersion() string
	GetRes() interface{}
	SetRes(interface{})
}

type res struct {
	ActionName string `json:"action"`
	Nonce      string `json:"nonce"`
	ClientId   string `json:"clientID"`
	RequestId  string `json:"requestID,omitempty"`
	Success    string `json:"success,omitempty"`
	Error      string `json:"error,omitempty"`
	ErrorCode  string `json:"errorCode,omitempty"`
	Version    string `json:"version,omitempty"`
	nonce      sodium.BoxNonce
	data       interface{}
}

func (r *res) GetAction() string    { return r.ActionName }
func (r *res) GetClientId() string  { return r.ClientId }
func (r *res) GetRequestId() string { return r.RequestId }
func (r *res) GetNonce() (nonce sodium.BoxNonce, err error) {
	if len(r.nonce.Bytes) == 0 {
		r.nonce.Bytes, err = base64.StdEncoding.DecodeString(r.Nonce)
	}

	return r.nonce, err
}
func (r *res) IsSuccess() bool {
	if r.Success == "true" {
		return true
	}
	return false
}
func (r res) GetError() string { return r.Error }

//func (r res) GetErrorCode() int  { return r.ErrorCode }
func (r *res) GetErrorCode() int {
	if ec, err := strconv.Atoi(r.ErrorCode); err != nil {
		return 0
	} else {
		return ec
	}
}

func (r *res) GetVersion() string      { return r.Version }
func (r *res) GetRes() interface{}     { return r.data }
func (r *res) SetRes(data interface{}) { r.data = data }

type RequestI interface {
	GetTimeout() int
	GetAction() string
}

type BaseRequest struct {
	Action
	Nonce     string `json:"nonce,omitempty"`
	ClientId  string `json:"clientID,omitempty"`
	RequestId string `json:"requestID,omitempty"`
	nonce     sodium.BoxNonce
	timeout   int
}

func (br *BaseRequest) GetAction() string { return br.ActionName }
func (br *BaseRequest) GetTimeout() int   { return br.timeout }

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

type PubKeyRes struct {
	res
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

func (c *Connection) sendReq(req ReqI, res ResI) (err error) {
	fmt.Printf("req: %v\n", req)
	jreq, err := json.Marshal(req.GetReq())
	if err != nil {
		return err
	}
	fmt.Printf("jreq: %v\n", string(jreq))

	if err = c.conn.Send(jreq); err != nil {
		return err
	}

	jres, err := c.conn.Recv(BufSize, req.GetTimeout())
	if err != nil {
		return err
	}
	fmt.Printf("jres: %v\n", string(jres))

	resData := res.GetRes()
	if err = json.Unmarshal(jres, resData); err != nil {
		return err
	}
	fmt.Printf("resData: %v\n", resData)

	v, ok := resData.(ResI)
	fmt.Printf("ok: %v\n", ok)
	if !ok {
		return err
	}

	fmt.Printf("S: %v\n", v.IsSuccess())
	if v.GetError() != "" || !v.IsSuccess() {
		return fmt.Errorf("Error exchanging keys: %s (code: %d)", v.GetError(), v.GetErrorCode())
	}

	return err
}

func (c *Connection) sendEncRequest(identity *Identity, reqId string, req RequestI, res interface{}) (err error) {
	breq := BaseRequest{}
	breq.timeout = req.GetTimeout()
	identity.SignRequest(req.GetAction(), &breq)

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
	breq := req{}
	identity.SignReq("change-public-keys", &breq)
	fmt.Printf("breq: %v\n", breq)

	breq.SetReq(struct {
		req
		MsgPublicKey
	}{
		breq,
		MsgPublicKey{identity.GetPubKey()},
	})

	bres := res{}
	res := &PubKeyRes{}
	bres.SetRes(res)
	if err = c.sendReq(&breq, &bres); err != nil {
		return err
	}
	fmt.Printf("bres: %v\n", res)

	//cnonce, err := breq.GetNonce()
	//if err != nil {
	//return err
	//}
	//if !bres.ValidateNonce(cnonce) {
	//return fmt.Errorf(("Nonce mismatch"))
	//}
	fmt.Printf("res: %v\n", res)

	identity.SetServerPubKey(res.PubKey)

	return err
}

func (c *Connection) Associate(identity *Identity) (err error) {
	req := MsgReqAssociate{
		BaseRequest: BaseRequest{
			Action: Action{"associate"},
		},
		Key:   identity.GetPubKey(),
		IdKey: identity.GetIdKey(),
	}

	res := MsgResAssociate{}
	if err := c.sendEncRequest(identity, "", &req, &res); err != nil {
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
		BaseRequest: BaseRequest{
			Action: Action{"test-associate"},
		},
		Id:  identity.AId,
		Key: identity.GetIdKey(),
	}

	res := MsgResAssociate{}
	if err := c.sendEncRequest(identity, "", &req, &res); err != nil {
		return err
	}
	if res.Success != "true" {
		return fmt.Errorf("Error test-associate: %s (code: %s)", res.Error, res.ErrorCode)
	}
	fmt.Printf("res: %v\n", res)

	return err
}

func (c *Connection) GeneratePassword(identity *Identity, timeout int) (err error) {
	req := MsgReqGeneratePassword{
		BaseRequest: BaseRequest{
			Action:  Action{"generate-password"},
			timeout: timeout,
		},
		RequestId: GenerateRequestID(),
	}

	res := MsgResGeneratePassword{}
	if err := c.sendEncRequest(identity, req.RequestId, &req, &res); err != nil {
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
		BaseRequest: BaseRequest{
			Action: Action{"get-logins"},
		},
		Url: url,
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
	if err := c.sendEncRequest(identity, "", &req, &res); err != nil {
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
