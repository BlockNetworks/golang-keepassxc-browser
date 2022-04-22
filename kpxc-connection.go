package keepassxc_browser

import (
	"encoding/base64"
	"encoding/json"
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

type encReq struct {
	req
	Message string `json:"message"`
}

func (r *encReq) Encrypt(identity *Identity, req interface{}) (err error) {
	jreq, err := json.Marshal(req)
	if err != nil {
		return err
	}
	smsg := sodium.Bytes(jreq)
	semsg := smsg.Box(r.nonce, identity.serverPubKey, identity.keyPair.SecretKey)
	r.Message = base64.StdEncoding.EncodeToString(semsg)

	return err
}

type encRes struct {
	res
	Message string `json:"message"`
}

func (r *encRes) Decrypt(identity *Identity, res interface{}) (err error) {
	nonce, err := r.GetNonce()
	if err != nil {
		return err
	}

	emsg, err := base64.StdEncoding.DecodeString(r.Message)
	if err != nil {
		return err
	}

	semsg := sodium.Bytes(emsg)
	jres, err := semsg.BoxOpen(nonce, identity.serverPubKey, identity.keyPair.SecretKey)
	if err != nil {
		return err
	}
	//fmt.Printf("Decrypted json: %s\n", jres)

	return json.Unmarshal(jres, &res)
}

type PubKeyRes struct {
	res
	MsgPublicKey
}
