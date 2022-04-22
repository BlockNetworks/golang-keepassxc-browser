package keepassxc_browser

import (
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

type Connection struct {
	serverAddress string
	conn          ConnectionI
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
	if v.GetError() != "" && !v.IsSuccess() {
		return fmt.Errorf("Error: %s (code: %d)", v.GetError(), v.GetErrorCode())
	}

	return err
}

func (c *Connection) sendEncReq(identity *Identity, reqName string, req interface{}, res interface{}) (err error) {
	breq := encReq{}
	identity.SignReq(reqName, &breq)
	breq.SetTimeout(30)

	if err = breq.Encrypt(identity, req); err != nil {
		return err
	}
	breq.SetReq(&breq)

	bres := encRes{}
	bres.SetRes(&bres)
	if err = c.sendReq(&breq, &bres); err != nil {
		return err
	}
	fmt.Printf("bres: %v\n", bres)

	// lock database call -> no encryption
	if reqName == "lock-database" {
		return nil
	}
	return bres.Decrypt(identity, res)
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
	fmt.Printf("res: %v\n", res)

	identity.SetServerPubKey(res.PubKey)

	return err
}

func (c *Connection) GetDatabasehash(identity *Identity) (err error) {
	req := MsgReqGetDatabasehash{
		Action: Action{"get-databasehash"},
	}

	res := MsgResGetDatabasehash{}
	if err := c.sendEncReq(identity, "get-databasehash", &req, &res); err != nil {
		return err
	}
	fmt.Printf("res: %v\n", res)
	fmt.Printf("res: %v\n", res.ActionName)

	return err
}

func (c *Connection) Associate(identity *Identity) (err error) {
	req := MsgReqAssociate{
		Action: Action{"associate"},
		Key:    identity.GetPubKey(),
		IdKey:  identity.GetIdKey(),
	}

	res := MsgResAssociate{}
	if err := c.sendEncReq(identity, "associate", &req, &res); err != nil {
		return err
	}

	identity.AId = res.Id

	return err
}

func (c *Connection) TestAssociate(identity *Identity) (err error) {
	req := MsgReqTestAssociate{
		Action: Action{"test-associate"},
		Id:     identity.AId,
		Key:    identity.GetIdKey(),
	}

	res := MsgResTestAssociate{}
	if err := c.sendEncReq(identity, "test-associate", &req, &res); err != nil {
		return err
	}
	fmt.Printf("res: %v\n", res)

	return err
}

func (c *Connection) GeneratePassword(identity *Identity, timeout int) (err error) {
	req := MsgReqGeneratePassword{
		Action: Action{"generate-password"},
	}

	res := MsgResGeneratePassword{}
	if err := c.sendEncReq(identity, "generate-password", &req, &res); err != nil {
		return err
	}
	fmt.Printf("res: %v\n", res)

	return err
}

func (c *Connection) GetLogins(identity *Identity, url, submitUrl, httpAuth string) (err error) {
	req := MsgReqGetLogins{
		Action:    Action{"get-logins"},
		Url:       url,
		SubmitUrl: submitUrl,
		HttpAuth:  httpAuth,
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
	if err := c.sendEncReq(identity, "get-logins", &req, &res); err != nil {
		return err
	}
	fmt.Printf("res: %v\n", res)

	return err
}

func (c *Connection) LockDatabase(identity *Identity) (err error) {
	req := MsgReqLockDatabase{
		Action: Action{"lock-database"},
	}

	res := MsgResLockDatabase{}
	if err := c.sendEncReq(identity, "lock-database", &req, &res); err != nil {
		fmt.Printf("res: %v\n", res)
		return err
	}

	return err
}

func (c *Connection) GetDatabaseGroups(identity *Identity) (err error) {
	req := MsgReqGetDatabaseGroups{
		Action: Action{"get-database-groups"},
	}

	res := MsgResGetDatabaseGroups{}
	if err := c.sendEncReq(identity, "get-database-groups", &req, &res); err != nil {
		return err
	}
	fmt.Printf("res: %v\n", res)
	for _, g := range res.Groups.Groups {
		fmt.Printf("Group: %v\n", g)
		for _, c := range g.Children {
			fmt.Printf("Children: %v\n", c)
		}
	}

	return err
}

func (c *Connection) CreateNewGroup(identity *Identity, groupName string) (err error) {
	req := MsgReqCreateNewGroup{
		Action:    Action{"create-new-group"},
		GroupName: groupName,
	}

	res := MsgResCreateNewGroup{}
	if err := c.sendEncReq(identity, "create-new-group", &req, &res); err != nil {
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
