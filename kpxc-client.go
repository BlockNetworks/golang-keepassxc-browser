package keepassxc_browser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"runtime"
)

type Client struct {
	serverAddress string
	conn          ConnectionI
}

func (c *Client) sendReq(req ReqI, res ResI, timeout int) (err error) {
	jreq, err := json.Marshal(req.GetReq())
	if err != nil {
		return err
	}

	if err = c.conn.Send(jreq); err != nil {
		return err
	}

	jres, err := c.conn.Recv(BufSize, timeout)
	if err != nil {
		return err
	}

	// stupid protocol....
	if len(jres) == 2 {
		jres, err = c.conn.Recv(BufSize, timeout)
		if err != nil {
			return err
		}
	}

	resData := res.GetRes()
	if err = json.Unmarshal(jres, resData); err != nil {
		return err
	}

	v, ok := resData.(ResI)
	if !ok {
		return err
	}

	if v.GetError() != "" && !v.IsSuccess() {
		return fmt.Errorf("Error: %s (code: %d)", v.GetError(), v.GetErrorCode())
	}

	if rnonce, err := v.GetNonce(); err != nil {
		return err
	} else {
		cnonce, err := req.GetNonce()
		if err != nil {
			return err
		}
		cnonce.Next()

		if bytes.Compare(cnonce.Bytes, rnonce.Bytes) != 0 {
			return fmt.Errorf("Nonce mismatch")
		}
	}

	return err
}

func (c *Client) SendReq(req ReqI, res ResI) (err error) {
	return c.sendReq(req, res, 0)
}

func (c *Client) sendEncReq(identity *Identity, reqName string, req interface{}, res interface{}, timeout int) (err error) {
	breq := encReq{}
	identity.SignReq(reqName, &breq)

	if err = breq.Encrypt(identity, req); err != nil {
		return err
	}
	breq.SetReq(&breq)

	bres := encRes{}
	bres.SetRes(&bres)
	if err = c.sendReq(&breq, &bres, timeout); err != nil {
		return err
	}

	// lock database call -> no encryption
	if reqName == "lock-database" {
		return nil
	}
	return bres.Decrypt(identity, res)
}

func (c *Client) SendEncReq(identity *Identity, reqName string, req interface{}, res interface{}) (err error) {
	return c.sendEncReq(identity, reqName, req, res, 0)
}

func (c *Client) Connect() error {
	return c.conn.Connect(c.serverAddress)
}

func (c *Client) Close() {
	c.conn.Close()
}

func (c *Client) ChangePublicKeys(identity *Identity) (ret *PubKeyRes, err error) {
	breq := req{}
	identity.SignReq("change-public-keys", &breq)

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
	if err = c.SendReq(&breq, &bres); err != nil {
		return ret, err
	}

	identity.SetServerPubKey(res.PubKey)

	return res, err
}

func (c *Client) GetDatabasehash(identity *Identity) (ret *MsgResGetDatabasehash, err error) {
	req := MsgReqGetDatabasehash{
		Action: Action{"get-databasehash"},
	}

	res := MsgResGetDatabasehash{}
	if err := c.SendEncReq(identity, "get-databasehash", &req, &res); err != nil {
		return ret, err
	}

	return &res, err
}

func (c *Client) Associate(identity *Identity) (ret *MsgResAssociate, err error) {
	req := MsgReqAssociate{
		Action: Action{"associate"},
		Key:    identity.GetPubKey(),
		IdKey:  identity.GetIdKey(),
	}

	res := MsgResAssociate{}
	if err := c.SendEncReq(identity, "associate", &req, &res); err != nil {
		return ret, err
	}

	identity.AId = res.Id

	return &res, err
}

func (c *Client) TestAssociate(identity *Identity) (ret *MsgResTestAssociate, err error) {
	req := MsgReqTestAssociate{
		Action: Action{"test-associate"},
		Id:     identity.AId,
		Key:    identity.GetIdKey(),
	}

	res := MsgResTestAssociate{}
	if err := c.SendEncReq(identity, "test-associate", &req, &res); err != nil {
		return ret, err
	}

	return &res, err
}

func (c *Client) GeneratePassword(identity *Identity, timeout int) (ret *MsgResGeneratePassword, err error) {
	req := MsgReqGeneratePassword{
		Action: Action{"generate-password"},
	}

	res := MsgResGeneratePassword{}
	if err := c.sendEncReq(identity, "generate-password", &req, &res, timeout); err != nil {
		return ret, err
	}

	return &res, err
}

func (c *Client) GetLogins(identity *Identity, url, submitUrl, httpAuth string) (ret *MsgResGetLogins, err error) {
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

	res := MsgResGetLogins{}
	if err := c.SendEncReq(identity, "get-logins", &req, &res); err != nil {
		return ret, err
	}

	return &res, err
}

func (c *Client) SetLogin(identity *Identity, url, submitUrl, login, password, group, groupUuid, uuid string) (ret *MsgResSetLogin, err error) {
	req := MsgReqSetLogin{
		Action:    Action{"set-login"},
		Url:       url,
		SubmitUrl: submitUrl,
		Login:     login,
		Password:  password,
		Group:     group,
		GroupUuid: groupUuid,
		Uuid:      uuid,
	}

	res := MsgResSetLogin{}
	if err := c.SendEncReq(identity, "set-login", &req, &res); err != nil {
		return ret, err
	}

	return &res, err
}

func (c *Client) LockDatabase(identity *Identity) (err error) {
	req := MsgReqLockDatabase{
		Action: Action{"lock-database"},
	}

	res := MsgResLockDatabase{}
	if err := c.SendEncReq(identity, "lock-database", &req, &res); err != nil {
		return err
	}

	return err
}

func (c *Client) GetDatabaseGroups(identity *Identity) (ret *MsgResGetDatabaseGroups, err error) {
	req := MsgReqGetDatabaseGroups{
		Action: Action{"get-database-groups"},
	}

	res := MsgResGetDatabaseGroups{}
	if err := c.SendEncReq(identity, "get-database-groups", &req, &res); err != nil {
		return ret, err
	}

	return &res, err
}

func (c *Client) CreateNewGroup(identity *Identity, groupName string) (ret *MsgResCreateNewGroup, err error) {
	req := MsgReqCreateNewGroup{
		Action:    Action{"create-new-group"},
		GroupName: groupName,
	}

	res := MsgResCreateNewGroup{}
	if err := c.SendEncReq(identity, "create-new-group", &req, &res); err != nil {
		return ret, err
	}

	return &res, err
}

func (c *Client) GetTotp(identity *Identity, uuid string) (ret *MsgResGetTotp, err error) {
	req := MsgReqGetTotp{
		Action: Action{"get-totp"},
		Uuid:   uuid,
	}

	res := MsgResGetTotp{}
	if err := c.SendEncReq(identity, "get-totp", &req, &res); err != nil {
		return ret, err
	}

	return &res, err
}

func NewClient() (conn *Client, err error) {
	conn = new(Client)

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
