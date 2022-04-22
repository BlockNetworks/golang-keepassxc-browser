package keepassxc_browser

import (
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
	fmt.Printf("req: %v\n", req)
	jreq, err := json.Marshal(req.GetReq())
	if err != nil {
		return err
	}
	fmt.Printf("jreq: %v\n", string(jreq))

	if err = c.conn.Send(jreq); err != nil {
		return err
	}

	jres, err := c.conn.Recv(BufSize, timeout)
	if err != nil {
		return err
	}
	fmt.Printf("jres: %v\n", string(jres))

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
	fmt.Printf("bres: %v\n", bres)

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

func (c *Client) ChangePublicKeys(identity *Identity) (err error) {
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
	if err = c.SendReq(&breq, &bres); err != nil {
		return err
	}
	fmt.Printf("bres: %v\n", res)
	fmt.Printf("res: %v\n", res)

	identity.SetServerPubKey(res.PubKey)

	return err
}

func (c *Client) GetDatabasehash(identity *Identity) (err error) {
	req := MsgReqGetDatabasehash{
		Action: Action{"get-databasehash"},
	}

	res := MsgResGetDatabasehash{}
	if err := c.SendEncReq(identity, "get-databasehash", &req, &res); err != nil {
		return err
	}
	fmt.Printf("res: %v\n", res)
	fmt.Printf("res: %v\n", res.ActionName)

	return err
}

func (c *Client) Associate(identity *Identity) (err error) {
	req := MsgReqAssociate{
		Action: Action{"associate"},
		Key:    identity.GetPubKey(),
		IdKey:  identity.GetIdKey(),
	}

	res := MsgResAssociate{}
	if err := c.SendEncReq(identity, "associate", &req, &res); err != nil {
		return err
	}

	identity.AId = res.Id

	return err
}

func (c *Client) TestAssociate(identity *Identity) (err error) {
	req := MsgReqTestAssociate{
		Action: Action{"test-associate"},
		Id:     identity.AId,
		Key:    identity.GetIdKey(),
	}

	res := MsgResTestAssociate{}
	if err := c.SendEncReq(identity, "test-associate", &req, &res); err != nil {
		return err
	}
	fmt.Printf("res: %v\n", res)

	return err
}

func (c *Client) GeneratePassword(identity *Identity, timeout int) (err error) {
	req := MsgReqGeneratePassword{
		Action: Action{"generate-password"},
	}

	res := MsgResGeneratePassword{}
	if err := c.sendEncReq(identity, "generate-password", &req, &res, timeout); err != nil {
		return err
	}
	fmt.Printf("res: %v\n", res)

	return err
}

func (c *Client) GetLogins(identity *Identity, url, submitUrl, httpAuth string) (err error) {
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
	if err := c.SendEncReq(identity, "get-logins", &req, &res); err != nil {
		return err
	}
	fmt.Printf("res: %v\n", res)

	return err
}

func (c *Client) SetLogin(identity *Identity, url, submitUrl, login, password, group, groupUuid, uuid string) (err error) {
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
		return err
	}
	fmt.Printf("res: %v\n", res)

	return err
}

func (c *Client) LockDatabase(identity *Identity) (err error) {
	req := MsgReqLockDatabase{
		Action: Action{"lock-database"},
	}

	res := MsgResLockDatabase{}
	if err := c.SendEncReq(identity, "lock-database", &req, &res); err != nil {
		fmt.Printf("res: %v\n", res)
		return err
	}

	return err
}

func (c *Client) GetDatabaseGroups(identity *Identity) (err error) {
	req := MsgReqGetDatabaseGroups{
		Action: Action{"get-database-groups"},
	}

	res := MsgResGetDatabaseGroups{}
	if err := c.SendEncReq(identity, "get-database-groups", &req, &res); err != nil {
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

func (c *Client) CreateNewGroup(identity *Identity, groupName string) (err error) {
	req := MsgReqCreateNewGroup{
		Action:    Action{"create-new-group"},
		GroupName: groupName,
	}

	res := MsgResCreateNewGroup{}
	if err := c.SendEncReq(identity, "create-new-group", &req, &res); err != nil {
		return err
	}
	fmt.Printf("res: %v\n", res)

	return err
}

func (c *Client) GetTotp(identity *Identity, uuid string) (err error) {
	req := MsgReqGetTotp{
		Action: Action{"get-totp"},
		Uuid:   uuid,
	}

	res := MsgResGetTotp{}
	if err := c.SendEncReq(identity, "get-totp", &req, &res); err != nil {
		return err
	}
	fmt.Printf("res: %v\n", res)
	fmt.Printf("res totp: %v\n", res.Totp)

	return err
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
