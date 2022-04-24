package keepassxc_browser

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"runtime"
	"strconv"

	"github.com/jamesruan/sodium"
)

type Client struct {
	ClientId      string
	IdKey         string
	AId           string
	keyPair       sodium.BoxKP
	serverPubKey  sodium.BoxPublicKey
	serverAddress string
	conn          ConnectionI
}

func (c *Client) sendMsg(req *ConnMsg, timeout int) (ret *ConnMsg, err error) {
	if err = c.prepareMsg(req); err != nil {
		return nil, err
	}

	jreq, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	//slog.LOG_DEBUGF("SendReq jreq: %v\n", jreq)
	//slog.LOG_DEBUGF("SendReq jreq: %s\n", jreq)
	if err = c.conn.Send(jreq); err != nil {
		return nil, err
	}

	jres, err := c.conn.Recv(BufSize, timeout)
	if err != nil {
		return nil, err
	}
	//slog.LOG_DEBUGF("SendReq jres: %v\n", jres)
	//slog.LOG_DEBUGF("SendReq jres: %s\n", jres)

	// stupid protocol....
	if len(jres) == 2 {
		jres, err = c.conn.Recv(BufSize, timeout)
		if err != nil {
			return nil, err
		}
	}

	if ret, err = ParseConnMsg(jres); err != nil {
		return nil, err
	}

	// even MORE stupid protocol.... ?????
	if ret.ActionName == "database-locked" {
		jres, err = c.conn.Recv(BufSize, timeout)
		if err != nil {
			return nil, err
		}
		if ret, err = ParseConnMsg(jres); err != nil {
			return nil, err
		}
	}

	if err = c.postMsg(req, ret); err != nil {
		return ret, err
	}

	return ret, nil
}

func (c *Client) SendMsg(req *ConnMsg) (ret *ConnMsg, err error) {
	return c.sendMsg(req, 0)
}

func (c *Client) prepareMsg(req *ConnMsg) (err error) {
	if req.data == nil {
		return nil
	}

	jdata, err := json.Marshal(req.data)
	if err != nil {
		return err
	}
	jedata := EncryptBytes(req.nonce, c.serverPubKey, c.keyPair.SecretKey, jdata)
	req.Message = base64.StdEncoding.EncodeToString(jedata)

	return nil
}

func (c *Client) postMsg(req, res *ConnMsg) (err error) {
	if res.Error != "" || res.ErrorCode != "" {
		ec, err := strconv.Atoi(res.ErrorCode)
		if err != nil {
			ec = -1
		}
		return fmt.Errorf("Error: %s (Code: %d)", res.Error, ec)
	}
	if res.Success != "" && res.Success != "true" {
		return fmt.Errorf("Unknown Error")
	}

	cnonce := sodium.BoxNonce{}
	cnonce.Bytes = sodium.Bytes(req.nonce.Bytes)
	cnonce.Next()

	if res.Nonce != "" && bytes.Compare(cnonce.Bytes, res.nonce.Bytes) != 0 {
		return fmt.Errorf("Nonce mismatch")
	}

	if res.Message != "" && res.Nonce != "" && res.data != nil {
		jedata, err := base64.StdEncoding.DecodeString(res.Message)
		if err != nil {
			return err
		}
		jdata, err := DecryptBytes(res.nonce, c.serverPubKey, c.keyPair.SecretKey, jedata)
		if err != nil {
			return err
		}
		if err = json.Unmarshal(jdata, res.data); err != nil {
			return err
		}
	}

	return nil
}

func (c *Client) Connect() error {
	return c.conn.Connect(c.serverAddress)
}

func (c *Client) Close() {
	c.conn.Close()
}

func (c *Client) ChangePublicKeys() (ret *ConnMsg, err error) {
	req, err := GenerateConnReq("change-public-keys", c.ClientId)
	if err != nil {
		return nil, err
	}
	req.PublicKey = base64.StdEncoding.EncodeToString(c.keyPair.PublicKey.Bytes)

	if ret, err = c.SendMsg(req); err != nil {
		return nil, err
	}

	if c.serverPubKey.Bytes, err = base64.StdEncoding.DecodeString(ret.PublicKey); err != nil {
		return nil, err
	}

	return ret, err
}

func (c *Client) GetDatabasehash() (ret *MsgGetDatabasehash, err error) {
	req, err := GenerateConnReq("get-databasehash", c.ClientId)
	if err != nil {
		return nil, err
	}

	res, err := c.SendMsg(req)
	if err != nil {
		return nil, err
	}
	ret = res.data.(*MsgGetDatabasehash)

	if ret.Success != "true" {
		return ret, fmt.Errorf("Unknown Error")
	}

	return ret, nil
}

func (c *Client) Associate() (ret *MsgAssociate, err error) {
	req, err := GenerateConnReq("associate", c.ClientId)
	if err != nil {
		return nil, err
	}
	req.data.(*MsgAssociate).Key = base64.StdEncoding.EncodeToString(c.keyPair.PublicKey.Bytes)
	req.data.(*MsgAssociate).IdKey = c.IdKey

	res, err := c.SendMsg(req)
	if err != nil {
		return nil, err
	}
	ret = res.data.(*MsgAssociate)

	if ret.Success != "true" {
		return ret, fmt.Errorf("Unknown Error")
	}
	c.AId = ret.Id

	return ret, nil
}

func (c *Client) TestAssociate() (ret *MsgAssociate, err error) {
	req, err := GenerateConnReq("test-associate", c.ClientId)
	if err != nil {
		return nil, err
	}
	req.data.(*MsgAssociate).Key = c.IdKey
	req.data.(*MsgAssociate).Id = c.AId

	res, err := c.SendMsg(req)
	if err != nil {
		return nil, err
	}
	ret = res.data.(*MsgAssociate)

	if ret.Success != "true" {
		return ret, fmt.Errorf("Unknown Error")
	}

	return ret, nil
}

func (c *Client) GeneratePassword(timeout int) (ret *MsgGeneratePassword, err error) {
	req, err := GenerateConnReq("generate-password", c.ClientId)
	if err != nil {
		return nil, err
	}

	res, err := c.sendMsg(req, timeout)
	if err != nil {
		return nil, err
	}
	ret = res.data.(*MsgGeneratePassword)

	if ret.Success != "true" {
		return ret, fmt.Errorf("Unknown Error")
	}

	return ret, nil
}

func (c *Client) GetLogins(url, submitUrl, httpAuth string) (ret *MsgGetLogins, err error) {
	req, err := GenerateConnReq("get-logins", c.ClientId)
	if err != nil {
		return nil, err
	}
	reqi := req.data.(*MsgGetLogins)
	reqi.Url = url
	reqi.SubmitUrl = submitUrl
	reqi.HttpAuth = httpAuth
	reqi.Keys = []key{
		{
			Id:  c.AId,
			Key: c.IdKey,
		},
	}

	res, err := c.SendMsg(req)
	if err != nil {
		return nil, err
	}
	ret = res.data.(*MsgGetLogins)

	if ret.Success != "true" {
		return ret, fmt.Errorf("Unknown Error")
	}

	return ret, nil
}

func (c *Client) SetLogin(url, submitUrl, login, password, group, groupUuid, uuid string) (ret *MsgSetLogin, err error) {
	req, err := GenerateConnReq("set-login", c.ClientId)
	if err != nil {
		return nil, err
	}
	reqi := req.data.(*MsgSetLogin)
	reqi.Url = url
	reqi.SubmitUrl = submitUrl
	reqi.Login = login
	reqi.Password = password
	reqi.Group = group
	reqi.GroupUuid = groupUuid
	reqi.Uuid = uuid

	res, err := c.SendMsg(req)
	if err != nil {
		return nil, err
	}
	ret = res.data.(*MsgSetLogin)

	if ret.Success != "true" {
		return ret, fmt.Errorf("Unknown Error")
	}

	return ret, nil
}

func (c *Client) LockDatabase() (err error) {
	req, err := GenerateConnReq("lock-database", c.ClientId)
	if err != nil {
		return err
	}

	res, err := c.SendMsg(req)
	if err != nil {
		return err
	}
	if res.data.(*MsgLockDatabase).Success != "true" {
		return fmt.Errorf("Unknown Error")
	}
	return nil
}

func (c *Client) GetDatabaseGroups() (ret *MsgGetDatabaseGroups, err error) {
	req, err := GenerateConnReq("get-database-groups", c.ClientId)
	if err != nil {
		return nil, err
	}

	res, err := c.SendMsg(req)
	if err != nil {
		return nil, err
	}
	ret = res.data.(*MsgGetDatabaseGroups)

	if ret.Success != "true" {
		return ret, fmt.Errorf("Unknown Error")
	}

	return ret, nil
}

func (c *Client) CreateNewGroup(groupName string) (ret *MsgCreateNewGroup, err error) {
	req, err := GenerateConnReq("create-new-group", c.ClientId)
	if err != nil {
		return nil, err
	}
	req.data.(*MsgCreateNewGroup).GroupName = groupName

	res, err := c.SendMsg(req)
	if err != nil {
		return nil, err
	}
	ret = res.data.(*MsgCreateNewGroup)

	if ret.Success != "true" {
		return ret, fmt.Errorf("Unknown Error")
	}

	return ret, nil
}

func (c *Client) GetTotp(uuid string) (ret *MsgGetTotp, err error) {
	req, err := GenerateConnReq("get-totp", c.ClientId)
	if err != nil {
		return nil, err
	}
	req.data.(*MsgGetTotp).Uuid = uuid

	res, err := c.SendMsg(req)
	if err != nil {
		return nil, err
	}
	ret = res.data.(*MsgGetTotp)

	if ret.Success != "true" {
		return ret, fmt.Errorf("Unknown Error")
	}

	return ret, nil
}

func (c *Client) SaveAssoc(file string) (err error) {
	jassoc, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(file, jassoc, 0644)
}

func (c *Client) LoadAssoc(file string) (err error) {
	jassoc, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(jassoc, c); err != nil {
		return err
	}

	return err
}

func NewClient(clientId string) (client *Client, err error) {
	client = new(Client)

	client.ClientId = clientId
	client.IdKey = base64.StdEncoding.EncodeToString(sodium.MakeBoxKP().PublicKey.Bytes)
	client.keyPair = sodium.MakeBoxKP()

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
		client.conn = &PosixConnection{}
		if _, err = os.Stat(tmpDir); err == nil {
			client.serverAddress = tmpDir
			return client, err
		}
		if _, err := os.Stat(xdgRuntimeDir); err == nil {
			client.serverAddress = xdgRuntimeDir
			return client, err
		}
		return nil, fmt.Errorf("Unable to locate keepassxc socket")
	default:
		return nil, fmt.Errorf("Operating System: '%s' not supported", oss)
	}
}
