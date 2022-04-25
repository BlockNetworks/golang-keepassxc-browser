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

type KpXcMitmI interface {
	ModifyReq(*ConnMsg) error
	ModifyRes(*ConnMsg) error
}

type kpXcModifier struct {
	keyPair      sodium.BoxKP
	clientPubKey sodium.BoxPublicKey
	serverPubKey sodium.BoxPublicKey
	modifier     KpXcMitmI
}

type KpXcMitm struct {
	conn     ConnectionI
	modifier *kpXcModifier
}

func (m *kpXcModifier) ModifyReq(req *ConnMsg) (err error) {
	encrypt := false

	switch req.ActionName {
	case "change-public-keys":
		if m.clientPubKey.Bytes, err = base64.StdEncoding.DecodeString(req.PublicKey); err != nil {
			return err
		}
		req.PublicKey = base64.StdEncoding.EncodeToString(m.keyPair.PublicKey.Bytes)
		break
	default:
		if req.Message != "" && req.Nonce != "" && req.data != nil {
			jedata, err := base64.StdEncoding.DecodeString(req.Message)
			if err != nil {
				return err
			}
			jdata, err := DecryptBytes(req.nonce, m.clientPubKey, m.keyPair.SecretKey, jedata)
			if err != nil {
				return err
			}
			if err = json.Unmarshal(jdata, req.data); err != nil {
				return err
			}

			if req.ActionName == "associate" {
				req.data.(*MsgAssociate).Key = base64.StdEncoding.EncodeToString(m.keyPair.PublicKey.Bytes)
			}
			encrypt = true
		}
		break
	}

	if err = m.modifier.ModifyReq(req); err != nil {
		return err
	}

	if encrypt {
		jdata, err := json.Marshal(req.data)
		if err != nil {
			return err
		}
		jedata := EncryptBytes(req.nonce, m.serverPubKey, m.keyPair.SecretKey, jdata)
		req.Message = base64.StdEncoding.EncodeToString(jedata)
	}

	return nil
}

func (m *kpXcModifier) ModifyRes(res *ConnMsg) (err error) {
	encrypt := false

	switch res.ActionName {
	case "change-public-keys":
		if m.serverPubKey.Bytes, err = base64.StdEncoding.DecodeString(res.PublicKey); err != nil {
			return err
		}
		res.PublicKey = base64.StdEncoding.EncodeToString(m.keyPair.PublicKey.Bytes)
		break
	default:
		if res.Message != "" && res.Nonce != "" && res.data != nil {
			jedata, err := base64.StdEncoding.DecodeString(res.Message)
			if err != nil {
				return err
			}
			jdata, err := DecryptBytes(res.nonce, m.serverPubKey, m.keyPair.SecretKey, jedata)
			if err != nil {
				return err
			}
			if err = json.Unmarshal(jdata, res.data); err != nil {
				return err
			}
			encrypt = true
		}
		break
	}

	if err = m.modifier.ModifyRes(res); err != nil {
		return err
	}

	if encrypt {
		jdata, err := json.Marshal(res.data)
		if err != nil {
			return err
		}
		jedata := EncryptBytes(res.nonce, m.clientPubKey, m.keyPair.SecretKey, jdata)
		res.Message = base64.StdEncoding.EncodeToString(jedata)
	}

	return nil
}

func (k *KpXcMitm) HandleReq(breq []byte) (bres []byte, err error) {
	req, err := ParseConnMsg(breq)
	if err != nil {
		return bres, err
	}

	if err = k.modifier.ModifyReq(req); err != nil {
		return bres, err
	}

	jreq, err := json.Marshal(req)
	if err != nil {
		return bres, err
	}

	if err = k.conn.Send(jreq); err != nil {
		return bres, err
	}

	jres, err := k.conn.Recv(BufSize, 0)
	if err != nil {
		return bres, err
	}

	res, err := ParseConnMsg(jres)
	if err != nil {
		return bres, err
	}

	if err = k.modifier.ModifyRes(res); err != nil {
		return bres, err
	}

	return json.Marshal(res)
}

func NewKpXcMitm(modifier KpXcMitmI) (ret *KpXcMitm, err error) {
	mod := new(kpXcModifier)
	mod.modifier = modifier
	mod.keyPair = sodium.MakeBoxKP()
	serv := new(KpXcMitm)
	serv.modifier = mod

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

	if err = serv.conn.Connect(serverAddress); err != nil {
		return serv, err
	}
	ret = serv

	return ret, err
}
