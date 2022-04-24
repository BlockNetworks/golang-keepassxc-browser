package keepassxc_browser

import (
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"time"

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

type ConnMsg struct {
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

func ParseConnMsg(bmsg []byte) (ret *ConnMsg, err error) {
	ret = new(ConnMsg)
	if err = json.Unmarshal(bmsg, ret); err != nil {
		return nil, err
	}

	if ret.Nonce != "" {
		ret.nonce.Bytes, err = base64.StdEncoding.DecodeString(ret.Nonce)
		if err != nil {
			return nil, err
		}
	}

	if ret.data, err = GetMessageType(ret.ActionName); err != nil {
		return nil, err
	}

	return ret, err
}

func GenerateRequestID() string {
	v := make([]byte, 8)
	rand.Seed(time.Now().UnixNano())

	for i := 0; i < 8; i++ {
		v[i] = byte(rand.Intn(255-0) + 0)
	}
	return string(v)
}

func EncryptBytes(nonce sodium.BoxNonce, pubkey sodium.BoxPublicKey, privkey sodium.BoxSecretKey, data []byte) (ret []byte) {
	sdata := sodium.Bytes(data)
	ret = sdata.Box(nonce, pubkey, privkey)

	return ret
}

func DecryptBytes(nonce sodium.BoxNonce, pubkey sodium.BoxPublicKey, privkey sodium.BoxSecretKey, data []byte) (ret []byte, err error) {
	sdata := sodium.Bytes(data)

	return sdata.BoxOpen(nonce, pubkey, privkey)
}

func GenerateConnReq(action, clientID string) (ret *ConnMsg, err error) {
	ret = new(ConnMsg)

	if ret.data, err = GetMessageType(action); err != nil {
		return nil, err
	}

	sodium.Randomize(&ret.nonce)
	ret.Nonce = base64.StdEncoding.EncodeToString(ret.nonce.Bytes)
	ret.RequestId = GenerateRequestID()
	ret.ClientId = clientID
	ret.ActionName = action

	return ret, nil
}
