package keepassxc_browser

import (
	"encoding/base64"

	"github.com/jamesruan/sodium"
)

type Identity struct {
	ClientId     string
	IdKey        sodium.BoxPublicKey
	AId          string
	keyPair      sodium.BoxKP
	serverPubKey sodium.BoxPublicKey
}

func (i *Identity) GetIdKey() (pubKey string) {
	return base64.StdEncoding.EncodeToString(i.IdKey.Bytes)
}

func (i *Identity) GetPubKey() (pubKey string) {
	return base64.StdEncoding.EncodeToString(i.keyPair.PublicKey.Bytes)
}

func (i *Identity) SetServerPubKey(serverPubKey string) (err error) {
	skey, err := base64.StdEncoding.DecodeString(serverPubKey)
	if err != nil {
		return err
	}

	i.serverPubKey.Bytes = skey
	return nil
}

func (i *Identity) GetSignedMessage(reqAction string) (msg map[string]interface{}) {
	msg = make(map[string]interface{})

	nonce := sodium.BoxNonce{}
	sodium.Randomize(&nonce)

	msg["action"] = reqAction
	msg["nonce"] = base64.StdEncoding.EncodeToString(nonce.Bytes)
	msg["clientID"] = i.ClientId

	return msg
}

func (i *Identity) Encrypt(nonce sodium.BoxNonce, msg []byte) (emsg string, err error) {
	smsg := sodium.Bytes(msg)
	semsg := smsg.Box(nonce, i.serverPubKey, i.keyPair.SecretKey)
	emsg = base64.StdEncoding.EncodeToString(semsg)

	return emsg, err
}

func (i *Identity) Decrypt(nonce sodium.BoxNonce, jemsg string) (msg []byte, err error) {
	emsg, err := base64.StdEncoding.DecodeString(jemsg)
	if err != nil {
		return msg, err
	}

	semsg := sodium.Bytes(emsg)
	return semsg.BoxOpen(nonce, i.serverPubKey, i.keyPair.SecretKey)
}

func NewIdentity(clientId string) (ret *Identity, err error) {
	ret = new(Identity)

	ret.ClientId = clientId
	ret.IdKey = sodium.MakeBoxKP().PublicKey
	ret.keyPair = sodium.MakeBoxKP()

	return ret, err
}
