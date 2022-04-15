package keepassxc_browser

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"

	"github.com/jamesruan/sodium"
)

type identityAssoc struct {
	IdKey []byte
	AId   string
}

type Identity struct {
	ClientId     string
	IdKey        []byte
	AId          string
	keyPair      sodium.BoxKP
	serverPubKey sodium.BoxPublicKey
}

func (i *Identity) GetIdKey() (pubKey string) {
	return base64.StdEncoding.EncodeToString(i.IdKey)
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

func (i *Identity) SignRequest(reqAction string, req *BaseRequest) {
	sodium.Randomize(&req.nonce)
	req.Nonce = base64.StdEncoding.EncodeToString(req.nonce.Bytes)
	req.ClientId = i.ClientId
	req.ActionName = reqAction
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

func (i *Identity) SaveAssoc(file string) (err error) {
	assoc := identityAssoc{}
	assoc.IdKey = i.IdKey
	assoc.AId = i.AId

	jassoc, err := json.Marshal(assoc)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(file, jassoc, 0644)
}

func (i *Identity) LoadAssoc(file string) (err error) {
	jassoc, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	assoc := identityAssoc{}
	if err = json.Unmarshal(jassoc, &assoc); err != nil {
		return err
	}
	i.IdKey = assoc.IdKey
	i.AId = assoc.AId

	return err
}

func NewIdentity(clientId string) (ret *Identity, err error) {
	ret = new(Identity)

	ret.ClientId = clientId
	ret.IdKey = sodium.MakeBoxKP().PublicKey.Bytes
	ret.keyPair = sodium.MakeBoxKP()

	return ret, err
}
