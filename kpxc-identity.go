package keepassxc_browser

import (
	"encoding/base64"

	"github.com/jamesruan/sodium"
)

type Identity struct {
	ClientId     string
	IdKey        sodium.BoxPublicKey
	keyPair      sodium.BoxKP
	serverPubKey sodium.BoxPublicKey
}

func (i *Identity) GetPubKey() (pubKey string) {
	return base64.StdEncoding.EncodeToString(SodiumBytesToByte(i.keyPair.PublicKey))
}

func (i *Identity) SetServerPubKey(serverPubKey string) (err error) {
	skey, err := base64.StdEncoding.DecodeString(serverPubKey)
	if err != nil {
		return err
	}

	i.serverPubKey.Bytes = ByteToSodiumBytes(skey)
	return nil
}

func (i *Identity) GetSignedMsgTransport(reqAction string) (msgTransport *msgBaseTransport) {
	msgTransport = &msgBaseTransport{}
	msgTransport.Action = reqAction
	msgTransport.nonce = sodium.BoxNonce{}
	sodium.Randomize(&msgTransport.nonce)

	msgTransport.Nonce = base64.StdEncoding.EncodeToString(SodiumBytesToByte(msgTransport.nonce))
	msgTransport.ClientId = i.ClientId

	return msgTransport
}

func (i *Identity) EncryptMessage(msg []byte, nonce sodium.BoxNonce) (emsg string) {
	smsg := ByteToSodiumBytes(msg)
	semsg := smsg.Box(nonce, i.serverPubKey, i.keyPair.SecretKey)

	emsg = base64.StdEncoding.EncodeToString(SodiumBytesToByte(semsg))

	return emsg
}

func NewIdentity(clientId string) (ret *Identity, err error) {
	ret = new(Identity)

	ret.ClientId = clientId
	ret.IdKey = sodium.MakeBoxKP().PublicKey
	ret.keyPair = sodium.MakeBoxKP()

	return ret, err
}
