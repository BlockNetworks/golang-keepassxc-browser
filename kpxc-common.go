package keepassxc_browser

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"github.com/jamesruan/sodium"
)

func IsSuccess(res map[string]interface{}) bool {
	if success, ok := res["success"]; ok && success == "true" {
		return true
	}
	return false
}

func ParseNonce(msg map[string]interface{}) (nonce sodium.BoxNonce, err error) {
	if _, ok := msg["nonce"]; !ok {
		return nonce, fmt.Errorf("Nonce missing")
	}

	if snonce, ok := msg["nonce"].(string); !ok {
		return nonce, fmt.Errorf("Nonce type invalid")
	} else if nonce.Bytes, err = base64.StdEncoding.DecodeString(snonce); err != nil {
		return nonce, fmt.Errorf("Nonce decode failed")
	}

	return nonce, err
}

func ValidateNonce(msg, res map[string]interface{}) bool {
	var cnonce sodium.BoxNonce
	var rnonce sodium.BoxNonce
	var err error

	if cnonce, err = ParseNonce(msg); err != nil {
		return false
	}
	cnonce.Next()
	if rnonce, err = ParseNonce(res); err != nil {
		return false
	}
	if bytes.Compare(cnonce.Bytes, rnonce.Bytes) == 0 {
		return true
	}

	return false
}
