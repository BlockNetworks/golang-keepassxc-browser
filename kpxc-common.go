package keepassxc_browser

import "github.com/jamesruan/sodium"

func SodiumBytesToByte(bytes interface{}) []byte {
	return bytes.([]byte)
}

func ByteToSodiumBytes(bytes []byte) sodium.Bytes {
	return sodium.Bytes(bytes)
}
