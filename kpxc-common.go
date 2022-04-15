package keepassxc_browser

import (
	"math/rand"
	"time"
)

func GenerateRequestID() string {
	v := make([]byte, 8)
	rand.Seed(time.Now().UnixNano())

	for i := 0; i < 8; i++ {
		v[i] = byte(rand.Intn(255-0) + 0)
	}
	return string(v)
}
