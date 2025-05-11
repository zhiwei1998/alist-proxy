package sign

import (
	"crypto/hmac"
	"crypto/sha256"
	"net/http"
)

type Signer interface {
	SignRequest(*http.Request)
}

type HMACSign struct {
	key []byte
}

func NewHMACSign(key []byte) *HMACSign {
	return &HMACSign{key: key}
}

func (s *HMACSign) SignRequest(req *http.Request) {
	if s.key == nil {
		return
	}
	h := hmac.New(sha256.New, s.key)
	h.Write([]byte(req.URL.Path))
	signature := h.Sum(nil)
	req.Header.Set("Authorization", "Bearer "+string(signature))
}
