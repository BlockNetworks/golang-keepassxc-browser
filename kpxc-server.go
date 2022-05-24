package keepassxc_browser

import (
	"encoding/binary"
	"fmt"

	"github.com/jamesruan/sodium"
)

type ServerI interface {
	HandleReq([]byte) ([]byte, error)
}

type Server struct {
	conn         ConnectionI
	serv         ServerI
	keyPair      sodium.BoxKP
	clientPubKey sodium.BoxPublicKey
}

func (s *Server) recvReq(timeout int) (err error) {
	jreq, err := s.conn.Recv(BufSize, timeout)
	if err != nil {
		return err
	}

	hres, err := s.serv.HandleReq(jreq)
	if err != nil {
		return err
	}

	ljres := make([]byte, 4)
	binary.LittleEndian.PutUint32(ljres, uint32(len(hres)))
	hres = append(ljres, hres...)

	if err = s.conn.Send(hres); err != nil {
		return err
	}

	return err
}

func (s *Server) Run() (err error) {
	if err = s.conn.Connect(""); err != nil {
		return err
	}

	for {
		err = s.recvReq(30)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	}

	//return err
}

func NewServer(serv ServerI, conn ConnectionI) (ret *Server) {
	ret = new(Server)
	ret.serv = serv
	ret.conn = conn
	ret.keyPair = sodium.MakeBoxKP()

	return ret
}
