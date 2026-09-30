package gos7_test

import (
	"github.com/kenvaid/gos7"
	"testing"
)

func TestPublicInterfaces(t *testing.T) {
	c := gos7.TCPClient("127.0.0.1", 0, 1)
	defer c.Close()
	var _ gos7.ConnectedClient = c
	var _ gos7.ClockClient = c
	p := gos7.S7Protection{SchSchal: 1, SchPar: 2, SchRel: 3, BartSch: 4, AnlSch: 5}
	if p.AnlSch != 5 {
		t.Fatal(p)
	}
}
