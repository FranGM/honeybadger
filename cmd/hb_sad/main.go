package main

import (
	"github.com/FranGM/pfkey"
	"github.com/FranGM/simplelog"
)

func init() {
	simplelog.SetThreshold(simplelog.LevelDebug)
}

func main() {
	socket, err := pfkey.NewPFKEY()
	if err != nil {
		simplelog.Fatal.Println(err)
	}
	defer socket.Close()

	err = socket.SendSADBDumpMsg()
	if err != nil {
		simplelog.Fatal.Println(err)
	}

	sadbList, err := socket.RetrieveSADBDump()
	if err != nil {
		simplelog.Fatal.Println(err)
	}

	for _, s := range sadbList {
		simplelog.Info.Printf("SA: %+v", s)
	}
}
