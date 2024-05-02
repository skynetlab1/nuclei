package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/projectdiscovery/nuclei/v3/internal/pdcp/agent"
)

func main() {
	if err := process(); err != nil {
		log.Fatalf("%s\n", err)
	}
}

func process() error {
	if agent.ServerKey == "" {
		return fmt.Errorf("server key is required")
	}

	// Sleep on linux machines before startup to allow us
	// some time for startup of agents
	if runtime.GOOS != "darwin" {
		time.Sleep(1 * time.Minute) // FIXME: Remove debug
	}

	f, err := os.OpenFile("/tmp/local-agent-log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	multiWriter := io.MultiWriter(os.Stderr, f)
	log.SetOutput(multiWriter)

	if err := agent.RegisterAgent(); err != nil {
		log.Printf("could not register agent: %s\n", err)
	}
	f.Close()
	return nil
}
