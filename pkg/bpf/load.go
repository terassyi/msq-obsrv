package bpf

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc /usr/local/bin/clang MsqObsrvProg ../../bpf/tc.c -g -- -I../../bpf/include

func Load() (*MsqObsrvProgObjects, error) {
	obj := &MsqObsrvProgObjects{}
	if err := LoadMsqObsrvProgObjects(obj, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:     ebpf.LogLevelInstruction,
			// LogLevel:     ebpf.LogLevelBranch,
			LogSizeStart: 1024 * 1024,
		},
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			fmt.Printf("Verifier error: %+v\n", ve)
			return nil, err
		}
		return nil, err
	}
	return obj, nil
}

func UnLoad() error {
	obj := MsqObsrvProgObjects{}
	obj.Close()
	return nil
}
