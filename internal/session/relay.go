package session

import (
	"io"
	"sync"
)

func Relay(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	copyDirection := func(dst, src io.ReadWriteCloser) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if closer, ok := dst.(CloseWriter); ok {
			_ = closer.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	go copyDirection(a, b)
	go copyDirection(b, a)
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}
