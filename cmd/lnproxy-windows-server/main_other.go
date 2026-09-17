//go:build !windows

package main

import "fmt"

func main() {
	fmt.Println("lnproxy-windows-server is only supported on Windows")
}
