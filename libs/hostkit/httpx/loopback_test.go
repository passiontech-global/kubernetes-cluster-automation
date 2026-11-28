// loopback_test.go — tests for ValidateLoopbackAddr.
package httpx

import "testing"

func TestValidateLoopbackAddr(t *testing.T) {
	valid := []string{
		"127.0.0.1:9116",
		"127.0.0.2:0",
		"[::1]:9116",
		"[::1]:0",
		"localhost:9116",
		"LOCALHOST:9116",
		"localhost:0",
		"[::ffff:127.0.0.1]:9116",
		"[::ffff:127.0.0.1]:65535",
	}
	for _, addr := range valid {
		if err := ValidateLoopbackAddr(addr); err != nil {
			t.Errorf("ValidateLoopbackAddr(%q) = %v, want nil", addr, err)
		}
	}
	invalid := []string{
		":9116",
		"0.0.0.0:9116",
		"[::]:9116",
		"10.0.0.1:9116",
		"192.168.1.1:9116",
		"example.com:9116",
		"127.0.0.1:",
		"127.0.0.1",
		"",
		"[::1%eth0]:8080",
		"[::ffff:127.0.0.1%eth0]:8080",
		"[localhost]:8080",
		"[127.0.0.1]:8080",
		"::1:8080",
		"[::1]",
		"127.0.0.1:abc",
		"127.0.0.1:99999",
		"127.0.0.1:-1",
		"127.0.0.1:+80",
		"127.0.0.1:8080 ",
		" 127.0.0.1:8080",
		"localhost:8080 ",
		"localhost.:8080",
	}
	for _, addr := range invalid {
		if err := ValidateLoopbackAddr(addr); err == nil {
			t.Errorf("ValidateLoopbackAddr(%q) = nil, want error", addr)
		}
	}
}
