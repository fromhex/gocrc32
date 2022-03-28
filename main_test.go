package main

import (
	"bytes"
	"testing"
)

func TestCrc32(t *testing.T) {
	crc := crc32("1234", 0)
	if crc != 0x9be3e0a3 {
		t.Error(crc)
		t.Error("测试失败")
	}
}

func TestFindReverse(t *testing.T) {
	patchBytes := findReverse(0x9be3e0a3, 0)
	if !bytes.Equal(patchBytes, []byte{49, 50, 51, 52}) {
		t.Error(patchBytes)
		t.Error("测试失败")
	}
}
