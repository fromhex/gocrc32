package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"

	"github.com/urfave/cli/v2"
)

const (
	Banner = `
                           ____ ___  
                          |___ \__ \ 
  __ _  ___   ___ _ __ ___  __) | ) |
 / _' |/ _ \ / __| '__/ __||__ < / / 
| (_| | (_) | (__| | | (__ ___) / /_ 
 \__, |\___/ \___|_|  \___|____/____|
  __/ |                              
 |___/
`
	// crc32的生成项
	poly        = 0x04C11DB7
	polyReverse = 0xEDB88320
)

var (
	// crc32的查找表
	crc32Table [256]uint32
	// 单字节补丁索引表
	crc32TableReverse [256]int
	// 允许字符集
	allowChar = []byte("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
)

/* 生成crc32的查找表，单字节补丁索引表 */
func initTables(poly uint32, reverse bool) error {
	// crc32的查找表生成，过程为一个字节的求crc过程
	for i := 0; i < 256; i++ {
		crc := uint32(i)
		for j := 0; j < 8; j++ {
			// 判断i最低位是否为1，为1异或poly，不为1异或0（-1的补码为0xffffffff）
			crc = (crc >> 1) ^ (poly & (-(crc & 1)))
		}
		crc32Table[i] = crc
	}
	// 单字节补丁索引表生成，crc的最高字节只由crc32查找表的最高字节决定
	if reverse {
		var found int
		for i := 0; i < 256; i++ {
			for j := 0; j < 256; j++ {
				if crc32Table[j]>>24 == uint32(i) {
					found = j
				}
			}
			crc32TableReverse[i] = found
		}
	}
	return nil
}

/*
crc为初始crc一般为0，防止初始字节为0，一般用0xffffffff
第一个字节查表时，整个有效的crc计算才算开始
最后一个字节查表时，整个有效的crc计算才算结束
crc寄存器为4个字节，当存在初始crc时，数据移入字节，每一个字节应该与之前的crc异或
所以数据窗口的最高字节应该与crc寄存器最高字节异或之后，再查表

可以看到crc的最高字节只由crc32表的最高字节决定
*/
func calc(data []byte, oldCrc uint32) (crc uint32) {
	crc = ^oldCrc // go的按位取反
	for _, b := range data {
		// crc寄存器每次从低位移除一个字节，每次移除的内容是数据和之前的crc异或的最低字节
		crc = (crc >> 8) ^ crc32Table[(crc^uint32(b))&0xff]
	}
	crc = ^crc
	return crc
}

/* 找到4字节的补丁 */
func findReverse(wantCrc uint32, oldCrc uint32) (patchBytes []byte) {
	var idx [4]int
	wantCrc = ^wantCrc
	oldCrc = ^oldCrc
	for i := 3; i >= 0; i-- {
		idx[i] = crc32TableReverse[wantCrc>>24]
		wantCrc = (wantCrc ^ crc32Table[idx[i]]) << 8
	}
	for i := 0; i < 4; i++ {
		patchBytes = append(patchBytes, byte((oldCrc^uint32(idx[i]))&0xff))
		oldCrc = (oldCrc >> 8) ^ crc32Table[(oldCrc^uint32(patchBytes[i]))&0xff]
	}
	return
}

func addData(wantCrc uint32, oldCrc uint32, data []byte) {
	patches := findReverse(wantCrc, calc(data, oldCrc))
	// 四字节
	if len(data) == 0 {
		checksum := calc(patches, oldCrc)
		if checksum == wantCrc {
			log.Printf("验证checksum: 0x%08x OK\n", checksum)
			log.Printf("4 Bytes: %#v\n", string(patches))
		}
		return
	}
	// 是否为常见字符
	for _, v := range patches {
		if bytes.IndexByte(allowChar, v) < 0 {
			return
		}
	}
	res := append(data, patches...)
	log.Printf("%d Bytes: %#v\n", len(res), string(res))
}

func getReverse(wantCrc uint32, oldCrc uint32, size int) {
	initTables(polyReverse, true)

	// for i := 0; i < size-4; i++ {
	// 	addData(wantCrc, oldCrc)
	// }

	switch size {
	case 4:
		addData(wantCrc, oldCrc, []byte{})
	case 5:
		for _, u := range allowChar {
			addData(wantCrc, oldCrc, []byte{u})
		}
	case 6:
		for _, u := range allowChar {
			for _, v := range allowChar {
				addData(wantCrc, oldCrc, []byte{u, v})
			}
		}
	default:
		addData(wantCrc, oldCrc, []byte{})
		for _, u := range allowChar {
			addData(wantCrc, oldCrc, []byte{u})
		}
		for _, u := range allowChar {
			for _, v := range allowChar {
				addData(wantCrc, oldCrc, []byte{u, v})
			}
		}
	}

}
func crc32(str string, oldCrc uint32) (crc32 uint32) {
	initTables(polyReverse, true)
	oldRune := []byte(str)
	crc32 = calc(oldRune, 0)
	log.Printf("数据%s的CRC32值为: 0x%08x\n", str, crc32)
	return
}

func main() {
	// 作者信息
	author := cli.Author{
		Name:  "fromhex",
		Email: "fromhex@163.com",
	}
	// 初始化命令行工具信息
	app := &cli.App{
		Name:    "gocrc32",
		Usage:   "A cmd tool by golang of crc32 calc or crash",
		Version: "v0.0.2",
		Authors: []*cli.Author{&author},
		Before: func(ctx *cli.Context) error {
			fmt.Print(Banner)
			return nil
		},
	}

	// 添加子命令
	app.Commands = []*cli.Command{Calc, Reverse}
	err := app.Run(os.Args)
	checkErr(err)
}

/* 检测错误 */
func checkErr(err error) {
	if err != nil {
		log.Fatal("\033[1;31m[ERRO] \033[0m", err)
	}
}

var Calc = &cli.Command{
	Name:        "calc",
	Usage:       "calc a string's CRC32",
	Description: "计算字符的CRC32值",
	Action:      doCalc,
}
var Reverse = &cli.Command{
	Name:        "reverse",
	Usage:       "reverse CRC32 or reverse -f zipfile",
	Description: "计算CRC32对应的4,5,6个字符或者计算zip文件对应的CRC32",
	Action:      doReverse,
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "file",
			Aliases: []string{"f"},
			Usage:   "Load CRC32 from zip file",
		},
	},
}

func doCalc(c *cli.Context) error {
	str := c.Args().First()
	crc32(str, 0)
	return nil
}
func doReverse(c *cli.Context) error {
	// zip文件
	if c.NumFlags() > 0 {
		tmp := c.String("file")
		getZipReverse(tmp)
		return nil
	}
	// CRC值
	tmp := c.Args().First()
	pattern := `0x[0-9a-fA-F]{8}`
	m, _ := regexp.MatchString(pattern, tmp)
	if !m {
		log.Println("请输入合法CRC32, 例如: 0x11223344")
		return nil
	}
	crc, _ := strconv.ParseUint(tmp, 0, 32)
	getReverse(uint32(crc), 0, 0)
	return nil
}

func getZipReverse(zipFile string) {
	zr, err := zip.OpenReader(zipFile)
	checkErr(err)

	for _, file := range zr.File {
		if file.FileInfo().IsDir() {
			continue
		}
		log.Printf("found file %v,crc32 0x%08x,file size %v\n", file.Name, file.CRC32, file.FileInfo().Size())
		getReverse(file.CRC32, 0, int(file.FileInfo().Size()))
	}
}
