package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
	"github.com/micro/go-micro/errors"
	"io"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("%s",
			`
	
使用方法:

1. 将encryptSoftware.exe 和 run.sh 复制到和加密或者解密的文件同一个文件夹下

2. 使用 记事本 打开 run.sh

3. 输入命令, 顺序为 [加密软件名称] [加密1, 解密2] ["需要加密或者解密的文件夹名称", 文件夹名称有时候有中文或者空格, 可能导致不能识别, 因此加上双引号]

   例如加密:
   ./encryptSoftware.exe 1 "【沙雕字幕组】南方公园第二十三季第六集 季终.mp4"
   解密:
   ./encryptSoftware.exe 1 "【沙雕字幕组】南方公园第二十三季第六集 季终.mp4_c"

4. 双击 run.sh 运行软件

**注意: 加密后的文件后缀为_c, 解密后的文件后缀为_d, 将解密后文件的_d 删除, 就可以正常观看

[command] filename

[command]:
1: encrypt 加密
2: decrypt 解密

  e.g.  1 text.txt`)
		return
	}

	if os.Args[1] == "1" {
		t1 := time.Now()
		fmt.Println("Start Enctypt")
		encryptProcess([]byte("12345678"), os.Args[2])
		fmt.Println("Encrypt finished")
		elapsed := time.Since(t1)
		fmt.Printf("Time used: %s, please close the window", elapsed)
		time.Sleep(time.Second*10)
	}


	if os.Args[1] == "2" {
		t1 := time.Now()
		fmt.Println("Start dectypt")
		decryptProcess([]byte("12345678"), os.Args[2])
		fmt.Println("Encrypt finished")
		elapsed := time.Since(t1)
		fmt.Printf("Time used: %s, please close the window", elapsed)
		time.Sleep(time.Second*10)
	}
}

func encryptProcess(key []byte,  filePath string) {
	path := fmt.Sprintf("./%s", filePath)
	fpR, err := os.Open(path)
	if err != nil {
		fmt.Println("open err: ", err)
		return
	}
	defer fpR.Close()

	pathNew := fmt.Sprintf("%s_c", path)
	fpW, err := os.Create(pathNew)
	if err != nil {
		fmt.Println("Create err: ", err)
		return
	}
	defer fpW.Close()

	buff := make([]byte, 4096)
	buffc := make([]byte, 4096)

	for {
		n, err := fpR.Read(buff)
		if err != nil {
			if err == io.EOF {
				fmt.Println("copy finished")
				break
			} else {
				fmt.Println("Read err: ", err)
			}
		}

		buffc, err = desCBCEncrypt(key, buff[:])
		if err != nil {
			fmt.Println("encrypted faild")
			return
		}

		_, err = fpW.Write(buffc[:n])
		if err != nil {
			fmt.Println("Write err: ", err)
			return
		}
		//Sync Read and Write!
	}
}
//加密函数
func desCBCEncrypt(key, plainText []byte) ([]byte, error) {
	//第一版：先实现加解密，不填充（需要输入的数据满足8的倍数）

	//第一步：创建密码接口
	//func NewCipher(key []byte) (cipher.Block, error)
	// 创建并返回一个使用DES算法的cipher.Block接口。
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	//创建与算法分组长度一致的初始化向量
	iv := bytes.Repeat([]byte("1"), block.BlockSize())

	//第二步：创建cbc加密分组
	blockMode := cipher.NewCBCEncrypter(block, iv)

	//fmt.Printf("填充之前的数据: %x\n", plainText)

	//填充环节，一定要在加密之前，否则不满足加密条件
	plainText,_ = paddingNumber(plainText, block.BlockSize())
	//fmt.Printf("填充之后的数据: %x\n", plainText)

	//第三步：加密
	blockMode.CryptBlocks(plainText /*密文*/, plainText /*明文*/)

	return plainText /*密文*/, nil
	//return []byte("加密后的数据"), nil
}

func paddingNumber(src []byte, blocksize int)  ([]byte, error){
	//校验src不能为nil
	if src ==nil {
		return nil, errors.New("1", "src nil", 1)
	}

	//src：20字节
	//blocksize：8
	//a. 找到剩余的字节数，b.求出需要填充：4

	//判断需要添加几个字节
	leftNumber := len(src) %blocksize
	//需要填充的个数
	needNumber := blocksize - leftNumber //4

	//创建一个slice，里面包含needNumber个数的byte
	b := byte(needNumber)
	newSlice := bytes.Repeat([]byte{b}, needNumber) //[]byte {'4', '4','4','4'}

	//将需要添加的字节数转换为byte，追加到src后面返回
	src = append(src, newSlice...)

	return src, nil
}

func decryptProcess(key []byte,  filePath string) {
	path := fmt.Sprintf("./%s", filePath)
	fpR, err := os.Open(path)
	if err != nil {
		fmt.Println("open err: ", err)
		return
	}
	defer fpR.Close()

	pathNew := fmt.Sprintf("%s_d", path)
	fpW, err := os.Create(pathNew)
	if err != nil {
		fmt.Println("Create err: ", err)
		return
	}
	defer fpW.Close()

	buff := make([]byte, 4096)
	buffc := make([]byte, 4096)

	for {
		n, err := fpR.Read(buffc)
		if err != nil {
			if err == io.EOF {
				fmt.Println("copy finished")
				break
			} else {
				fmt.Println("Read err: ", err)
			}
		}

		buff, err = desCBCDecrypt(key, buffc[:])
		if err != nil {
			fmt.Println("encrypted faild")
			return
		}

		_, err = fpW.Write(buff[:n])
		if err != nil {
			fmt.Println("Write err: ", err)
			return
		}
		//Sync Read and Write!
	}
}
//去掉填充的函数
func unPaddingNumber(src []byte) []byte{
	//fmt.Println("unPaddingNumber 被调用...")
	//1. 获取最后一个字符
	lastByte := src[len(src) - 1]

	//2. 将字符转换为截取的数字
	num := int(lastByte)

	//3. 截取原文, 左闭右开
	return src[:len(src) - num]
}

//解密函数
func desCBCDecrypt(key, cipherText []byte) ([]byte, error) {
	//fmt.Println("开始解密....")
	//第一步：创建密码接口
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := bytes.Repeat([]byte("1"), block.BlockSize())

	//第二步：创建CBC分组
	mode := cipher.NewCBCDecrypter(block, iv)

	//第三步：解密
	mode.CryptBlocks(cipherText /*明文*/, cipherText /*密文*/)

	//在解密之后进行数据截取
	cipherText = unPaddingNumber(cipherText)

	return cipherText/*明文*/, nil
	//return []byte("解密后的数据"), nil
}
