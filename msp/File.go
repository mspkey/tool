package msp

import (
	"encoding/json"
	"go.mongodb.org/mongo-driver/bson"
	"io/ioutil"
	"os"
)

type File struct {
}

//ReadTxt 文件读取 path:路径  适合小文件读取123
func (c *File) ReadTxt(path string) (str string, err error) {

	op, err := os.Open(path)
	if err != nil {
		return
	}
	defer op.Close()
	buf, _ := ioutil.ReadAll(op)
	str = string(buf)
	err = nil
	return
}

//WriteJson 写入json配置文件
func (c *File) WriteJson(path string, str map[string]interface{}) error {

	//创建文件（并打开）
	filePtr, err := os.Create(path)
	if err != nil {
		return err
	}
	defer filePtr.Close()

	//创建基于文件的JSON编码器
	encoder := json.NewEncoder(filePtr)

	//将实例编码到文件中
	err = encoder.Encode(str)
	if err != nil {
		return err
	}
	return nil
}

//ReadConFig  读取配置文件
func (c *File) ReadConFig(path string) (bson.M, error) {
	file, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t1 bson.M
	err = json.Unmarshal(file, &t1)
	if err != nil {
		return nil, err
	}
	return t1, nil
}
