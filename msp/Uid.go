package msp

import (
	uuid "github.com/satori/go.uuid"
)

//GetUID 生成一个唯一的UID
func GetUID() string {
	var err error
	u1 := uuid.Must(uuid.NewV4(), err)
	return u1.String()
}
