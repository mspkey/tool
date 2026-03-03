package msp

import (
	"context"
	"errors"
	"fmt"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
	"time"
)

// MongoDB 数据库常用方法
type MongoDB struct {
	Client   *mongo.Client   //连接
	Ctx      context.Context //环境
	database string          //数据库名称
}

// SetDB 初始化数据库 前置条件 需要设置数据库 url
func (c *MongoDB) SetDB(url string) error {
	// 1. 检查旧客户端，避免连接泄露
	if c.Client != nil {
		// 关闭旧连接（使用独立的上下文，避免主 ctx 已取消）
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer closeCancel()
		if err := c.Client.Disconnect(closeCtx); err != nil {
			return fmt.Errorf("关闭旧数据库连接失败: %w", err)
		}
	}

	// 2. 初始化上下文（推荐使用可取消的 ctx，而非 background）
	c.Ctx, _ = context.WithCancel(context.Background()) // 可在外部调用 cancel 关闭连接

	// 3. 配置客户端选项（优化连接池参数）
	clientOptions := options.Client().ApplyURI(url)
	clientOptions.SetMaxPoolSize(100)                   // 合理的最大连接数（建议不超过 200）
	clientOptions.SetMinPoolSize(10)                    // 最小连接数（按需设置）
	clientOptions.SetConnectTimeout(30 * time.Second)   // 连接超时（30s 足够）
	clientOptions.SetRetryWrites(true)                  // 新增：开启写重试
	clientOptions.SetReadPreference(readpref.Primary()) // 新增：指定读偏好（主节点）

	// 4. 建立连接（必须传递上下文）
	client, err := mongo.Connect(clientOptions)
	if err != nil {
		return fmt.Errorf("数据库连接失败: %w", err) // 保留原始错误
	}

	// 5. 验证连接（关键：确保客户端能正常访问数据库）
	pingCtx, pingCancel := context.WithTimeout(c.Ctx, 10*time.Second)
	defer pingCancel()
	if err := client.Ping(pingCtx, readpref.Primary()); err != nil {
		// 验证失败时关闭客户端，避免资源泄露
		_ = client.Disconnect(context.Background())
		return fmt.Errorf("数据库连接验证失败: %w", err)
	}

	// 6. 赋值客户端
	c.Client = client
	return nil
}

// CloseDB 优雅关闭数据库连接（新增：配套的关闭方法）
func (c *MongoDB) CloseDB() error {
	if c.Client == nil {
		return nil
	}
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer closeCancel()
	if err := c.Client.Disconnect(closeCtx); err != nil {
		return fmt.Errorf("关闭数据库连接失败: %w", err)
	}
	c.Client = nil
	return nil
}

func (c *MongoDB) SetDataBase(dataBaseName string) {
	c.database = dataBaseName
}

// Insert 插入单条数据
func (c *MongoDB) Insert(Collection string, document interface{}) error {

	_, err := c.Client.Database(c.database).Collection(Collection).InsertOne(c.Ctx, document)
	if err != nil {
		return errors.New("插入错误,该数据已存在")
	}
	return nil
}

// InsertMany 插入多条数据
func (c *MongoDB) InsertMany(collection string, document []interface{}) error {

	_, err := c.Client.Database(c.database).Collection(collection).InsertMany(c.Ctx, document)
	if err != nil {
		return errors.New("插入错误,该数据已存在")
	}
	return nil
}

// UpDate 更新数据 需要$set
func (c *MongoDB) UpDate(collection string, find, update interface{}) error {

	_, err := c.Client.Database(c.database).Collection(collection).UpdateMany(c.Ctx, find, update)
	if err != nil {
		return errors.New("数据更新失败")
	}
	return nil
}

// UpDateOne 更新数据单条 不需要$set
func (c *MongoDB) UpDateOne(collection string, find, update interface{}) error {

	res := c.Client.Database(c.database).Collection(collection).FindOneAndUpdate(c.Ctx, find, bson.M{
		"$set": update,
	})
	if res.Err() != nil {
		return errors.New("数据更新失败")
	}
	return nil
}

// UpdateMany 更新数据多条不需要$set
func (c *MongoDB) UpdateMany(collection string, find, update interface{}) error {

	_, err := c.Client.Database(c.database).Collection(collection).UpdateMany(c.Ctx, find, bson.M{
		"$set": update,
	})
	if err != nil {
		return errors.New("数据更新失败")
	}

	return nil
}

// DeleteOne 删除单条数据
func (c *MongoDB) DeleteOne(collection string, find interface{}) (int64, error) {

	one, err := c.Client.Database(c.database).Collection(collection).DeleteOne(c.Ctx, find)
	if err != nil {
		return 0, errors.New("没有可删除的数据")
	}
	return one.DeletedCount, nil
}

// DeleteMany 删除多条数据
func (c *MongoDB) DeleteMany(collection string, find interface{}) (int64, error) {

	one, err := c.Client.Database(c.database).Collection(collection).DeleteMany(c.Ctx, find)
	if err != nil {
		return 0, errors.New("没有可删除的数据")
	}
	return one.DeletedCount, nil
}

// FindOne 查询单个信息
func (c *MongoDB) FindOne(collection string, find interface{}, Data interface{}) error {

	one := c.Client.Database(c.database).Collection(collection).FindOne(c.Ctx, find)
	err := one.Decode(Data)
	if err != nil {
		return errors.New("数据不存在")
	}
	return nil
}

// FindMany 查询多个信息
func (c *MongoDB) FindMany(collection string, find interface{}, limit, skip int64, Data interface{}) error {

	opts := options.Find().SetLimit(limit).SetSkip(skip)
	one, err := c.Client.Database(c.database).Collection(collection).Find(c.Ctx, find, opts)
	err = one.All(c.Ctx, Data)
	if err != nil {
		return errors.New("数据不存在")
	}
	return nil
}

// FindManyOpt 查询多个信息,附加查询条件
func (c *MongoDB) FindManyOpt(collection string, find interface{}, Data interface{}, findOptions *options.FindOptionsBuilder) error {
	one, err := c.Client.Database(c.database).Collection(collection).Find(c.Ctx, find, findOptions)
	if err != nil {
		return err
	}
	err = one.All(c.Ctx, Data)
	if err != nil {
		return errors.New("数据不存在")
	}
	return nil
}

// FindManyAll 查询多个信息
func (c *MongoDB) FindManyAll(collection string, find interface{}, Data interface{}) error {

	one, err := c.Client.Database(c.database).Collection(collection).Find(c.Ctx, find)
	err = one.All(c.Ctx, Data)
	if err != nil {
		return errors.New("数据不存在")
	}
	return nil
}

// Count 计数
func (c *MongoDB) Count(collection string, find interface{}) (int64, error) {
	documents, err := c.Client.Database(c.database).Collection(collection).CountDocuments(c.Ctx, find)
	return documents, err
}

// CollectionOps 其他选项用于使用原生库函数
func (c *MongoDB) CollectionOps(collection string) *mongo.Collection {
	res := c.Client.Database(c.database).Collection(collection)
	return res
}
