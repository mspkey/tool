package msp

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

// MongoDB 数据库常用方法
type MongoDB struct {
	Client    *mongo.Client //连接
	OpTimeout time.Duration //单次操作超时时间，SetDB 默认设为 30s；<=0 表示不限制
	database  string        //数据库名称
	mu        sync.RWMutex  //保护 Client/database，避免并发读写冲突
}

// SetDB 初始化数据库 前置条件 需要设置数据库 url
func (c *MongoDB) SetDB(url string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 1. 检查旧客户端，避免连接泄露
	if c.Client != nil {
		// 关闭旧连接（使用独立的上下文，避免主 ctx 已取消）
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer closeCancel()
		if err := c.Client.Disconnect(closeCtx); err != nil {
			return fmt.Errorf("关闭旧数据库连接失败: %w", err)
		}
	}
	// 2. 配置客户端选项（优化连接池参数）
	clientOptions := options.Client().ApplyURI(url)
	clientOptions.SetMaxPoolSize(100)                   // 合理的最大连接数（建议不超过 200）
	clientOptions.SetMinPoolSize(10)                    // 最小连接数（按需设置）
	clientOptions.SetConnectTimeout(30 * time.Second)   // 连接超时（30s 足够）
	clientOptions.SetRetryWrites(true)                  // 开启写重试
	clientOptions.SetReadPreference(readpref.Primary()) // 指定读偏好（主节点）

	// 3. 建立连接（必须传递上下文）
	client, err := mongo.Connect(clientOptions)
	if err != nil {
		return fmt.Errorf("数据库连接失败: %w", err) // 保留原始错误
	}

	// 4. 验证连接（关键：确保客户端能正常访问数据库）
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer pingCancel()
	if err := client.Ping(pingCtx, readpref.Primary()); err != nil {
		// 验证失败时关闭客户端，避免资源泄露
		_ = client.Disconnect(context.Background())
		return fmt.Errorf("数据库连接验证失败: %w", err)
	}

	// 5. 赋值客户端，设置默认操作超时
	c.Client = client
	c.OpTimeout = 30 * time.Second
	return nil
}

// CloseDB 优雅关闭数据库连接
func (c *MongoDB) CloseDB() error {
	c.mu.Lock()
	defer c.mu.Unlock()

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
	c.mu.Lock()
	defer c.mu.Unlock()
	c.database = dataBaseName
}

// opCtx 派生单次操作的上下文（带超时）并返回对应集合
func (c *MongoDB) opCtx(collection string) (*mongo.Collection, context.Context, context.CancelFunc) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	coll := c.Client.Database(c.database).Collection(collection)
	if c.OpTimeout > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), c.OpTimeout)
		return coll, ctx, cancel
	}
	return coll, context.Background(), func() {}
}

// Insert 插入单条数据
func (c *MongoDB) Insert(collection string, document interface{}) error {
	coll, ctx, cancel := c.opCtx(collection)
	defer cancel()
	if _, err := coll.InsertOne(ctx, document); err != nil {
		return fmt.Errorf("插入数据失败: %w", err)
	}
	return nil
}

// InsertMany 插入多条数据
func (c *MongoDB) InsertMany(collection string, document []interface{}) error {
	coll, ctx, cancel := c.opCtx(collection)
	defer cancel()
	if _, err := coll.InsertMany(ctx, document); err != nil {
		return fmt.Errorf("批量插入数据失败: %w", err)
	}
	return nil
}

// UpDateSetOne 更新数据 需要$set
func (c *MongoDB) UpDateSetOne(collection string, find, update interface{}) error {
	coll, ctx, cancel := c.opCtx(collection)
	defer cancel()
	if _, err := coll.UpdateOne(ctx, find, update); err != nil {
		return fmt.Errorf("数据更新失败: %w", err)
	}
	return nil
}

// UpDateSetMany 更新数据 需要$set
func (c *MongoDB) UpDateSetMany(collection string, find, update interface{}) error {
	coll, ctx, cancel := c.opCtx(collection)
	defer cancel()
	if _, err := coll.UpdateMany(ctx, find, update); err != nil {
		return fmt.Errorf("数据更新失败: %w", err)
	}
	return nil
}

// UpDateOne 更新数据单条 不需要$set
func (c *MongoDB) UpDateOne(collection string, find, update interface{}) error {
	coll, ctx, cancel := c.opCtx(collection)
	defer cancel()
	if _, err := coll.UpdateOne(ctx, find, bson.M{"$set": update}); err != nil {
		return fmt.Errorf("数据更新失败: %w", err)
	}
	return nil
}

// UpdateMany 更新数据多条不需要$set
func (c *MongoDB) UpdateMany(collection string, find, update interface{}) error {
	coll, ctx, cancel := c.opCtx(collection)
	defer cancel()
	if _, err := coll.UpdateMany(ctx, find, bson.M{"$set": update}); err != nil {
		return fmt.Errorf("数据更新失败: %w", err)
	}
	return nil
}

// DeleteOne 删除单条数据
func (c *MongoDB) DeleteOne(collection string, find interface{}) (int64, error) {
	coll, ctx, cancel := c.opCtx(collection)
	defer cancel()
	one, err := coll.DeleteOne(ctx, find)
	if err != nil {
		return 0, fmt.Errorf("删除数据失败: %w", err)
	}
	return one.DeletedCount, nil
}

// DeleteMany 删除多条数据
func (c *MongoDB) DeleteMany(collection string, find interface{}) (int64, error) {
	coll, ctx, cancel := c.opCtx(collection)
	defer cancel()
	one, err := coll.DeleteMany(ctx, find)
	if err != nil {
		return 0, fmt.Errorf("删除数据失败: %w", err)
	}
	return one.DeletedCount, nil
}

// FindOne 查询单个信息
func (c *MongoDB) FindOne(collection string, find interface{}, Data interface{}) error {
	coll, ctx, cancel := c.opCtx(collection)
	defer cancel()
	if err := coll.FindOne(ctx, find).Decode(Data); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return errors.New("数据不存在")
		}
		return fmt.Errorf("查询数据失败: %w", err)
	}
	return nil
}

// FindOneAndUpdate 更新单条数据 不需要$set
func (c *MongoDB) FindOneAndUpdate(collection string, find interface{}, update interface{}) error {
	coll, ctx, cancel := c.opCtx(collection)
	defer cancel()
	res := coll.FindOneAndUpdate(ctx, find, bson.M{"$set": update})
	if err := res.Err(); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return errors.New("没有匹配的数据")
		}
		return fmt.Errorf("数据更新失败: %w", err)
	}
	return nil
}

// FindMany 查询多个信息
func (c *MongoDB) FindMany(collection string, find interface{}, limit, skip int64, Data interface{}) error {
	coll, ctx, cancel := c.opCtx(collection)
	defer cancel()
	opts := options.Find().SetLimit(limit).SetSkip(skip)
	cursor, err := coll.Find(ctx, find, opts)
	if err != nil {
		return fmt.Errorf("查询数据失败: %w", err)
	}
	if err = cursor.All(ctx, Data); err != nil {
		return fmt.Errorf("解析数据失败: %w", err)
	}
	return nil
}

// FindManyOpt 查询多个信息,附加查询条件
func (c *MongoDB) FindManyOpt(collection string, find interface{}, Data interface{}, findOptions *options.FindOptionsBuilder) error {
	coll, ctx, cancel := c.opCtx(collection)
	defer cancel()
	cursor, err := coll.Find(ctx, find, findOptions)
	if err != nil {
		return fmt.Errorf("查询数据失败: %w", err)
	}
	if err = cursor.All(ctx, Data); err != nil {
		return fmt.Errorf("解析数据失败: %w", err)
	}
	return nil
}

// FindManyAll 查询多个信息
func (c *MongoDB) FindManyAll(collection string, find interface{}, Data interface{}) error {
	coll, ctx, cancel := c.opCtx(collection)
	defer cancel()
	cursor, err := coll.Find(ctx, find)
	if err != nil {
		return fmt.Errorf("查询数据失败: %w", err)
	}
	if err = cursor.All(ctx, Data); err != nil {
		return fmt.Errorf("解析数据失败: %w", err)
	}
	return nil
}

// Count 计数
func (c *MongoDB) Count(collection string, find interface{}) (int64, error) {
	coll, ctx, cancel := c.opCtx(collection)
	defer cancel()
	return coll.CountDocuments(ctx, find)
}

// Context 返回带单次操作超时的上下文，调用方使用完后必须调用 cancel
func (c *MongoDB) Context() (context.Context, context.CancelFunc) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.OpTimeout > 0 {
		return context.WithTimeout(context.Background(), c.OpTimeout)
	}
	return context.Background(), func() {}
}

// CollectionOps 其他选项用于使用原生库函数
// 返回集合与带超时的上下文，调用方使用完后必须调用 cancel 释放
func (c *MongoDB) CollectionOps(collection string) (*mongo.Collection, context.Context, context.CancelFunc) {
	return c.opCtx(collection)
}
