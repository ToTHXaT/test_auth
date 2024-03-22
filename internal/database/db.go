package database

import (
	"context"
	"github.com/ToTHXaT/test_auth/config"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"time"
)

var DB *mongo.Client

func GetClient() *mongo.Client {
	if DB == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		client, err := mongo.Connect(ctx, options.Client().ApplyURI(config.Config.MongoDBURI))
		if err != nil {
			log.Fatal("Couldn't connect to db ", err.Error())
		}
		DB = client
	}
	return DB
}
