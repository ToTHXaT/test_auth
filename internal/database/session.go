package database

import (
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"time"
)

func hashToken(token string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(token), 8)
	return string(bytes), err
}

func compareTokenAndHash(token string, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(token))
}

func getHashedToken(userId string, rawToken string) (string, error) {
	db := GetClient()
	users := db.Database("authService").Collection("users")

	var res struct {
		UUID     string             `json:"uuid"`
		Sessions []RefreshTokenInfo `json:"sessions"`
	}
	err := users.FindOne(context.Background(), bson.M{"uuid": userId}).Decode(&res)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return "", errors.New("no such user")
		}
		return "", err
	}

	for _, tokenInfo := range res.Sessions {
		if err := compareTokenAndHash(rawToken, tokenInfo.RefreshToken); err == nil {
			return tokenInfo.RefreshToken, nil
		}
	}
	return "", errors.New("no token hash matches given refresh token")
}

func SetRefreshToken(userId string, refreshToken string, issuedAt, expiresAt time.Time) error {
	db := GetClient()
	users := db.Database("authService").Collection("users")

	_, err := getHashedToken(userId, refreshToken)
	if err != nil {
		if err.Error() != "no token hash matches given refresh token" &&
			err.Error() != "no such user" {
			return err
		}
	}

	hashedRefreshToken, err := hashToken(refreshToken)
	if err != nil {
		return err
	}

	opts := options.Update().SetUpsert(true)
	result, err := users.UpdateOne(
		context.Background(),
		bson.M{"uuid": userId},
		bson.M{
			"$addToSet": bson.M{
				"sessions": bson.M{
					"refreshToken": hashedRefreshToken,
					"issued":       issuedAt.UTC(),
					"expires":      expiresAt.UTC(),
				},
			},
		},
		opts,
	)
	if err != nil {
		return err
	}

	if result.MatchedCount != 0 || result.UpsertedCount != 0 {
		return nil
	}
	return errors.New("not added")
}

type RefreshTokenInfo struct {
	RefreshToken string    `json:"refreshToken"`
	Expires      time.Time `json:"expires"`
	Issued       time.Time `json:"issued"`
}

func GetRefreshTokenInfo(userId string, refreshToken string) (*RefreshTokenInfo, error) {
	db := GetClient()
	users := db.Database("authService").Collection("users")

	token, err := getHashedToken(userId, refreshToken)
	if err != nil {
		return nil, err
	}

	var res struct {
		Sessions []RefreshTokenInfo `json:"sessions"`
	}

	ops := options.FindOne().SetProjection(bson.M{"sessions.$": 1})
	err = users.FindOne(context.Background(), bson.M{"sessions.refreshToken": token}, ops).Decode(&res)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.New("refresh token not found")
		}
		return nil, err
	}

	return &res.Sessions[0], nil
}

func RefreshRefreshToken(userId string, oldRefreshToken, newRefreshToken string, issuedAt, expiresAt time.Time) error {
	db := GetClient()
	users := db.Database("authService").Collection("users")

	oldToken, err := getHashedToken(userId, oldRefreshToken)
	if err != nil {
		if err.Error() != "no token hash matches given refresh token" {
			return err
		}
	}

	res, err := users.UpdateOne(
		context.Background(),
		bson.M{"uuid": userId},
		bson.M{"$pull": bson.M{"sessions": bson.M{"refreshToken": oldToken}}},
	)
	if err != nil {
		return err
	}

	if res.MatchedCount == 0 {
		return errors.New("old refresh token is not found")
	}

	return SetRefreshToken(userId, newRefreshToken, issuedAt, expiresAt)
}
