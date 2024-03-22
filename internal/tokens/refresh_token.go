package tokens

import (
	"github.com/ToTHXaT/test_auth/internal/database"
	"github.com/google/uuid"
	"log"
)

func createRefreshToken() string {
	token, err := uuid.NewUUID()
	if err != nil {
		log.Fatal(err)
	}
	tokenString := token.String()
	return tokenString
}

func GetDataFromRefreshToken(userId string, token string) (*database.RefreshTokenInfo, error) {
	tokenInfo, err := database.GetRefreshTokenInfo(userId, token)
	return tokenInfo, err
}
