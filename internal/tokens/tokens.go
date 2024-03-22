package tokens

import (
	"github.com/ToTHXaT/test_auth/config"
	"github.com/ToTHXaT/test_auth/internal/database"
	"time"
)

type Tokens struct {
	AccessToken          string
	RefreshToken         string
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
}

type tokensWithExpiration struct {
	now               time.Time
	accessDuration    time.Duration
	refreshDuration   time.Duration
	accessExpiration  time.Time
	refreshExpiration time.Time
	accessToken       string
	refreshToken      string
}

func generateTokens(userData *UserData) *tokensWithExpiration {
	now := time.Now()
	accessDuration := time.Duration(config.Config.AccessTokenLifetimeMinutes) * time.Minute
	refreshDuration := time.Duration(config.Config.RefreshTokenLifetimeDays*24) * time.Hour
	accessExpiration := now.Add(accessDuration)
	refreshExpiration := now.Add(refreshDuration)
	accessToken := createAccessToken(userData, now, accessExpiration)
	refreshToken := createRefreshToken()

	return &tokensWithExpiration{
		now,
		accessDuration,
		refreshDuration,
		accessExpiration,
		refreshExpiration,
		accessToken,
		refreshToken,
	}
}

func NewTokens(userData *UserData) (*Tokens, error) {
	allTokens := generateTokens(userData)

	err := database.SetRefreshToken(userData.UserId, allTokens.refreshToken, allTokens.now, allTokens.refreshExpiration)
	if err != nil {
		return nil, err
	}

	return &Tokens{
		AccessToken:          allTokens.accessToken,
		RefreshToken:         allTokens.refreshToken,
		AccessTokenDuration:  allTokens.accessDuration,
		RefreshTokenDuration: allTokens.refreshDuration,
	}, nil
}

func NewTokensWithRefresh(userData *UserData, oldToken string) (*Tokens, error) {
	allTokens := generateTokens(userData)

	err := database.RefreshRefreshToken(userData.UserId, oldToken,
		allTokens.refreshToken, allTokens.now, allTokens.refreshExpiration)
	if err != nil {
		return nil, err
	}

	return &Tokens{
		AccessToken:          allTokens.accessToken,
		RefreshToken:         allTokens.refreshToken,
		AccessTokenDuration:  allTokens.accessDuration,
		RefreshTokenDuration: allTokens.refreshDuration,
	}, nil
}
