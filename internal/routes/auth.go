package routes

import (
	"encoding/base64"
	"github.com/ToTHXaT/test_auth/internal/tokens"
	"github.com/gin-gonic/gin"
	"time"
)

func Login(c *gin.Context) {
	userData := tokens.UserData{}
	if err := c.BindJSON(&userData); err != nil {
		c.JSON(400, gin.H{"error": err})
		return
	}

	allTokens, err := tokens.NewTokens(&userData)

	if err != nil {
		c.JSON(400, gin.H{"error": err})
		return
	}

	base64RefreshToken := base64.StdEncoding.EncodeToString([]byte(allTokens.RefreshToken))

	c.SetCookie("access_token", allTokens.AccessToken, int(allTokens.AccessTokenDuration.Seconds()), "/", "localhost", true, true)
	c.SetCookie("refresh_token", base64RefreshToken, int(allTokens.RefreshTokenDuration.Seconds()), "/refresh", "localhost", true, true)

	c.JSON(200, gin.H{"success": true})

}

func Refresh(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(401, gin.H{
			"error": "no refresh token present",
		})
		return
	}
	accessToken, err := c.Cookie("access_token")
	if err != nil {
		c.JSON(401, gin.H{
			"error": "no access token present",
		})
		return
	}

	accessTokenInfo, err := tokens.GetDataFromAccessToken(accessToken)
	if err != nil {
		c.JSON(400, gin.H{
			"error": err.Error(),
		})
		return
	}

	rawRefreshToken, err := base64.StdEncoding.DecodeString(refreshToken)
	if err != nil {
		c.JSON(400, gin.H{
			"error": err.Error(),
		})
		return
	}
	refreshToken = string(rawRefreshToken)

	refreshTokenInfo, err := tokens.GetDataFromRefreshToken(accessTokenInfo.UserId, refreshToken)
	if err != nil {
		c.JSON(400, gin.H{
			"error": err.Error(),
		})
		return
	}
	if accessTokenInfo.IssuedAt.Equal(refreshTokenInfo.Issued) {
		c.JSON(401, gin.H{
			"error": "access token and refresh token do not match",
		})
		return
	}
	if time.Now().After(refreshTokenInfo.Expires) {
		c.JSON(401, gin.H{
			"error": "refresh token has expired",
		})
		return
	}

	allTokens, err := tokens.NewTokensWithRefresh(&tokens.UserData{UserId: accessTokenInfo.UserId}, refreshTokenInfo.RefreshToken)
	if err != nil {
		c.JSON(400, gin.H{"error": err})
		return
	}

	base64RefreshToken := base64.StdEncoding.EncodeToString([]byte(allTokens.RefreshToken))

	c.SetCookie("access_token", allTokens.AccessToken, int(allTokens.AccessTokenDuration.Seconds()), "/", "localhost", true, true)
	c.SetCookie("refresh_token", base64RefreshToken, int(allTokens.RefreshTokenDuration.Seconds()), "/refresh", "localhost", true, true)

	c.JSON(200, gin.H{"success": true})
}
