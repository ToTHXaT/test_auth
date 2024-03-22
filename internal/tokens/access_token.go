package tokens

import (
	"errors"
	"github.com/golang-jwt/jwt"
	"log"
	"time"
)

type UserData struct {
	UserId string `json:"user_id"`
}

type AccessTokenData struct {
	UserData
	ExpiresAt time.Time
	IssuedAt  time.Time
}

type UserClaims struct {
	jwt.StandardClaims
	UserId string `json:"user_id"`
}

func createAccessToken(u *UserData, issuedAt, expiresAt time.Time) string {
	claims := UserClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiresAt.UTC().Unix(),
			IssuedAt:  issuedAt.UTC().Unix(),
		},
		UserId: u.UserId,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, &claims)
	tokenString, err := token.SignedString([]byte("1234"))
	if err != nil {
		log.Fatal(err)
	}

	return tokenString
}

func GetDataFromAccessToken(accessToken string) (*AccessTokenData, error) {
	claims := &UserClaims{}
	token, err := jwt.ParseWithClaims(accessToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("1234"), nil
	})

	if err != nil {
		var v *jwt.ValidationError
		errors.As(err, &v)
		if v.Errors != jwt.ValidationErrorExpired {
			return nil, err
		}
	}

	var ok bool
	claims, ok = token.Claims.(*UserClaims)
	if !ok {
		return nil, errors.New("invalid access token")
	}

	return &AccessTokenData{
		UserData: UserData{
			UserId: claims.UserId,
		},
		ExpiresAt: time.Unix(claims.StandardClaims.ExpiresAt, 0),
		IssuedAt:  time.Unix(claims.StandardClaims.IssuedAt, 0),
	}, nil
}
