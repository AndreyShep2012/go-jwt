package main

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go/v4"
)

//Claims -
type Claims struct {
	jwt.StandardClaims
	Username string `json:"username"`
}

func main() {
	signingKey := getSigningKey()

	token, err := createToken("user", signingKey)
	if err != nil {
		log.Fatal(err)
	}

	log.Println(token)

	user, err := parseToken(token, signingKey)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("user: ", user)
}

func getSigningKey() []byte {
	return []byte("some_string")
}

func createToken(user string, signingKey []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &Claims{
		StandardClaims: jwt.StandardClaims{
			IssuedAt: jwt.At(time.Now()),
		},
		Username: user,
	})

	return token.SignedString(signingKey)
}

func parseToken(accessToken string, signingKey []byte) (string, error) {
	token, err := jwt.ParseWithClaims(accessToken, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return signingKey, nil
	})

	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims.Username, nil
	}

	return "", errors.New("ErrInvalidAccessToken")
}
