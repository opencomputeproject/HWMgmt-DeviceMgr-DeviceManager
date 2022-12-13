package rest

import (
	"encoding/base64"
	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/context"
	"golang.org/x/crypto/sha3"
	"net/http"
)

type basicAuthHandler struct {
	userName, encryptedPassword string
}

func (b basicAuthHandler) handle(ctx iris.Context) {
	userName, password, ok := ctx.Request().BasicAuth()

	if !ok {
		ctx.StatusCode(http.StatusUnauthorized)
		ctx.JSON("Unexpected Authorization header value")
		return
	}

	if userName != b.userName {
		ctx.StatusCode(http.StatusUnauthorized)
		ctx.JSON("Invalid user or password")
		return
	}

	hash := sha3.New512()
	hash.Write([]byte(password))
	hashSum := hash.Sum(nil)
	hashedPassword := base64.URLEncoding.EncodeToString(hashSum)
	if hashedPassword != b.encryptedPassword {
		ctx.StatusCode(http.StatusUnauthorized)
		ctx.JSON("Invalid user or password")
		return
	}

	ctx.Next()
}

func newBasicAuthHandler(userName, encryptedPassword string) context.Handler {
	return basicAuthHandler{
		userName:          userName,
		encryptedPassword: encryptedPassword,
	}.handle
}
