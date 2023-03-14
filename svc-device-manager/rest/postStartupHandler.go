package rest

import (
	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/context"
	"net/http"
)

type startupHandler struct {
}

func (s startupHandler) handle(ctx iris.Context) {
	ctx.StatusCode(http.StatusOK)
}

func newStartupHandler() context.Handler {
	return new(startupHandler).handle
}
