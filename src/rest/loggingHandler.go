package rest

import (
	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/context"
	"github.com/sirupsen/logrus"
)

type loggingHandler struct {
}

func (l *loggingHandler) handle(ctx iris.Context) {
	logrus.Debugf("request: %s on %s", ctx.Request().Method, ctx.Request().URL.String())
	ctx.Next()
}

func newLoggingHandler() context.Handler {
	return new(loggingHandler).handle
}
