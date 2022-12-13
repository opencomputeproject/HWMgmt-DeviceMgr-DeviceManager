package rest

import (
	"devicemanager/config"
	"github.com/ODIM-Project/ODIM/lib-dmtf/model"
	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/context"
	"net/http"
)

type managersCollectionHandler struct {
	managersCollection model.Collection
}

func (mc *managersCollectionHandler) handle(ctx iris.Context) {
	ctx.JSON(mc.managersCollection)
	ctx.StatusCode(http.StatusOK)
}

func newManagersCollectionHandler(cfg config.Config) context.Handler {
	return (&managersCollectionHandler{managersCollection: newManagersCollection(cfg)}).handle
}

func newManagersCollection(cfg config.Config) model.Collection {
	members := []*model.Link{{
		Oid: "/ODIM/v1/Managers/" + cfg.RootServiceUUID,
	}}

	return model.Collection{
		ODataContext: "/ODIM/v1/$metadata#ManagerCollection.ManagerCollection",
		ODataID:      "/ODIM/v1/Managers",
		ODataType:    "#ManagerCollection.ManagerCollection",
		Description:  "Managers collection",
		Name:         "Managers",
		Members:      members,
		MembersCount: len(members),
	}
}
