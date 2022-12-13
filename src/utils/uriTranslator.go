package utils

import "strings"

type uriTranslator struct {
	dm      string
	redfish string
}

func (u *uriTranslator) DmToRedfish(uri string) string {
	return strings.Replace(uri, u.dm, u.redfish, -1)
}

func (u *uriTranslator) RedfishToDm(uri string) string {
	return strings.Replace(uri, u.redfish, u.dm, -1)
}

var UriTranslator = &uriTranslator{
	dm:      "ODIM",
	redfish: "redfish",
}
