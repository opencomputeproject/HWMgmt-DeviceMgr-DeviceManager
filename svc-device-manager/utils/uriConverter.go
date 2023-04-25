package utils

import "strings"

type uriConverter struct {
	dm      string
	redfish string
}

func (u *uriConverter) DmToRedfish(uri string) string {
	return strings.Replace(uri, u.dm, u.redfish, -1)
}

func (u *uriConverter) RedfishToDm(uri string) string {
	return strings.Replace(uri, u.redfish, u.dm, -1)
}

var UriConverter = &uriConverter{
	dm:      "ODIM",
	redfish: "redfish",
}
