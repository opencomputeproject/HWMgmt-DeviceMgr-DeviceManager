package redfish

type RequestInformation struct {
	Host     string `json:"ManagerAddress"`
	Username string `json:"UserName"`
	Password []byte `json:"Password"`
	Body     []byte `json:"PostBody"`
	Location string `json:"Location"`
	SystemID string `json:"SystemID"`
}
