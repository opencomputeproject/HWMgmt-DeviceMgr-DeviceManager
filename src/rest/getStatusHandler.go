package rest

import (
	"devicemanager/config"
	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/context"
	"time"
)

const deviceManagerName = "Device Manager"

// StatusResponse holds the information of response of Device Manager Status
type StatusResponse struct {
	Comment         string          `json:"_comment"`
	Name            string          `json:"Name"`
	Version         string          `json:"Version"`
	Status          Status          `json:"Status"`
	EventMessageBus EventMessageBus `json:"EventMessageBus"`
}

// Status holds information of Device Manager Status
type Status struct {
	Available string `json:"Available"`
	Uptime    string `json:"Uptime"`
	TimeStamp string `json:"TimeStamp"`
}

// EventMessageBus holds the  information of  EMB Broker type and EMBQueue information
type EventMessageBus struct {
	EmbType  string     `json:"EmbType"`
	EmbQueue []EmbQueue `json:"EmbQueue"`
}

// EmbQueue holds the  information of Queue Name and Queue Description
type EmbQueue struct {
	QueueName string `json:"EmbQueueName"`
	QueueDesc string `json:"EmbQueueDesc"`
}

type statusHandler struct {
	status          *Status
	startupTime     time.Time
	firmwareVersion string
}

func (s *Status) Init() {
	s.RefreshTimeStampAndUptime(time.Now())
	s.Available = "Yes"
	s.Uptime = s.TimeStamp
}

func (s *Status) RefreshTimeStampAndUptime(startupTime time.Time) {
	s.TimeStamp = time.Now().Format(time.RFC3339)
	s.Uptime = time.Since(startupTime).String()
}

func (sh statusHandler) handle(ctx iris.Context) {
	sh.status.RefreshTimeStampAndUptime(sh.startupTime)
	var resp = StatusResponse{
		Comment: "Device Manager",
		Name:    deviceManagerName,
		Status:  *sh.status,
		Version: sh.firmwareVersion,
	}
	ctx.JSON(resp)
}

func newStatusHandler(cfg config.Config) context.Handler {
	status := new(Status)
	status.Init()
	return statusHandler{
		status:          status,
		startupTime:     time.Now(),
		firmwareVersion: cfg.FirmwareVersion,
	}.handle
}
