package main

import (
	manager "devicemanager/demo_test/proto"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"os"
	"testing"
)

var IpAddress = os.Getenv("IP_ADDRESS")
var UserName = os.Getenv("BASIC_AUTH_USERNAME")
var Password = os.Getenv("BASIC_AUTH_PASSWORD")
var managerAddress = "localhost:31085"

var conn *grpc.ClientConn
var cc manager.DeviceManagementClient
var ctx context.Context

func TestPostSimpleUpdate(t *testing.T) {
	conn, err := grpc.Dial(managerAddress, grpc.WithInsecure())
	if err != nil {
		logrus.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	cc = manager.NewDeviceManagementClient(conn)
	ctx = context.Background()

	attach(t)
	login(t)
	simpleUpdate := new(manager.SimpleUpdateRequest)
	simpleUpdate.IpAddress = IpAddress
	simpleUpdate.UserOrToken = UserName
	simpleUpdate.ImageURI = "imageURI"
	task, error := cc.SimpleUpdate(ctx, simpleUpdate)
	assert.Nil(t, error)
	assert.Contains(t, task.TaskURI, "redfish/v1/TaskService/TaskMonitors/")
	detach(t)
}

func TestInvalidPostSimpleUpdate(t *testing.T) {
	conn, err := grpc.Dial(managerAddress, grpc.WithInsecure())
	if err != nil {
		logrus.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	cc = manager.NewDeviceManagementClient(conn)
	ctx = context.Background()

	attach(t)
	login(t)
	simpleUpdate := new(manager.SimpleUpdateRequest)
	simpleUpdate.IpAddress = IpAddress
	simpleUpdate.UserOrToken = UserName
	simpleUpdate.ImageURI = ""
	_, error := cc.SimpleUpdate(ctx, simpleUpdate)

	assert.NotEmpty(t, error)
	detach(t)
}

func attach(t *testing.T) {
	deviceInfo := new(manager.DeviceInfo)
	deviceInfo.IpAddress = IpAddress
	deviceInfo.DetectDevice = true
	deviceInfo.PassAuth = false
	deviceInfo.Frequency = 180

	var deviceList manager.DeviceList
	deviceList.Device = append(deviceList.Device, deviceInfo)
	_, err := cc.SendDeviceList(ctx, &deviceList)
	assert.Nil(t, err)
}

func login(t *testing.T) {
	deviceAccount := new(manager.DeviceAccount)
	deviceAccount.IpAddress = IpAddress
	deviceAccount.ActUsername = UserName
	deviceAccount.ActPassword = Password

	basicAuth := new(manager.BasicAuth)
	basicAuth.Enabled = true
	basicAuth.UserName = UserName
	basicAuth.Password = Password

	deviceAccount.BasicAuth = basicAuth
	deviceAccount, err := cc.LoginDevice(ctx, deviceAccount)
	assert.Nil(t, err)
	assert.NotEmpty(t, deviceAccount)
}

func detach(t *testing.T) {
	device := new(manager.Device)
	device.IpAddress = IpAddress
	device.UserOrToken = UserName

	_, err := cc.DeleteDeviceList(ctx, device)
	assert.Nil(t, err)
}
