package main

import (
	"CtiConsole/config"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/websocket"
	"github.com/spf13/viper"
)

func main() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")

	var cfg config.Configurations
	err := viper.ReadInConfig()

	if err != nil {
		log.Fatal("Error reading config file, ", err)
	}

	err = viper.Unmarshal(&cfg)
	if err != nil {
		log.Fatal("Unmarshal config file failed, ", err)
	} else {
		log.Println("Server URL: ", cfg.Server.Url)
		log.Println("Username: ", cfg.Server.Username)
		log.Println("Password: ", cfg.Server.Password)
	}

	socketURL := cfg.Server.Url
	username := cfg.Server.Username
	password := cfg.Server.Password
	hdr := http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))}, "Sec-WebSocket-Protocol": {"openapi"}}
	dialer := *websocket.DefaultDialer

	dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	_, resp, err := dialer.Dial(socketURL, hdr)
	if nil != err {
		log.Fatal("connect failed:", err)
	} else {
		fmt.Println(resp)
	}

}
