package main

import (
	"CtiConsole/config"
	"CtiConsole/src/ipo_mtcti3"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/websocket"
	"github.com/spf13/viper"
	"google.golang.org/protobuf/proto"
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
	conn, resp, err := dialer.Dial(socketURL, hdr)
	if nil != err {
		log.Fatal("connect failed:", err)
	} else {
		fmt.Println(resp)
	}

	defer conn.Close()

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	receiveChan := make(chan struct{})
	msg := &ipo_mtcti3.Message{
		Payload: &ipo_mtcti3.Message_Subscribe{
			Subscribe: &ipo_mtcti3.Subscribe{
				SubscribeId: 1,
				Requestid:   1,
				Timeout:     3600,
				Payload: &ipo_mtcti3.Subscribe_Lines{
					Lines: &ipo_mtcti3.SubscribeLines{
						Flags: 7,
					},
				},
			},
		},
	}

	data, err := proto.Marshal(msg)
	log.Printf("raw data %X", data)
	framePrefix := make([]byte, 4)
	framePrefix[0] = 0x00
	framePrefix[1] = 0x00
	framePrefix[2] = 0x00
	framePrefix[3] = 0x01

	conn.WriteMessage(websocket.BinaryMessage, append(framePrefix[:], data[:]...))

	go func() {
		defer close(receiveChan)
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				log.Println("Error occured while receive. ", err)
				return
			}

			if len(msg) > 4 {
				log.Printf("recv: %s", msg)
				realMsg := ipo_mtcti3.Message{}
				err = proto.Unmarshal(msg[4:], &realMsg)
				if err != nil {
					log.Printf("unmarshal msg failed, %s", err)
				} else {
					log.Println("recv msg: ", &realMsg)
				}
			} else {
				log.Printf("Not valid avaya packet frame: %s", msg)
			}

		}
	}()

	// ticker := time.NewTicker(time.Second)
	for {
		select {
		case <-receiveChan:
			return
		case <-interrupt:
			log.Println("interrupt")
			select {
			case <-time.After(time.Second):
			}
			return
		}
	}

}
