package ipo

import (
	"CtiConsole/api/ipo_mtcti3"
	"CtiConsole/config"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"text/tabwriter"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/spf13/viper"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type AsyncWriteFunc func(str string)

type IPO struct {
	Config     *config.Configurations
	Context    string
	AsyncWrite AsyncWriteFunc
	Lines      *ipo_mtcti3.NotifyLines
	Queues     map[string]*ipo_mtcti3.NotifyQueue
	// Users *ipo_mtcti3.NotifyUser;
	// Queue *ipo_mtcti3.NotifyQueue
	conn    *websocket.Conn
	traceOn bool
}

func (ipoSrv *IPO) SetTrace(flag bool) {
	ipoSrv.traceOn = flag
	if flag {
		ipoSrv.WriteLog("Verbose trace on", true)
	} else {
		ipoSrv.WriteLog("Verbose trace off", true)
	}
}

func (ipoSrv *IPO) WriteLog(logStr string, ignorLogFlag bool) {
	if ipoSrv.traceOn || ignorLogFlag {
		ipoSrv.AsyncWrite(logStr)
		// fmt.Println(logStr)
		// fmt.Fprintln(os.Stdout, logStr)
		// os.Stdout.Sync()
	}
}

func (ipoSrv *IPO) GetUsers() []*ipo_mtcti3.LinesUser {
	if ipoSrv.Lines != nil {
		return ipoSrv.Lines.Adduser
	}
	return nil
}

// func (ipoSrv *IPO) GetSysInfo() {
// 	if runtime.GOOS == "windows" {
// 		v, _ := syscall.GetVersion()

// 		majorVer := byte(v)
// 		minorVer := uint8(v >> 8)
// 		buildVer := uint8(v >> 16)
// 		ipoSrv.WriteLog(fmt.Sprintf("Current OS version, Major:%d,Minor:%d, build:%d", majorVer, minorVer, buildVer), false)
// 	}
// }

func (ipoSrv *IPO) GetLinesTable() error {
	if ipoSrv.Lines != nil {
		w := tabwriter.NewWriter(os.Stdout, 10, 1, 5, ' ', 0)
		//blue color: "\033[34m"
		//yellow color: "\033[33m"
		//Green := "\033[32m"
		//no clolor: "\033[0m"
		//;1 bold, ;21 off bold
		//;4 underline, ;24 off underline
		// known issue: colors only works on windows 10 and above.
		fmt.Fprintln(w, "\033[32;1;4muser\tguid\textn\tname")
		for idx, user := range ipoSrv.Lines.Adduser {
			uid, _ := uuid.FromBytes(user.Guid)
			fmt.Fprintf(w, "\033[33;21;24m%d\t\033[0m%s\t%s\t%s\n", idx, uid, user.Extn, user.Name)
		}

		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "\033[32;1;4mqueue\tguid\textn\tname")
		for idx, queue := range ipoSrv.Lines.Addqueue {
			uid, _ := uuid.FromBytes(queue.Guid)
			fmt.Fprintf(w, "\033[33;21;24m%d\t\033[0m%s\t%s\t%s\n", idx, uid, queue.Extn, queue.Name)
		}
		w.Flush()
	} else {
		ipoSrv.WriteLog("Please get line info first", true)
	}
	return nil
}

func (ipoSrv *IPO) GetAllQueuesTable() error {
	if ipoSrv.Queues != nil {
		w := tabwriter.NewWriter(os.Stdout, 10, 1, 5, ' ', 0)
		//blue color: "\033[34m"
		//yellow color: "\033[33m"
		//Green := "\033[32m"
		//no clolor: "\033[0m"
		//;1 bold, ;21 off bold
		//;4 underline, ;24 off underline
		// known issue: colors only works on windows 10 and above.
		var idx int = 0
		fmt.Fprintln(w, "\033[32;1;4mqueue\textn\tname\tkatakananame\temail\tringmode"+
			"\tnoanswertime\tvoicemail\tvoicemailtime\tservicemode")
		for extn, queue := range ipoSrv.Queues {
			idx++
			fmt.Fprintf(w, "\033[33;21;24m%d\t\033[0m%s\t%s\t%s\t%s\t%d"+
				"\t%d\t%t\t%d\t%s\n",
				idx, extn, queue.Name, queue.Katakananame, queue.Email, queue.Ringmode,
				queue.Noanswertime, queue.Voicemail, queue.Voicemailtime, queue.Servicemode)
		}
		w.Flush()

		fmt.Fprintln(w, "")
		for extn, queue := range ipoSrv.Queues {
			fmt.Fprintf(w, "\033[32;1;4m%s Member\textn\tdisabled\n", extn)
			for idx, member := range queue.Queuemembers.Member {
				fmt.Fprintf(w, "\033[33;21;24m%d\t\033[0m%s\t%t\n", idx, member.Extn, member.Disabled)
			}
			fmt.Fprintln(w, "")
		}
		w.Flush()
	} else {
		ipoSrv.WriteLog("Please get queues info first", true)
	}
	return nil
}

func (ipoSrv *IPO) SubscribeLines() error {
	if ipoSrv.conn == nil {
		ipoSrv.WriteLog("Please login first!", true)
		return fmt.Errorf("conn not open, please login first!")
	}

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

	if err != nil {
		return fmt.Errorf("proto.Marshal failed: %s", err)
	} else {
		// fmt.Printf("raw data %X", data)
	}

	framePrefix := make([]byte, 4)
	framePrefix[0] = 0x00
	framePrefix[1] = 0x00
	framePrefix[2] = 0x00
	framePrefix[3] = 0x01

	return ipoSrv.conn.WriteMessage(websocket.BinaryMessage, append(framePrefix[:], data[:]...))
}

func (ipoSrv *IPO) SubscribeAllQueues() error {
	if ipoSrv.conn == nil {
		ipoSrv.WriteLog("Please login first!", true)
		return fmt.Errorf("conn not open, please login first!")
	}

	if ipoSrv.Lines == nil {
		ipoSrv.WriteLog("Please get Lines first!", true)
		return fmt.Errorf("Need get lines first!")
	}

	errstr := ""
	for idx, addqueue := range ipoSrv.Lines.Addqueue {
		err := ipoSrv.subscribeQueue((int32)(idx+100), addqueue)
		if err != nil {
			errstr += fmt.Sprintf("error on sub queue: %s, error info:%s\n", addqueue.Name, err)
		}
	}
	if errstr == "" {
		return nil
	} else {
		return fmt.Errorf("subscribe all queues error: \n%s", errstr)
	}

}

func (ipoSrv *IPO) subscribeQueue(subid int32, queue *ipo_mtcti3.LinesQueue) error {
	if ipoSrv.conn == nil {
		ipoSrv.WriteLog("Please login first!", true)
		return fmt.Errorf("conn not open, please login first!")
	}

	msg := &ipo_mtcti3.Message{
		Payload: &ipo_mtcti3.Message_Subscribe{
			Subscribe: &ipo_mtcti3.Subscribe{
				SubscribeId: subid,
				Requestid:   1,
				Timeout:     0,
				Payload: &ipo_mtcti3.Subscribe_Queue{
					Queue: &ipo_mtcti3.SubscribeQueue{
						Guid:    queue.Guid,
						Flags:   0x3,
						Ccflags: 0x40039,
					},
				},
			},
		},
	}

	data, err := proto.Marshal(msg)

	if err != nil {
		return fmt.Errorf("proto.Marshal failed: %s", err)
	} else {
		// fmt.Printf("raw data %X", data)
	}

	framePrefix := make([]byte, 4)
	framePrefix[0] = 0x00
	framePrefix[1] = 0x00
	framePrefix[2] = 0x00
	framePrefix[3] = 0x01

	return ipoSrv.conn.WriteMessage(websocket.BinaryMessage, append(framePrefix[:], data[:]...))
}

func (ipoSrv *IPO) subscribeQueueByName(queueName string) error {
	if ipoSrv.conn == nil {
		ipoSrv.WriteLog("Please login first!", true)
		return fmt.Errorf("conn not open, please login first!")
	}

	msg := &ipo_mtcti3.Message{
		Payload: &ipo_mtcti3.Message_Subscribe{
			Subscribe: &ipo_mtcti3.Subscribe{
				SubscribeId: 2,
				Requestid:   1,
				Timeout:     0,
				Payload: &ipo_mtcti3.Subscribe_Queue{
					Queue: &ipo_mtcti3.SubscribeQueue{
						Flags:   0x3,
						Ccflags: 0x40039,
						Name:    queueName,
					},
				},
			},
		},
	}

	data, err := proto.Marshal(msg)

	if err != nil {
		return fmt.Errorf("proto.Marshal failed: %s", err)
	} else {
		// fmt.Printf("raw data %X", data)
	}

	framePrefix := make([]byte, 4)
	framePrefix[0] = 0x00
	framePrefix[1] = 0x00
	framePrefix[2] = 0x00
	framePrefix[3] = 0x01

	return ipoSrv.conn.WriteMessage(websocket.BinaryMessage, append(framePrefix[:], data[:]...))
}

func (ipoSrv *IPO) loginFunc(cfg *config.Configurations) (*websocket.Conn, error) {
	socketURL := cfg.Server.Url
	username := cfg.Server.Username
	password := cfg.Server.Password
	hdr := http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))}, "Sec-WebSocket-Protocol": {"openapi"}}
	dialer := *websocket.DefaultDialer

	dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	conn, _, err := dialer.Dial(socketURL, hdr)
	if nil != err {
		err = fmt.Errorf("login failed:%s", err)
		ipoSrv.WriteLog(fmt.Sprint(err), true)
		return nil, err
	} else {
		ipoSrv.WriteLog("login success", true)
		ipoSrv.Context = fmt.Sprintf("%s@%s", username, socketURL)
	}

	go func() {
		// defer close(*ipoSrv.ReceiveChan)
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				ipoSrv.WriteLog(fmt.Sprintf("Error occured while receive. %s", err), false)
				return
			}

			if len(msg) > 4 {
				// fmt.Printf("recv: %s", msg)
				realMsg := ipo_mtcti3.Message{}
				err = proto.Unmarshal(msg[4:], &realMsg)
				if err != nil {
					ipoSrv.WriteLog(fmt.Sprintf("unmarshal msg failed, %s", err), true)
				} else {
					jsonMarshaler := protojson.MarshalOptions{
						Indent:          " ",
						UseProtoNames:   true,
						UseEnumNumbers:  true,
						EmitUnpopulated: true,
					}

					if realMsg.GetNotify() != nil {
						switch py := realMsg.GetNotify().Payload.(type) {
						case *ipo_mtcti3.Notify_Lines:
							ipoSrv.Lines = py.Lines
						case *ipo_mtcti3.Notify_Queue:
							ipoSrv.addOrUpdateQueueList(py.Queue)
						default:
							ipoSrv.WriteLog("Unknown type found!", false)
						}
					}

					jsonstr, err := jsonMarshaler.Marshal(&realMsg)

					if err != nil {
						ipoSrv.WriteLog(fmt.Sprintf("json format msg failed: %s", err), true)
					} else {
						ipoSrv.WriteLog(string(jsonstr), false)
					}
				}
			} else {
				fmt.Printf("Not valid mtcti3 packet frame: %s", msg)
			}
		}
	}()

	return conn, err
}

func (ipoSrv *IPO) addOrUpdateQueueList(queueInfo *ipo_mtcti3.NotifyQueue) {
	if ipoSrv.Queues == nil {
		ipoSrv.Queues = make(map[string]*ipo_mtcti3.NotifyQueue, 10)
	}

	ipoSrv.Queues[queueInfo.Extn] = queueInfo
}

func (ipoSrv *IPO) Login() error {
	if ipoSrv.conn == nil {
		if ipoSrv.Config == nil {
			err := ipoSrv.readConfig()
			if err != nil {
				return fmt.Errorf("Readconfig failed: %s", err)
			}
			ipoSrv.conn, err = ipoSrv.loginFunc(ipoSrv.Config)
			return err
		}

		var err error = nil
		ipoSrv.conn, err = ipoSrv.loginFunc(ipoSrv.Config)
		return err

	} else {
		ipoSrv.WriteLog("already login!", true)
	}

	return nil
}

func (ipoSrv *IPO) readConfig() error {

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")
	err := viper.ReadInConfig()

	if err != nil {
		ipoSrv.WriteLog(fmt.Sprintf("Error reading config file, %s", err), true)
		return err
	}

	err = viper.Unmarshal(&ipoSrv.Config)
	if err != nil {
		ipoSrv.WriteLog(fmt.Sprintf("Unmarshal config file failed, %s", err), true)
		return err
	} else {
		ipoSrv.WriteLog(fmt.Sprintf("Server URL: %s", ipoSrv.Config.Server.Url), false)
		ipoSrv.WriteLog(fmt.Sprintf("Username: %s", ipoSrv.Config.Server.Username), false)
		ipoSrv.WriteLog(fmt.Sprintf("Password: %s", ipoSrv.Config.Server.Password), false)
	}

	return nil
}
