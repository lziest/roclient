package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/cloudflare/redoctober/client"
	"github.com/cloudflare/redoctober/core"

	"code.google.com/p/gopass"
)

var action, user, pswd, server, caPath string

var owners, lefters, righters, inPath, labels, outPath string

var uses int

var time, users string

func registerFlags() {
	flag.StringVar(&action, "action", "", "client action")
	flag.StringVar(&server, "server", "localhost:8080", "server address")
	flag.StringVar(&caPath, "ca", "", "ca file path")
	flag.StringVar(&owners, "owners", "", "comma separated owner list")
	flag.StringVar(&users, "users", "", "comma separated user list")
	flag.IntVar(&uses, "uses", 0, "number of delegated key uses")
	flag.StringVar(&time, "time", "0h", "duration of delegated key uses")
	flag.StringVar(&lefters, "left", "", "comma separated left owners")
	flag.StringVar(&righters, "right", "", "comma separated right owners")
	flag.StringVar(&labels, "labels", "", "comma separated labels")
	flag.StringVar(&inPath, "in", "", "input data file")
	flag.StringVar(&outPath, "out", "", "output data file")
	flag.StringVar(&user, "user", "", "username")
	flag.StringVar(&pswd, "password", "", "password")
}

func getUserCredentials() {
	if user == "" || pswd == "" {
		fmt.Print("Username:")
		fmt.Scanf("%s", &user)
		var err error
		pswd, err = gopass.GetPass("Password:")
		processError(err)
	}
}

func processError(err error) {
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(2)
	}
}

func processCSL(s string) []string {
	if s == "" {
		return nil
	}

	return strings.Split(s, ",")
}

func main() {
	registerFlags()
	flag.Parse()
	server, err := client.NewRemoteServer(server, caPath)
	processError(err)
	switch action {
	case "create":
		getUserCredentials()
		req := core.CreateRequest{
			Name:     user,
			Password: pswd,
		}
		resp, err := server.Create(req)
		processError(err)
		fmt.Printf("%v", resp.Status)
	case "delegate":
		getUserCredentials()
		req := core.DelegateRequest{
			Name:     user,
			Password: pswd,
			Uses:     uses,
			Time:     time,
			Users:    processCSL(users),
			Labels:   processCSL(labels),
		}
		resp, err := server.Delegate(req)
		processError(err)
		fmt.Printf("%v\n", resp.Status)
	case "summary":
		getUserCredentials()
		req := core.SummaryRequest{
			Name:     user,
			Password: pswd,
		}
		resp, err := server.Summary(req)
		processError(err)
		fmt.Printf("%v\n", resp)
	case "encrypt":
		getUserCredentials()
		inBytes, err := ioutil.ReadFile(inPath)
		processError(err)
		req := core.EncryptRequest{
			Name:        user,
			Password:    pswd,
			Owners:      processCSL(owners),
			LeftOwners:  processCSL(lefters),
			RightOwners: processCSL(righters),
			Labels:      processCSL(labels),
			Data:        inBytes,
		}

		resp, err := server.Encrypt(req)
		processError(err)
		fmt.Println("Response Status:", resp.Status)
		ioutil.WriteFile(outPath, resp.Response, 0644)
	case "decrypt":
		getUserCredentials()
		inBytes, err := ioutil.ReadFile(inPath)
		processError(err)
		req := core.DecryptRequest{
			Name:     user,
			Password: pswd,
			Data:     inBytes,
		}

		resp, err := server.Decrypt(req)
		processError(err)
		var msg core.DecryptWithDelegates
		err = json.Unmarshal(resp.Response, &msg)
		processError(err)
		fmt.Println("Response Status:", resp.Status)
		fmt.Println("Secure:", msg.Secure)
		fmt.Println("Delegates:", msg.Delegates)
		ioutil.WriteFile(outPath, msg.Data, 0644)
	default:
		fmt.Println("Unsupported action")
		os.Exit(1)
	}
}
