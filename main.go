package main

import (
	"log"

	"github.com/siddharth-sable/go-csrf/db"
	"github.com/siddharth-sable/go-csrf/server"
	"github.com/siddharth-sable/go-csrf/server/middleware/myJwt"
)

var host = "localhost"
var port = "9000"

func main() {
	db.InitDB()

	jwtErr := myJwt.InitJWT()
	if jwtErr != nil {
		log.Println("Error initializing the JWT!")
		log.Fatal(jwtErr)
	}

	serverErr := server.StartServer(host, port)
	if serverErr != nil {
		log.Println("error starting server!")
		log.Fatal(serverErr)
	}

}
