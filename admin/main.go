package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

//go:embed web
var webFiles embed.FS

func main() {
	listenAddress := flag.String("listen", "127.0.0.1:8740", "address to listen on")
	dataDirectory := flag.String("data", "/var/lib/hause-admin", "directory holding registered devices")
	publicOrigin := flag.String("origin", "https://su.hause.dev", "public origin the panel is served from")
	flag.Parse()

	origin := strings.TrimRight(*publicOrigin, "/")
	parsedOrigin, err := url.Parse(origin)
	if err != nil || parsedOrigin.Hostname() == "" {
		log.Fatalf("invalid -origin %q", *publicOrigin)
	}

	if flag.Arg(0) == "setup-link" {
		link, err := issueSetupLink(*dataDirectory, origin)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(link)
		fmt.Println("The link registers one device and expires in 30 minutes.")
		return
	}

	store, err := openStore(*dataDirectory)
	if err != nil {
		log.Fatal(err)
	}
	if store.deviceCount() == 0 {
		link, err := issueSetupLink(*dataDirectory, origin)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("no passkeys registered yet; open this link on your first device within 30 minutes: %s", link)
	}

	relyingParty, err := webauthn.New(&webauthn.Config{
		RPID:          parsedOrigin.Hostname(),
		RPDisplayName: "hause admin",
		RPOrigins:     []string{origin},
	})
	if err != nil {
		log.Fatal(err)
	}

	monitor, err := newProcessMonitor()
	if err != nil {
		log.Fatal(err)
	}
	go monitor.run(2 * time.Second)

	app := newApp(store, relyingParty, monitor, *dataDirectory, origin)
	go app.purgeExpiredLoop()

	staticFiles, err := fs.Sub(webFiles, "web")
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{
		Addr:              *listenAddress,
		Handler:           app.routes(staticFiles),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	log.Printf("listening on %s for %s", *listenAddress, origin)
	log.Fatal(server.ListenAndServe())
}
