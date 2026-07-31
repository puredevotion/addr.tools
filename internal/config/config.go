package config

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/brianshea2/addr.tools/internal/dns2json"
	"github.com/brianshea2/addr.tools/internal/dnsutil"
	"github.com/brianshea2/addr.tools/internal/httputil"
	"github.com/brianshea2/addr.tools/internal/netutil"
	"github.com/brianshea2/addr.tools/internal/probereport"
	"github.com/brianshea2/addr.tools/internal/probewatch"
	"github.com/brianshea2/addr.tools/internal/status"
	"github.com/brianshea2/addr.tools/internal/ttlstore"
	"github.com/brianshea2/addr.tools/internal/zones/challenges"
	"github.com/brianshea2/addr.tools/internal/zones/dnscheck"
	"github.com/brianshea2/addr.tools/internal/zones/dyn"
	"github.com/brianshea2/addr.tools/internal/zones/myaddr"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/valkey-io/valkey-go"
	"golang.org/x/time/rate"
)

const (
	MaxDnscheckWatchers          = 100
	MaxDnscheckLargeResponseRate = 10 // per second
)

type Config struct {
	HTTPSocketPath string
	// HTTPListenAddr is a host:port for the HTTP API, as an alternative (or
	// addition) to HTTPSocketPath. See the listener below for why this exists.
	HTTPListenAddr string
	RequestLogPath string
	DatabasePath   string
	ValkeyURL      string
	TLSCertPath    string
	TLSKeyPath     string
	LookupUpstream string
	// LookupAllowedZones restricts the /dns/{name}/{type} endpoint to these
	// zones. Required whenever LookupUpstream is set — see the fatal at the
	// handler's registration for why there is no permissive default.
	LookupAllowedZones []string
	IPInfoBaseURL      string
	// ProbeReportEnabled exposes GET /api/report?token=, which reports what a
	// visitor's resolver did using observations the CoreDNS probe plugin wrote
	// to Valkey. Requires ValkeyURL — that key space is the only thing the two
	// programs share.
	// It also registers the websocket at /watch/{watcher}, fed from the same
	// Valkey key space (internal/probewatch). Both are views of one store, so one
	// flag governs both: enabling the polling read while leaving the live feed off
	// would only ever be a way to half-configure the same feature.
	ProbeReportEnabled bool
	// ProbeZone is the probe plugin's zone, e.g. "check.hivre.com". Used only to
	// reconstruct a display query name for the /watch feed, since the plugin
	// records the properties of a query rather than its name. Optional.
	ProbeZone             string
	MyaddrTurnstileSecret string
	DnscheckZones         []struct {
		*dnscheck.DnscheckHandler
		PrivateKey string
	}
	ChallengesZone struct {
		*dnsutil.SimpleHandler
		PrivateKey string
	}
	DynZone struct {
		*dnsutil.SimpleHandler
		PrivateKey string
	}
	MyaddrZones []struct {
		*dnsutil.SimpleHandler
		PrivateKey string
	}
}

func ParseConfig(path string) *Config {
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	var config Config
	err = json.NewDecoder(f).Decode(&config)
	if err != nil {
		log.Fatal(err)
	}
	return &config
}

func ParsePrivateKey(s string) []byte {
	if len(s) == 0 {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		log.Fatal(err)
	}
	return b
}

func (config *Config) Run() {
	// init status handler, uptime
	statusHandler := new(status.StatusHandler)
	statusHandler.Add(status.NewUptimeProvider())
	dns.Handle("status.", (&dnsutil.SimpleHandler{
		Zone:            "status.",
		Ns:              []string{"invalid."}, // not delegated
		RecordGenerator: statusHandler,
	}).Init(nil))

	// init dns request logger
	var requestLogger *log.Logger
	if len(config.RequestLogPath) > 0 {
		requestLogFile, err := os.OpenFile(config.RequestLogPath, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0666)
		if err != nil {
			log.Fatal(err)
		}
		buffer := bufio.NewWriter(requestLogFile)
		defer buffer.Flush()
		requestLogger = log.New(buffer, "", log.LstdFlags)
	}
	dnsHandler := &dnsutil.LoggingHandler{
		Logger: requestLogger,
		Next:   dns.DefaultServeMux,
	}
	statusHandler.Add(status.StatusProviderFunc(func() []status.Status {
		return []status.Status{{Title: "dns requests", Value: strconv.FormatUint(dnsHandler.RequestCount(), 10)}}
	}))

	// init valkey client
	var valkeyClient valkey.Client
	if len(config.ValkeyURL) > 0 {
		opt, err := valkey.ParseURL(config.ValkeyURL)
		if err == nil {
			valkeyClient, err = valkey.NewClient(opt)
		}
		if err != nil {
			log.Fatal(err)
		}
		defer valkeyClient.Close()
		log.Printf("[info] connected to %v", config.ValkeyURL)
	}

	// init the probe report endpoint (read side of the CoreDNS probe plugin)
	if config.ProbeReportEnabled {
		if valkeyClient == nil {
			log.Fatal("ProbeReportEnabled requires ValkeyURL: the probe plugin's observations live in Valkey and there is nowhere else to read them from")
		}
		http.Handle("/api/report", &probereport.HTTPHandler{
			Store: &probereport.Store{Client: valkeyClient},
		})
		log.Print("[info] serving /api/report from valkey")

		// The live feed the SPA actually consumes. Upstream registers
		// /watch/{watcher} only inside the `len(config.DnscheckZones) > 0` block
		// below, because there it is fed by this process's own DNS handler. This
		// fork serves no DNS, so that block never runs and the endpoint the SPA
		// opens on page load did not exist. probewatch.Hub supplies the missing
		// publisher by tailing Valkey, and wraps SimpleWatcherHub rather than
		// replacing it so the websocket handler and its JSON encoding stay
		// upstream's — the SPA needs no change at all.
		probeHub := &probewatch.Hub{
			Inner:  &dnscheck.SimpleWatcherHub{MaxSize: MaxDnscheckWatchers},
			Client: valkeyClient,
			Zone:   config.ProbeZone,
		}
		http.Handle("/watch/{watcher}", dnscheck.NewWebsocketHandler(probeHub))
		statusHandler.Add(status.StatusProviderFunc(func() []status.Status {
			return []status.Status{{Title: "probe watchers", Value: strconv.Itoa(probeHub.Tails())}}
		}))
		log.Print("[info] serving /watch/{watcher} from valkey")
	}

	// init persistent data store
	var persistentStore ttlstore.TtlStore
	if valkeyClient == nil {
		simpleStore := &ttlstore.SimpleTtlStore{}
		go simpleStore.PrunePeriodically(time.Hour)
		if len(config.DatabasePath) > 0 {
			if err := simpleStore.LoadFile(config.DatabasePath); err != nil && !errors.Is(err, fs.ErrNotExist) {
				log.Fatal(err)
			}
			defer func() {
				if err := simpleStore.WriteFile(config.DatabasePath); err != nil {
					log.Printf("[error] %v", err)
				}
			}()
			go func() {
				log.Fatal(simpleStore.WriteFilePeriodically(config.DatabasePath, time.Minute))
			}()
			log.Printf("[info] loaded database, size %v", simpleStore.Size())
		}
		persistentStore = simpleStore
	} else {
		persistentStore = &ttlstore.ValkeyClient{Client: valkeyClient}
	}

	// init temporary challenge record store
	var challengeStore ttlstore.TtlStore
	if valkeyClient == nil {
		simpleStore := &ttlstore.SimpleTtlStore{}
		go simpleStore.PrunePeriodically(time.Minute)
		challengeStore = simpleStore
	} else {
		challengeStore = &ttlstore.Prefixed{
			Store:  &ttlstore.ValkeyClient{Client: valkeyClient},
			Prefix: "challenge:",
		}
	}

	// init and set dnscheck handlers
	if len(config.DnscheckZones) > 0 {
		var ipinfoClient *httputil.IPInfoClient
		if len(config.IPInfoBaseURL) > 0 {
			ipinfoClient = &httputil.IPInfoClient{
				BaseURL:    config.IPInfoBaseURL,
				HttpClient: http.Client{Timeout: time.Second},
			}
		}
		largeResponseLimiter := rate.NewLimiter(rate.Limit(MaxDnscheckLargeResponseRate), MaxDnscheckLargeResponseRate)
		watcherHub := &dnscheck.SimpleWatcherHub{MaxSize: MaxDnscheckWatchers}
		for _, h := range config.DnscheckZones {
			h.DnscheckHandler.IPInfoClient = ipinfoClient
			h.DnscheckHandler.LargeResponseLimiter = largeResponseLimiter
			h.DnscheckHandler.Watchers = watcherHub
			h.DnscheckHandler.Init(ParsePrivateKey(h.PrivateKey))
			dns.Handle(h.DnscheckHandler.Zone, h.DnscheckHandler)
		}
		http.Handle("/watch/{watcher}", dnscheck.NewWebsocketHandler(watcherHub))
		statusHandler.Add(status.StatusProviderFunc(func() []status.Status {
			return []status.Status{{Title: "watchers", Value: strconv.Itoa(watcherHub.Size())}}
		}))
	}

	// init and set challenges handler
	if config.ChallengesZone.SimpleHandler != nil {
		config.ChallengesZone.SimpleHandler.RecordGenerator = &challenges.RecordGenerator{
			ChallengeStore: challengeStore,
		}
		config.ChallengesZone.SimpleHandler.Init(ParsePrivateKey(config.ChallengesZone.PrivateKey))
		dns.Handle(config.ChallengesZone.SimpleHandler.Zone, config.ChallengesZone.SimpleHandler)
		http.Handle("/challenges", &challenges.HTTPHandler{
			ChallengeStore: challengeStore,
			Zone:           config.ChallengesZone.SimpleHandler.Zone,
		})
	}

	// init and set dyn handler
	if config.DynZone.SimpleHandler != nil {
		config.DynZone.SimpleHandler.RecordGenerator = &dyn.RecordGenerator{
			DataStore: persistentStore,
		}
		config.DynZone.SimpleHandler.Init(ParsePrivateKey(config.DynZone.PrivateKey))
		dns.Handle(config.DynZone.SimpleHandler.Zone, config.DynZone.SimpleHandler)
		http.Handle("/dyn", &dyn.HTTPHandler{
			DataStore: persistentStore,
			Zone:      config.DynZone.SimpleHandler.Zone,
		})
	}

	// init and set myaddr handlers
	if len(config.MyaddrZones) > 0 {
		myaddrDataStore := &ttlstore.Prefixed{Store: persistentStore, Prefix: "myaddr:"}
		myaddrChallengeStore := &ttlstore.Prefixed{Store: challengeStore, Prefix: "myaddr:"}
		for _, h := range config.MyaddrZones {
			h.SimpleHandler.RecordGenerator = &myaddr.RecordGenerator{
				DataStore:      myaddrDataStore,
				ChallengeStore: myaddrChallengeStore,
			}
			h.SimpleHandler.Init(ParsePrivateKey(h.PrivateKey))
			dns.Handle(h.SimpleHandler.Zone, h.SimpleHandler)
		}
		http.Handle("/admin/myaddr", &myaddr.AdminHandler{
			DataStore:      myaddrDataStore,
			ChallengeStore: myaddrChallengeStore,
		})
		http.Handle("/myaddr-reg", &myaddr.RegistrationHandler{
			DataStore:      myaddrDataStore,
			ChallengeStore: myaddrChallengeStore,
			TurnstileClient: &httputil.TurnstileClient{
				Secret:     config.MyaddrTurnstileSecret,
				HttpClient: http.Client{Timeout: 5 * time.Second},
			},
		})
		http.Handle("/myaddr-update", &myaddr.UpdateHandler{
			DataStore:      myaddrDataStore,
			ChallengeStore: myaddrChallengeStore,
		})
	}

	// set dns lookup handler
	if len(config.LookupUpstream) > 0 {
		// Refused rather than defaulted: an unrestricted lookup endpoint is an
		// open resolver reachable over HTTP, usable as a reconnaissance proxy
		// and an amplification reflector against our own address. There is no
		// safe implicit value for this.
		if len(config.LookupAllowedZones) == 0 {
			log.Fatal("LookupUpstream is set but LookupAllowedZones is empty: refusing to serve an unrestricted lookup endpoint")
		}
		http.Handle("/dns/{name}/{type}", &dns2json.LookupHandler{
			Upstream:     config.LookupUpstream,
			AllowedZones: config.LookupAllowedZones,
		})
	}

	// start dns listeners
	go func() {
		log.Print("[info] starting dns udp listener")
		log.Fatal((&dns.Server{
			Addr:          ":53",
			Net:           "udp",
			MsgAcceptFunc: dnsutil.MsgAcceptFunc,
			Handler:       dnsHandler,
		}).ListenAndServe())
	}()
	go func() {
		log.Print("[info] starting dns tcp listener")
		log.Fatal((&dns.Server{
			Addr:          ":53",
			Net:           "tcp",
			MsgAcceptFunc: dnsutil.MsgAcceptFunc,
			Handler:       dnsHandler,
		}).ListenAndServe())
	}()
	if len(config.TLSCertPath) > 0 && len(config.TLSKeyPath) > 0 {
		cert, err := tls.LoadX509KeyPair(config.TLSCertPath, config.TLSKeyPath)
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			log.Print("[info] starting dns over tls listener")
			log.Fatal((&dns.Server{
				Addr:          ":853",
				Net:           "tcp-tls",
				MsgAcceptFunc: dnsutil.MsgAcceptFunc,
				Handler:       dnsHandler,
				TLSConfig: &tls.Config{
					NextProtos:   []string{"dot"},
					Certificates: []tls.Certificate{cert},
					MinVersion:   tls.VersionTLS12,
					CurvePreferences: []tls.CurveID{
						tls.X25519MLKEM768,
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					},
					CipherSuites: []uint16{
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
						tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					},
				},
			}).ListenAndServe())
		}()
		go func() {
			log.Print("[info] starting dns over quic listener")
			udpConn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 853})
			if err != nil {
				log.Fatal(err)
			}
			quicListener, err := (&quic.Transport{
				Conn: udpConn,
			}).Listen(
				&tls.Config{
					NextProtos:   []string{"doq"},
					Certificates: []tls.Certificate{cert},
					MinVersion:   tls.VersionTLS13,
					CurvePreferences: []tls.CurveID{
						tls.X25519MLKEM768,
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					},
				},
				&quic.Config{},
			)
			if err != nil {
				log.Fatal(err)
			}
			log.Fatal((&dns.Server{
				Listener:      netutil.NewQUICStreamListener(quicListener),
				MaxTCPQueries: 1, // max requests per quic stream
				MsgAcceptFunc: dnsutil.MsgAcceptFunc,
				Handler:       dnsHandler,
			}).ActivateAndServe())
		}()
	}

	// start http tcp listener
	//
	// Added for the hivre.com lab fork. Upstream serves HTTP over a unix socket
	// only, which works when nginx runs on the same host but not in Kubernetes:
	// an ingress controller in another pod cannot reach a socket inside this
	// one. The alternative was a socat/nginx sidecar in every pod purely to
	// translate TCP to a unix socket, which is a moving part with no other
	// purpose. Both listeners can run at once; set whichever the deployment
	// needs.
	if len(config.HTTPListenAddr) > 0 {
		go func() {
			log.Printf("[info] starting http tcp listener on %s", config.HTTPListenAddr)
			ln, err := net.Listen("tcp", config.HTTPListenAddr)
			if err != nil {
				log.Fatal(err)
			}
			// ReadHeaderTimeout, unlike upstream's bare &http.Server{}: this
			// listener is reachable from the network rather than from a
			// same-host nginx, so a client that opens a connection and never
			// finishes its headers would otherwise hold a goroutine forever.
			log.Fatal((&http.Server{
				ReadHeaderTimeout: 10 * time.Second,
			}).Serve(ln))
		}()
	}

	// start http socket listener
	if len(config.HTTPSocketPath) > 0 {
		go func() {
			log.Print("[info] starting http socket listener")
			os.Remove(config.HTTPSocketPath)
			ln, err := net.Listen("unix", config.HTTPSocketPath)
			if err != nil {
				log.Fatal(err)
			}
			err = os.Chmod(config.HTTPSocketPath, 0666)
			if err != nil {
				log.Fatal(err)
			}
			log.Fatal(new(http.Server).Serve(ln))
		}()
	}

	// goroutines are go-ing, wait
	terminate := make(chan os.Signal, 1)
	signal.Notify(terminate, syscall.SIGINT, syscall.SIGTERM)
	<-terminate
	log.Print("[info] exiting")
}
