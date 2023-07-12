package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
        "context"

	"github.com/coreos/go-systemd/daemon"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
        "golang.org/x/sync/errgroup"

	"github.com/asians-cloud/cs-cloud-bouncer/pkg/version"
        "github.com/asians-cloud/crowdsec/pkg/apiclient"
	csbouncer "github.com/asians-cloud/go-cs-bouncer" 
	"gopkg.in/tomb.v2"
)

const (
	name = "crowdsec-cloud-bouncer"
        scope = "cloud"
)

var t tomb.Tomb

func termHandler(sig os.Signal, cloud *cloudBouncer) error {
	if err := cloud.ShutDown(); err != nil {
		return err
	}
	return nil
}

func HandleSignals(cloud *cloudBouncer) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan,
		syscall.SIGTERM)

	exitChan := make(chan int)
	go func() {
		for {
			s := <-signalChan
			switch s {
			// kill -SIGTERM XXXX
			case syscall.SIGTERM:
				if err := termHandler(s, cloud); err != nil {
					log.Fatalf("shutdown fail: %s", err)
				}
				exitChan <- 0
			}
		}
	}()

	code := <-exitChan
	log.Infof("Shutting down cloud-bouncer service")
	os.Exit(code)
}

func main() {
	var err error
	log.Infof("crowdsec-cloud-bouncer %s", version.VersionStr())
	configPath := flag.String("c", "", "path to crowdsec-cloud-bouncer.yaml")
	verbose := flag.Bool("v", false, "set verbose mode")

	flag.Parse()

	if configPath == nil || *configPath == "" {
		log.Fatalf("configuration file is required")
	}

	log.AddHook(&writer.Hook{ // Send logs with level fatal to stderr
		Writer: os.Stderr,
		LogLevels: []log.Level{
			log.PanicLevel,
			log.FatalLevel,
		},
	})

	config, err := NewConfig(*configPath)
	if err != nil {
		log.Fatalf("unable to load configuration: %s", err)
	}

	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	cloud, err := newCloudBouncer()
	if err != nil {
		log.Fatalf(err.Error())
	}

	if err := cloud.Init(); err != nil {
		log.Fatalf(err.Error())
	}
        
	bouncer := &csbouncer.StreamBouncer{
		APIKey:         config.APIKey,
		APIUrl:         config.APIUrl,
		TickerInterval: config.UpdateFrequency,
		UserAgent:      fmt.Sprintf("%s/%s", name, version.VersionStr()),
                Opts: apiclient.DecisionsStreamOpts{
			Scopes: scope,
		},
	}
	if err := bouncer.Init(); err != nil {
		log.Fatalf(err.Error())
	}
	cacheResetTicker := time.NewTicker(config.CacheRetentionDuration)

	g, ctx := errgroup.WithContext(context.Background())

	g.Go(func() error {
		bouncer.RunStream(ctx)
		return fmt.Errorf("stream api init failed")
	})

	t.Go(func() error {
		log.Printf("Processing new and deleted decisions . . .")
		for {
			select {
			case <-t.Dying():
				log.Infoln("terminating bouncer process")
				return nil
			case decisions := <-bouncer.Stream:
				log.Infof("deleting '%d' decisions", len(decisions.Deleted))
				for _, decision := range decisions.Deleted {
                                        if *decision.Scope == scope {
                                              if err := cloud.Delete(decision, *config); err != nil {
                                                      log.Errorf("unable to delete decision for '%s': %s", *decision.Value, err)
                                              } else {
                                                      log.Debugf("deleted '%s'", *decision.Value)
                                              }
                                        }

				}
				log.Infof("adding '%d' decisions", len(decisions.New))
				for _, decision := range decisions.New {
                                        if *decision.Scope == scope {
                                              if err := cloud.Add(decision, *config); err != nil {
                                                      log.Errorf("unable to insert decision for '%s': %s", *decision.Value, err)
                                              } else {
                                                      log.Debugf("Adding '%s' for '%s'", *decision.Value, *decision.Duration)
                                              }
                                        }
				}
			case <-cacheResetTicker.C:
				cloud.ResetCache()
			}
		}
	})

	if config.Daemon == true {
		sent, err := daemon.SdNotify(false, "READY=1")
		if !sent && err != nil {
			log.Errorf("Failed to notify: %v", err)
		}
		HandleSignals(cloud)
	}

	err = t.Wait()
	if err != nil {
		log.Fatalf("process return with error: %s", err)
	}
}
