package main

import (
	"encoding/json"
	"fmt"
        "os"
	"strconv"
	"time"
        "bytes"
        "net/http"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type DecisionKey struct {
	Value string
	Type  string
}

type cloudBouncer struct {
	newDecisionValueSet     map[DecisionKey]struct{}
	expiredDecisionValueSet map[DecisionKey]struct{}
}

func newCloudBouncer() (*cloudBouncer, error) {
	return &cloudBouncer{
	}, nil
}

func (c *cloudBouncer) AddCloud(IP string, config bouncerConfig) {
        hostname, _ := os.Hostname()
        params := map[string]string{"ip": IP, "type": "ban", "hostname": hostname}
        jsonValue, _ := json.Marshal(params)
        url := fmt.Sprint(config.GAIUSUrl, "/cloud-firewall/")
        req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
        req.Header.Set("Authorization", fmt.Sprint("Token ", config.GAIUSToken))
        req.Header.Set("Content-Type", "application/json")

        client := &http.Client{}
        resp, err := client.Do(req)
        if err != nil {
            panic(err)
        }
        defer resp.Body.Close()
        
        log.Infof("Status: %s", resp.Status)
        if resp.Status == "200" {
            log.Info(fmt.Sprint("Success to ban IP : ", IP))
        } else {
            log.Error(fmt.Sprint("Fail to ban IP : ", IP))
        }
}

func (c *cloudBouncer) DeleteCloud(IP string, config bouncerConfig) {
        hostname, _ := os.Hostname()
        params := map[string]string{"ip": IP, "type": "unban", "hostname": hostname}
        jsonValue, _ := json.Marshal(params)
        url := fmt.Sprint(config.GAIUSUrl, "/cloud-firewall/")
        req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
        req.Header.Set("Authorization", fmt.Sprint("Token ", config.GAIUSToken))
        req.Header.Set("Content-Type", "application/json")

        client := &http.Client{}
        resp, err := client.Do(req)
        if err != nil {
            panic(err)
        }
        defer resp.Body.Close()
        
        if resp.Status == "200" {
            log.Info(fmt.Sprint("Success to ban IP : ", IP))
        } else {
            log.Error(fmt.Sprint("Fail to unban IP : ", IP))
        }
}

func (c *cloudBouncer) ResetCache() {
	cachedDecisionCount := len(c.newDecisionValueSet) + len(c.expiredDecisionValueSet)
	if cachedDecisionCount != 0 {
		log.Debugf("resetting cache, clearing %d decisions", cachedDecisionCount)
		// dont return here, because this could be used to intiate the sets
	}
	c.newDecisionValueSet = make(map[DecisionKey]struct{})
	c.expiredDecisionValueSet = make(map[DecisionKey]struct{})
}

func (c *cloudBouncer) Init() error {
	c.ResetCache()
	return nil
}

func (c *cloudBouncer) Add(decision *models.Decision, config bouncerConfig) error {
	if _, exists := c.newDecisionValueSet[decisionToDecisionKey(decision)]; exists {
		return nil
	}
	banDuration, err := time.ParseDuration(*decision.Duration)
	if err != nil {
		return err
	}
	log.Debugf("cloud : add ban on %s for %s sec (%s)", *decision.Value, strconv.Itoa(int(banDuration.Seconds())), *decision.Scenario)
        c.AddCloud(*decision.Value, config)
	c.newDecisionValueSet[decisionToDecisionKey(decision)] = struct{}{}
	return nil
}

func (c *cloudBouncer) Delete(decision *models.Decision, config bouncerConfig) error {
	if _, exists := c.expiredDecisionValueSet[decisionToDecisionKey(decision)]; exists {
		return nil
	}
	banDuration, err := time.ParseDuration(*decision.Duration)
	if err != nil {
		return err
	}
	log.Debugf("cloud : del ban on %s for %s sec (%s)", *decision.Value, strconv.Itoa(int(banDuration.Seconds())), *decision.Scenario)
        c.DeleteCloud(*decision.Value, config)
	c.expiredDecisionValueSet[decisionToDecisionKey(decision)] = struct{}{}
	return nil
}

func (c *cloudBouncer) ShutDown() error {
	return nil
}

func decisionToDecisionKey(decision *models.Decision) DecisionKey {
	return DecisionKey{
		Value: *decision.Value,
		Type:  *decision.Type,
	}
}
