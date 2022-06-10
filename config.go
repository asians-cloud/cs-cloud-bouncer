package main

import (
	"fmt"
	"io/ioutil"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"

	"gopkg.in/natefinch/lumberjack.v2"
	"gopkg.in/yaml.v2"
)

type bouncerConfig struct {
	PidDir                 string        `yaml:"piddir"`
	UpdateFrequency        string        `yaml:"update_frequency"`
	Daemon                 bool          `yaml:"daemonize"`
	LogMode                string        `yaml:"log_mode"`
	LogDir                 string        `yaml:"log_dir"`
	LogLevel               log.Level     `yaml:"log_level"`
	APIUrl                 string        `yaml:"api_url"`
	APIKey                 string        `yaml:"api_key"`
	CacheRetentionDuration time.Duration `yaml:"cache_retention_duration"`
        GAIUSUrl               string        `yaml:"gaius_url"`
        GAIUSToken             string        `yaml:"gaius_token"`
}

func NewConfig(configPath string) (*bouncerConfig, error) {
	var LogOutput *lumberjack.Logger //io.Writer

	config := &bouncerConfig{}

	configBuff, err := ioutil.ReadFile(configPath)
	if err != nil {
		return &bouncerConfig{}, fmt.Errorf("failed to read %s : %v", configPath, err)
	}

	err = yaml.UnmarshalStrict(configBuff, &config)
	if err != nil {
		return &bouncerConfig{}, fmt.Errorf("failed to unmarshal %s : %v", configPath, err)
	}

        if config.GAIUSToken == "" {
                return &bouncerConfig{}, fmt.Errorf("gaius_token is required")
        }
        

	/*Configure logging*/
        compress := true
	if err = types.SetDefaultLoggerConfig(config.LogMode, config.LogDir, config.LogLevel, 500, 3, 28, &compress); err != nil {
		log.Fatal(err.Error())
	}
	if config.LogMode == "file" {
		if config.LogDir == "" {
			config.LogDir = "/var/log/"
		}
		LogOutput = &lumberjack.Logger{
			Filename:   config.LogDir + "/crowdsec-cloud-bouncer.log",
			MaxSize:    500, //megabytes
			MaxBackups: 3,
			MaxAge:     28,   //days
			Compress:   true, //disabled by default
		}
		log.SetOutput(LogOutput)
		log.SetFormatter(&log.TextFormatter{TimestampFormat: "02-01-2006 15:04:05", FullTimestamp: true})
	} else if config.LogMode != "stdout" {
		return &bouncerConfig{}, fmt.Errorf("log mode '%s' unknown, expecting 'file' or 'stdout'", config.LogMode)
	}

	if config.CacheRetentionDuration == 0 {
		log.Infof("cache_retention_duration defaults to 10 seconds")
		config.CacheRetentionDuration = time.Duration(10 * time.Second)
	}

	return config, nil
}
