package config

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"net/url"
	"os"
)

// Config struct holds configuration of Device Manager
type Config struct {
	Host               string   `yaml:"Host"`
	Port               string   `yaml:"Port"`
	UserName           string   `yaml:"UserName"`
	Password           string   `yaml:"Password"`
	RootServiceUUID    string   `yaml:"RootServiceUUID"`
	OdimURL            string   `yaml:"OdimURL"`
	OdimUserName       string   `yaml:"OdimUserName"`
	OdimPassword       string   `yaml:"OdimPassword"`
	TLSConf            *TLSConf `yaml:"TLSConf"`
	RSAPrivateKeyPath  string   `yaml:"RSAPrivateKeyPath"`
	RSAPublicKeyPath   string   `yaml:"RSAPublicKeyPath"`
	PKIRootCAPath      string   `yaml:"PKIRootCACertificatePath"`
	PKIPrivateKeyPath  string   `yaml:"PKIPrivateKeyPath"`
	PKICertificatePath string   `yaml:"PKICertificatePath"`
	PKIRootCA          []byte
	PKIPrivateKey      []byte
	PKICertificate     []byte
}

// TLSConf holds TLS configuration
type TLSConf struct {
	MinVersion uint16 `yaml:"MinVersion"`
	MaxVersion uint16 `yaml:"MaxVersion"`
}

// LoadConfiguration loads Device Manager configuration from env path variable DM_CONFIG_FILE_PATH
func LoadConfiguration() (*Config, error) {
	config := new(Config)

	if configPath := os.Getenv("DM_CONFIG_FILE_PATH"); configPath != "" {
		if configData, err := ioutil.ReadFile(configPath); err == nil {
			_ = yaml.Unmarshal(configData, config)
		} else {
			logrus.Fatalf("cannot load configuration file: %s", err)
		}
	} else {
		logrus.Fatal("missing DM_CONFIG_FILE_PATH env")
	}

	if err := loadCerts(config); err != nil {
		return config, err
	}

	return config, validateConfig(config)
}

func loadCerts(config *Config) error {
	var err error
	if config.PKICertificate, err = ioutil.ReadFile(config.PKICertificatePath); err != nil {
		return fmt.Errorf("value check failed for CertificatePath:%s with %v", config.PKICertificatePath, err)
	}
	if config.PKIPrivateKey, err = ioutil.ReadFile(config.PKIPrivateKeyPath); err != nil {
		return fmt.Errorf("value check failed for PrivateKeyPath:%s with %v", config.PKIPrivateKeyPath, err)
	}
	if config.PKIRootCA, err = ioutil.ReadFile(config.PKIRootCAPath); err != nil {
		return fmt.Errorf("value check failed for RootCACertificatePath:%s with %v", config.PKIRootCAPath, err)
	}

	return nil
}

func validateConfig(config *Config) error {
	if config.Host == "" {
		return fmt.Errorf("missing value for Host")
	}

	if config.Port == "" {
		return fmt.Errorf("missing value for Port")
	}

	if config.UserName == "" {
		return fmt.Errorf("missing value for Username")
	}

	if config.Password == "" {
		return fmt.Errorf("missing value for Password")
	}

	if config.RootServiceUUID == "" {
		return fmt.Errorf("missing value for RootServiceUUID")
	} else if _, err := uuid.Parse(config.RootServiceUUID); err != nil {
		return err
	}

	if config.OdimURL == "" {
		return fmt.Errorf("missing value for OdimURL")
	} else if _, e := url.Parse(config.OdimURL); e != nil {
		return e
	}

	if config.OdimUserName == "" {
		return fmt.Errorf("missing value for OdimUserName")
	}

	if config.OdimPassword == "" {
		return fmt.Errorf("missing value for OdimPassword")
	}

	if config.TLSConf == nil {
		return fmt.Errorf("missing TLSConf, setting default value")
	}
	if config.TLSConf.MinVersion == 0 || config.TLSConf.MinVersion == 0x0301 || config.TLSConf.MinVersion == 0x0302 {
		return fmt.Errorf("configured TLSConf.MinVersion is wrong")
	}
	if config.TLSConf.MaxVersion == 0 || config.TLSConf.MaxVersion == 0x0301 || config.TLSConf.MaxVersion == 0x0302 {
		return fmt.Errorf("configured TLSConf.MaxVersion is wrong")
	}

	return nil
}
