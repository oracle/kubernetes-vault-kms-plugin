/*
Copyright © 2018, Oracle and/or its affiliates. All rights reserved.

The Universal Permissive License (UPL), Version 1.0
*/

// Package vault implements envelop encryption provider based on Vault KMS
package vault

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
	"sync"

	"github.com/ghodss/yaml"
	log "github.com/sirupsen/logrus"

)

var once sync.Once

const vaultPrefix = "vault"

//EnvelopeConfig contains connection information for Vault transformer
type EnvelopeConfig struct {
	// The names of encryption key for Vault transit communication
	KeyNames []string `json:"keyNames"`

	// Vault listen address, for example https://localhost:8200
	Address string `json:"addr"`

	// Token authentication information
	Token string `json:"token"`

	// TLS certificate authentication information
	ClientCert string `json:"clientCert"`
	ClientKey  string `json:"clientKey"`

	// AppRole authentication information
	RoleID   string `json:"roleID"`
	SecretID string `json:"secretID"`

	// CACert is the path to a PEM-encoded CA cert file to use to verify the
	// Vault server SSL certificate.
	VaultCACert string `json:"vaultCACert"`

	// TLSServerName, if set, is used to set the SNI host when connecting via TLS.
	TLSServerName string `json:"tlsServerName"`

	// The path for transit API, default is "transit"
	TransitPath string `json:"transitPath"`

	// The path for auth backend, default is "auth"
	AuthPath string `json:"authPath"`
}

// KMSFactory function creates Vault KMS service
func KMSFactory(configFile io.Reader) (*VaultEnvelopeService, error) {
	configFileContents, err := ioutil.ReadAll(configFile)
	if err != nil {
		return nil, fmt.Errorf("could not read contents: %v", err)
	}

	var config EnvelopeConfig
	err = yaml.Unmarshal(configFileContents, &config)
	if err != nil {
		return nil, fmt.Errorf("error while parsing file: %v", err)
	}

	err = validateConfig(&config)
	if err != nil {
		return nil, err
	}

	client, err := newClientWrapper(&config)
	if err != nil {
		return nil, err
	}

	return &VaultEnvelopeService{config: &config, client: client}, nil
}

func validateConfig(config *EnvelopeConfig) error {
	if len(config.KeyNames) == 0 {
		return errors.New("vault provider has no valid key names")
	}

	if config.Address == "" {
		return errors.New("vault provider has no valid address")
	}

	return validateAuthConfig(config)
}

func validateAuthConfig(config *EnvelopeConfig) error {
	count := 0

	if config.Token != "" {
		count++
	}

	if config.ClientCert != "" || config.ClientKey != "" {
		if config.ClientCert == "" || config.ClientKey == "" {
			return errors.New("vault provider has invalid TLS authentication information")
		}
		count++
	}

	if config.RoleID != "" || config.SecretID != "" {
		if config.RoleID == "" {
			return errors.New("vault provider has invalid approle authentication information")
		}
		count++
	}

	if count == 0 {
		return errors.New("vault provider has no authentication information")
	}
	if count > 1 {
		return errors.New("vault provider has more than one authentication information")
	}

	return nil
}

type VaultEnvelopeService struct {
	config *EnvelopeConfig
	client *clientWrapper
	// We may update token for api.Client, but there is no sync for api.Client.
	// Read lock for encrypt/decrypt requests, write lock for login requests which
	// will update token for api.Client.
	rwmutex sync.RWMutex
}

func (s *VaultEnvelopeService) Decrypt(data []byte) ([]byte, error) {
	cipher := string(data)
	//cipher := base64.StdEncoding.EncodeToString(data)
	// Find the mached key
	var key string
	for _, name := range s.config.KeyNames {
		if strings.HasPrefix(cipher, name+":") {
			key = name
			break
		}
	}
	if key == "" {
		return nil, errors.New("no matching vault key found")
	}

	// Replace the key name with "vault:" for Vault transit API
	if !strings.HasPrefix(cipher, key) {
		return nil, errors.New("encrypted data from storage does not have key prefix")
	}
	cipher = vaultPrefix + cipher[len(key):]

	plain, err := s.withRefreshToken(false, key, cipher)
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(plain)
}

func (s *VaultEnvelopeService) Encrypt(data []byte) ([]byte, error) {
	// Use the frist key to encrypt
	key := s.config.KeyNames[0]
	plain := base64.StdEncoding.EncodeToString(data)
	cipher, err := s.withRefreshToken(true, key, plain)
	if err != nil {
		return nil, err
	}

	// The format of cipher from Vault is "vault:v1:....".
	// "vault:" is unnecessary, replace it with key name.
	if !strings.HasPrefix(cipher, vaultPrefix) {
		return nil, fmt.Errorf("encrypted data from vault does not have prefix %v", vaultPrefix)
	}
	cipher = key + cipher[len(vaultPrefix):]
	return []byte(cipher), nil
}

func (s *VaultEnvelopeService) withRefreshToken(isEncrypt bool, key, data string) (string, error) {
	// Execute operation first time.
	var result string
	var err error
	func() {
		s.rwmutex.RLock()
		defer s.rwmutex.RUnlock()
		if isEncrypt {
			result, err = s.client.encryptLocked(key, data)
		} else {
			result, err = s.client.decryptLocked(key, data)
		}
	}()
	if err == nil || s.config.Token != "" {
		return result, err
	}
	_, ok := err.(*forbiddenError)
	if !ok {
		return result, err
	}

	// The request is forbidden, refresh token and execute operation again.
	// With the expected usage:
	//a. rare calls to KMS provider for decrypt during secret read: due to DEK caching,
	//b. rare concurrent secret creation,
	//c. Token policy having reasonable expiry and num. of use;
	// the locking is not expected to degrade performance for normal usage scenarios.
	// The race condition is still eliminated for worst case scenarios.
	s.rwmutex.Lock()
	defer s.rwmutex.Unlock()
	err = s.client.refreshTokenLocked(s.config)
	if err != nil {
		return result, err
	}
	log.Info("vault token refreshed")
	if isEncrypt {
		result, err = s.client.encryptLocked(key, data)
	} else {
		result, err = s.client.decryptLocked(key, data)
	}
	return result, err
}
