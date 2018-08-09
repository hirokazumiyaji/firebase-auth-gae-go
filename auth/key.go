package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const publicKeyUrl = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"

type publicKey struct {
	Kid string
	Key *rsa.PublicKey
}

var (
	cachedKeys []*publicKey
	expiryTime time.Time
	mutex      *sync.Mutex
)

func init() {
	mutex = &sync.Mutex{}
}

func publicKeys(client *http.Client) ([]*publicKey, error) {
	mutex.Lock()
	defer mutex.Unlock()
	if len(cachedKeys) == 0 || time.Now().After(expiryTime) {
		err := refreshKeys(client)
		if err != nil && len(cachedKeys) == 0 {
			return nil, err
		}
	}
	return cachedKeys, nil
}

func refreshKeys(client *http.Client) error {
	res, err := client.Get(publicKeyUrl)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	contents, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf(
			"invalid response (%d) while retrieving public keys: %s",
			res.StatusCode,
			string(contents),
		)
	}
	newKeys, err := parsePublicKeys(contents)
	if err != nil {
		return err
	}
	maxAge, err := findMaxAge(res)
	if err != nil {
		return err
	}
	cachedKeys = append([]*publicKey(nil), newKeys...)
	expiryTime = time.Now().Add(*maxAge)
	return nil
}

func findMaxAge(resp *http.Response) (*time.Duration, error) {
	cc := resp.Header.Get("cache-control")
	for _, value := range strings.Split(cc, ",") {
		value = strings.TrimSpace(value)
		if strings.HasPrefix(value, "max-age=") {
			sep := strings.Index(value, "=")
			seconds, err := strconv.ParseInt(value[sep+1:], 10, 64)
			if err != nil {
				return nil, err
			}
			duration := time.Duration(seconds) * time.Second
			return &duration, nil
		}
	}
	return nil, errors.New("Could not find expiry time from HTTP headers")
}

func parsePublicKeys(keys []byte) ([]*publicKey, error) {
	m := make(map[string]string)
	err := json.Unmarshal(keys, &m)
	if err != nil {
		return nil, err
	}

	var result []*publicKey
	for kid, key := range m {
		pubKey, err := parsePublicKey(kid, []byte(key))
		if err != nil {
			return nil, err
		}
		result = append(result, pubKey)
	}
	return result, nil
}

func parsePublicKey(kid string, key []byte) (*publicKey, error) {
	block, _ := pem.Decode(key)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	pk, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("Certificate is not a RSA key")
	}
	return &publicKey{kid, pk}, nil
}
