package main

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const setupTokenLifetime = 30 * time.Minute

var (
	errLastDevice     = errors.New("You can't remove the only registered device.")
	errDeviceNotFound = errors.New("That device isn't registered.")
)

type Device struct {
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	CreatedAt  time.Time           `json:"createdAt"`
	LastUsedAt time.Time           `json:"lastUsedAt"`
	Credential webauthn.Credential `json:"credential"`
}

type storedState struct {
	OwnerID []byte   `json:"ownerId"`
	Devices []Device `json:"devices"`
}

type Store struct {
	mutex     sync.Mutex
	statePath string
	state     storedState
}

type owner struct {
	id          []byte
	credentials []webauthn.Credential
}

func (account owner) WebAuthnID() []byte                         { return account.id }
func (account owner) WebAuthnName() string                       { return "dilutedev" }
func (account owner) WebAuthnDisplayName() string                { return "dilutedev" }
func (account owner) WebAuthnCredentials() []webauthn.Credential { return account.credentials }

func openStore(dataDirectory string) (*Store, error) {
	if err := os.MkdirAll(dataDirectory, 0o700); err != nil {
		return nil, err
	}
	store := &Store{statePath: filepath.Join(dataDirectory, "state.json")}
	contents, err := os.ReadFile(store.statePath)
	switch {
	case err == nil:
		if err := json.Unmarshal(contents, &store.state); err != nil {
			return nil, fmt.Errorf("reading %s: %w", store.statePath, err)
		}
	case errors.Is(err, os.ErrNotExist):
		store.state.OwnerID = randomBytes(32)
		if err := store.saveLocked(); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	return store, nil
}

func (store *Store) saveLocked() error {
	contents, err := json.MarshalIndent(store.state, "", "  ")
	if err != nil {
		return err
	}
	temporaryPath := store.statePath + ".tmp"
	if err := os.WriteFile(temporaryPath, contents, 0o600); err != nil {
		return err
	}
	return os.Rename(temporaryPath, store.statePath)
}

func (store *Store) owner() owner {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	credentials := make([]webauthn.Credential, len(store.state.Devices))
	for index, device := range store.state.Devices {
		credentials[index] = device.Credential
	}
	return owner{id: store.state.OwnerID, credentials: credentials}
}

func (store *Store) deviceCount() int {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	return len(store.state.Devices)
}

func (store *Store) credentialDescriptors() []protocol.CredentialDescriptor {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	descriptors := make([]protocol.CredentialDescriptor, len(store.state.Devices))
	for index, device := range store.state.Devices {
		descriptors[index] = device.Credential.Descriptor()
	}
	return descriptors
}

func (store *Store) addDevice(name string, credential *webauthn.Credential) (Device, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	now := time.Now()
	device := Device{ID: randomToken(9), Name: name, CreatedAt: now, LastUsedAt: now, Credential: *credential}
	store.state.Devices = append(store.state.Devices, device)
	if err := store.saveLocked(); err != nil {
		store.state.Devices = store.state.Devices[:len(store.state.Devices)-1]
		return Device{}, err
	}
	return device, nil
}

func (store *Store) recordSignIn(credential *webauthn.Credential) (Device, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	for index := range store.state.Devices {
		device := &store.state.Devices[index]
		if bytes.Equal(device.Credential.ID, credential.ID) {
			device.Credential = *credential
			device.LastUsedAt = time.Now()
			return *device, store.saveLocked()
		}
	}
	return Device{}, errDeviceNotFound
}

func (store *Store) listDevices() []Device {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	return append([]Device(nil), store.state.Devices...)
}

func (store *Store) hasDevice(deviceID string) bool {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	for _, device := range store.state.Devices {
		if device.ID == deviceID {
			return true
		}
	}
	return false
}

func (store *Store) removeDevice(deviceID string) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	for index, device := range store.state.Devices {
		if device.ID != deviceID {
			continue
		}
		if len(store.state.Devices) == 1 {
			return errLastDevice
		}
		remaining := append(append([]Device(nil), store.state.Devices[:index]...), store.state.Devices[index+1:]...)
		previous := store.state.Devices
		store.state.Devices = remaining
		if err := store.saveLocked(); err != nil {
			store.state.Devices = previous
			return err
		}
		return nil
	}
	return errDeviceNotFound
}

func setupTokenPath(dataDirectory string) string {
	return filepath.Join(dataDirectory, "setup-token")
}

func issueSetupLink(dataDirectory, origin string) (string, error) {
	if err := os.MkdirAll(dataDirectory, 0o700); err != nil {
		return "", err
	}
	token := randomToken(24)
	if err := os.WriteFile(setupTokenPath(dataDirectory), []byte(token), 0o600); err != nil {
		return "", err
	}
	return origin + "/#setup=" + token, nil
}

func setupTokenValid(dataDirectory, candidate string) bool {
	if candidate == "" {
		return false
	}
	info, err := os.Stat(setupTokenPath(dataDirectory))
	if err != nil || time.Since(info.ModTime()) > setupTokenLifetime {
		return false
	}
	contents, err := os.ReadFile(setupTokenPath(dataDirectory))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(string(contents))), []byte(candidate)) == 1
}

func discardSetupToken(dataDirectory string) {
	os.Remove(setupTokenPath(dataDirectory))
}

func randomBytes(length int) []byte {
	buffer := make([]byte, length)
	if _, err := rand.Read(buffer); err != nil {
		panic(err)
	}
	return buffer
}

func randomToken(length int) string {
	return base64.RawURLEncoding.EncodeToString(randomBytes(length))
}
