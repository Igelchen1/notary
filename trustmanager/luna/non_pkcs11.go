// +build !pkcs11

package luna

import (
	"github.com/theupdateframework/notary"
	"github.com/theupdateframework/notary/tuf/data"
)

type LunaKeyStore struct {
	passRetriever notary.PassRetriever
}

func (s *LunaKeyStore) AddKey(keyID, role string, privKey data.PrivateKey) error {
	return nil
}

func (s *LunaKeyStore) ExportKey(keyID string) ([]byte, error) {
	return nil, nil
}

func (s *LunaKeyStore) ImportKey(pemBytes []byte, keyPath string) error {
	return nil
}

func (s *LunaKeyStore) GetKey(keyID string) (data.PrivateKey, string, error) {
	return nil, "", nil
}

func (s *LunaKeyStore) RemoveKey(keyID string) error {
	return nil
}

func (s *LunaKeyStore) ListKeys() map[string]string {
	return nil
}

func (s LunaKeyStore) Name() string {
	return "luna"
}

func (s *LunaKeyStore) GenerateKey(gun, role string) (data.PrivateKey, error) {
	return nil, nil
}
