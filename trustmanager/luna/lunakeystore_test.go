// +build pkcs11

package luna

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/theupdateframework/notary/passphrase"
	"github.com/theupdateframework/notary/trustmanager"
	"github.com/theupdateframework/notary/tuf/data"
	"github.com/theupdateframework/notary/tuf/signed"
	"github.com/theupdateframework/notary/tuf/utils"
)

var ret = passphrase.ConstantRetriever("userpin")

//clears all keys from the luna partition
func clearAllKeys(t *testing.T) {
	store, err := NewLunaKeyStore(ret)
	require.NoError(t, err)

	for k := range store.ListKeys() {
		err := store.RemoveKey(k)
		require.NoError(t, err)
	}
}

// Test that generates a root ECDSA key and verifies that the key is in the
// key list.
func TestGenerateRootECDSAKey(t *testing.T) {

	clearAllKeys(t)

	privKey, err := utils.GenerateECDSAKey(rand.Reader)
	require.NoError(t, err)

	store, err := NewLunaKeyStore(ret)

	err = store.AddKey(trustmanager.KeyInfo{Role: data.CanonicalRootRole, Gun: ""}, privKey)
	require.NoError(t, err)

	ecdsaPublicKey := data.NewECDSAPublicKey(privKey.Public())

	keys := store.ListKeys()

	require.Equal(t, 1, len(keys), "There should be one key in list.")

	for k := range keys {
		require.Equal(t, ecdsaPublicKey.ID(), k, "The key returned has the wrong id.")
	}

}

// Test that adding a snapshot or targets key fails when in generate root key only mode.
func TestGenerateSnapshotTargetsECDSAKeyRootKeysOnlyMode(t *testing.T) {

	clearAllKeys(t)

	gun := "example.com/collection"

	privKey, err := utils.GenerateECDSAKey(rand.Reader)
	require.NoError(t, err)

	store, err := NewLunaKeyStore(ret)

	os.Setenv("NOTARY_LUNA_GENERATE_ROOT_KEYS_ONLY", "true")
	defer os.Setenv("NOTARY_LUNA_GENERATE_ROOT_KEYS_ONLY", "")

	err = store.AddKey(trustmanager.KeyInfo{Role: data.CanonicalSnapshotRole, Gun: data.GUN(gun)}, privKey)
	require.Error(t, err)
	require.Equal(t, err.Error(), "Can only generate root keys in generate root keys only mode.")

	err = store.AddKey(trustmanager.KeyInfo{Role: data.CanonicalTargetsRole, Gun: data.GUN(gun)}, privKey)
	require.Error(t, err)
	require.Equal(t, err.Error(), "Can only generate root keys in generate root keys only mode.")

	err = store.AddKey(trustmanager.KeyInfo{Role: data.CanonicalRootRole, Gun: ""}, privKey)
	require.NoError(t, err)
}

// Test that generates a root RSA key and verifies that the key is in the
// key list.
func TestGenerateRootRSAKey(t *testing.T) {

	//log.SetLevel(log.DebugLevel)
	clearAllKeys(t)

	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privKey, err := utils.RSAToPrivateKey(rsaPrivKey)
	require.NoError(t, err)

	store, err := NewLunaKeyStore(ret)

	err = store.AddKey(trustmanager.KeyInfo{Role: data.CanonicalRootRole, Gun: ""}, privKey)
	require.NoError(t, err)

	rsaPublicKey := data.NewRSAPublicKey(privKey.Public())

	keys := store.ListKeys()

	require.Equal(t, 1, len(keys), "There should be one key in list.")

	for k := range keys {
		require.Equal(t, rsaPublicKey.ID(), k, "The key returned has the wrong id.")
	}

}

// Test that generates a snapshot ECDSA key, performs a signature and
// verifies signature
func TestGenerateSnapshotECDSAKeySign(t *testing.T) {

	//log.SetLevel(log.DebugLevel)

	gun := "example.com/collection"

	clearAllKeys(t)

	privKey, err := utils.GenerateECDSAKey(rand.Reader)
	require.NoError(t, err)

	store, err := NewLunaKeyStore(ret)

	err = store.AddKey(trustmanager.KeyInfo{Role: data.CanonicalSnapshotRole, Gun: data.GUN(gun)}, privKey)
	require.NoError(t, err)

	ecdsaPublicKey := data.NewECDSAPublicKey(privKey.Public())

	keys := store.ListKeys()

	require.Equal(t, 1, len(keys), "There should be one key in list.")

	for k := range keys {
		require.Equal(t, ecdsaPublicKey.ID(), k, "The key returned has the wrong id.")
		require.Equal(t, data.CanonicalSnapshotRole, keys[k].Role, "The key has the wrong role.")
		require.Equal(t, data.GUN(gun), keys[k].Gun, "The key has the wrong gun.")
	}

	key, alias, err := store.GetKey(ecdsaPublicKey.ID())
	require.NoError(t, err)
	require.Equal(t, data.RoleName("snapshot"), alias)

	msg := []byte("Message to sign with a ECDSA key on an HSM!")
	sig, err := key.Sign(rand.Reader, msg, nil)
	require.NoError(t, err)

	ecdsaPublicKey = data.NewECDSAPublicKey(key.Public())
	v := signed.Verifiers[data.ECDSASignature]
	err = v.Verify(ecdsaPublicKey, sig, msg)
	require.NoError(t, err)
}

// Test that generates a snapshot RSA key, performs a signature and
// verifies signature
func TestGenerateTargetRSAKeySign(t *testing.T) {

	//log.SetLevel(log.DebugLevel)

	gun := "example.com/collection"

	clearAllKeys(t)

	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privKey, err := utils.RSAToPrivateKey(rsaPrivKey)
	require.NoError(t, err)

	store, err := NewLunaKeyStore(ret)

	err = store.AddKey(trustmanager.KeyInfo{Role: data.CanonicalTargetsRole, Gun: data.GUN(gun)}, privKey)
	require.NoError(t, err)

	rsaPublicKey := data.NewRSAPublicKey(privKey.Public())

	keys := store.ListKeys()

	require.Equal(t, 1, len(keys), "There should be one key in list.")

	for k := range keys {
		require.Equal(t, rsaPublicKey.ID(), k, "The key returned has the wrong id.")
		require.Equal(t, data.CanonicalTargetsRole, keys[k].Role, "The key has the wrong role.")
		require.Equal(t, data.GUN(gun), keys[k].Gun, "The key has the wrong gun.")
	}

	key, alias, err := store.GetKey(rsaPublicKey.ID())
	require.NoError(t, err)
	require.Equal(t, data.RoleName("targets"), alias)

	msg := []byte("Message to sign with an RSA key on an HSM!")
	sig, err := key.Sign(rand.Reader, msg, nil)
	require.NoError(t, err)

	rsaPublicKey = data.NewRSAPublicKey(key.Public())
	v := signed.Verifiers[data.RSAPKCS1v15Signature]
	err = v.Verify(rsaPublicKey, sig, msg)
	require.NoError(t, err)
}

//Tests the selection of a root key using an environment variable
func TestRootKeySelection(t *testing.T) {
	clearAllKeys(t)

	rsaPrivKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privKey1, err := utils.RSAToPrivateKey(rsaPrivKey1)
	require.NoError(t, err)

	store, err := NewLunaKeyStore(ret)

	err = store.AddKey(trustmanager.KeyInfo{Role: data.CanonicalRootRole, Gun: ""}, privKey1)
	require.NoError(t, err)
	rsaPublicKey1 := data.NewRSAPublicKey(privKey1.Public())

	rsaPrivKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privKey2, err := utils.RSAToPrivateKey(rsaPrivKey2)
	require.NoError(t, err)

	err = store.AddKey(trustmanager.KeyInfo{Role: data.CanonicalRootRole, Gun: ""}, privKey2)
	require.NoError(t, err)
	rsaPublicKey2 := data.NewRSAPublicKey(privKey2.Public())

	id1 := rsaPublicKey1.ID()
	id2 := rsaPublicKey2.ID()

	os.Setenv("NOTARY_LUNA_ROOT_KEY", id1)
	keys := store.ListKeys()
	require.Equal(t, 1, len(keys), "There should be one key in list.")
	for k := range keys {
		require.Equal(t, k, id1)
	}

	os.Setenv("NOTARY_LUNA_ROOT_KEY", id2)
	keys = store.ListKeys()
	require.Equal(t, 1, len(keys), "There should be one key in list.")
	for k := range keys {
		require.Equal(t, k, id2)
	}

	os.Setenv("NOTARY_LUNA_ROOT_KEY", "")
	keys = store.ListKeys()
	require.Equal(t, 2, len(keys), "There should be two keys returned.")

}

func setSlot(slot int) {
	os.Setenv("NOTARY_LUNA_SLOT", fmt.Sprintf("%d", slot))
}

func setTokenLabel(tokenLabel string) {
	os.Setenv("NOTARY_LUNA_TOKEN_LABEL", tokenLabel)
}

type SlotTokenLabel struct {
	slot       int
	tokenLabel string
}

func getSlotTokenLabels(t *testing.T) []SlotTokenLabel {
	p, session, cleanupInfo, err := SetupLuna(false, ret)
	require.NoError(t, err)
	slotTokenLabels := []SlotTokenLabel{}
	slots, err := p.GetSlotList(true)
	if err != nil {
		return slotTokenLabels
	}

	for i := 0; i < len(slots); i++ {
		info, err := p.GetTokenInfo(slots[i])

		if err != nil {
			continue
		}

		stl := SlotTokenLabel{slot: int(slots[i]), tokenLabel: info.Label}
		slotTokenLabels = append(slotTokenLabels, stl)
	}
	CleanupLuna(p, session, cleanupInfo)
	for _, stl := range slotTokenLabels {
		log.Debugf("Slot: %d, TokenLabel: %s", stl.slot, stl.tokenLabel)
	}

	return slotTokenLabels
}

//Tests the selection of the slot to use when using an environment variable
func TestSlotSelection(t *testing.T) {

	slotTokenLabels := getSlotTokenLabels(t)
	if len(slotTokenLabels) < 2 {
		t.Skip("Skipping test: need at least 2 slots.")
	}

	setSlot(slotTokenLabels[0].slot)
	clearAllKeys(t)
	rsaPrivKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privKey1, err := utils.RSAToPrivateKey(rsaPrivKey1)
	require.NoError(t, err)

	store1, err := NewLunaKeyStore(ret)
	require.NoError(t, err)

	err = store1.AddKey(trustmanager.KeyInfo{Role: data.CanonicalRootRole, Gun: ""}, privKey1)
	require.NoError(t, err)
	rsaPublicKey1 := data.NewRSAPublicKey(privKey1.Public())

	setSlot(slotTokenLabels[1].slot)
	clearAllKeys(t)
	rsaPrivKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privKey2, err := utils.RSAToPrivateKey(rsaPrivKey2)
	require.NoError(t, err)

	store2, err := NewLunaKeyStore(ret)
	require.NoError(t, err)

	err = store2.AddKey(trustmanager.KeyInfo{Role: data.CanonicalRootRole, Gun: ""}, privKey2)
	require.NoError(t, err)
	rsaPublicKey2 := data.NewRSAPublicKey(privKey2.Public())

	id1 := rsaPublicKey1.ID()
	id2 := rsaPublicKey2.ID()

	setSlot(slotTokenLabels[0].slot)
	keys := store1.ListKeys()
	require.Equal(t, 1, len(keys), "There should be one key in list.")
	for k := range keys {
		require.Equal(t, k, id1)
	}

	setSlot(slotTokenLabels[1].slot)
	keys = store2.ListKeys()
	require.Equal(t, 1, len(keys), "There should be one key in list.")
	for k := range keys {
		require.Equal(t, k, id2)
	}
	os.Setenv("NOTARY_LUNA_SLOT", "")
}

//Tests the selection of the slot by token label using an environment variable
func TestSlotSelectionByTokenLabel(t *testing.T) {

	slotTokenLabels := getSlotTokenLabels(t)
	if len(slotTokenLabels) < 2 {
		t.Skip("Skipping test: need at least 2 slots.")
	}

	setTokenLabel(slotTokenLabels[0].tokenLabel)
	clearAllKeys(t)
	rsaPrivKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privKey1, err := utils.RSAToPrivateKey(rsaPrivKey1)
	require.NoError(t, err)

	store1, err := NewLunaKeyStore(ret)
	require.NoError(t, err)

	err = store1.AddKey(trustmanager.KeyInfo{Role: data.CanonicalRootRole, Gun: ""}, privKey1)
	require.NoError(t, err)
	rsaPublicKey1 := data.NewRSAPublicKey(privKey1.Public())

	setTokenLabel(slotTokenLabels[1].tokenLabel)
	clearAllKeys(t)
	rsaPrivKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privKey2, err := utils.RSAToPrivateKey(rsaPrivKey2)
	require.NoError(t, err)

	store2, err := NewLunaKeyStore(ret)
	require.NoError(t, err)

	err = store2.AddKey(trustmanager.KeyInfo{Role: data.CanonicalRootRole, Gun: ""}, privKey2)
	require.NoError(t, err)
	rsaPublicKey2 := data.NewRSAPublicKey(privKey2.Public())

	id1 := rsaPublicKey1.ID()
	id2 := rsaPublicKey2.ID()

	setTokenLabel(slotTokenLabels[0].tokenLabel)
	keys := store1.ListKeys()
	require.Equal(t, 1, len(keys), "There should be one key in list.")
	for k := range keys {
		require.Equal(t, k, id1)
	}

	setTokenLabel(slotTokenLabels[1].tokenLabel)
	keys = store2.ListKeys()
	require.Equal(t, 1, len(keys), "There should be one key in list.")
	for k := range keys {
		require.Equal(t, k, id2)
	}
	os.Setenv("NOTARY_LUNA_TOKEN_LABEL", "")
}

//clears all keys from the luna partition
func clearAllKeysB(b *testing.B) {
	store, err := NewLunaKeyStore(ret)
	if err != nil {
		b.FailNow()
	}

	for k := range store.ListKeys() {
		err := store.RemoveKey(k)
		if err != nil {
			b.FailNow()
		}
	}
}

var keyId string
var nKeys = 250

func GenerateKeys(b *testing.B) {
	store, err := NewLunaKeyStore(ret)
	if err != nil {
		b.FailNow()
	}
	for i := 0; i <= nKeys; i++ {
		gun := fmt.Sprintf("example.com/collection%d", i)
		privKey, err := utils.GenerateECDSAKey(rand.Reader)
		if err != nil {
			b.FailNow()
		}

		err = store.AddKey(trustmanager.KeyInfo{Role: data.CanonicalSnapshotRole, Gun: data.GUN(gun)}, privKey)
		if err != nil {
			b.FailNow()
		}
	}
}

func AddKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		store, err := NewLunaKeyStore(ret)
		if err != nil {
			b.FailNow()
		}
		gun := "example2.com/collection"
		privKey, err := utils.GenerateECDSAKey(rand.Reader)
		if err != nil {
			b.FailNow()
		}

		err = store.AddKey(trustmanager.KeyInfo{Role: data.CanonicalSnapshotRole, Gun: data.GUN(gun)}, privKey)
		ecdsaPublicKey := data.NewECDSAPublicKey(privKey.Public())
		keyId = ecdsaPublicKey.ID()
	}
}

func GetKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		store, err := NewLunaKeyStore(ret)
		if err != nil {
			b.FailNow()
		}
		_, _, err = store.GetKey(keyId)
		if err != nil {
			b.FailNow()
		}
	}
}

func ListKeys(b *testing.B) {
	for i := 0; i < b.N; i++ {
		store, err := NewLunaKeyStore(ret)
		if err != nil {
			b.FailNow()
		}
		keys := store.ListKeys()
		if len(keys) == 0 {
			b.FailNow()
		}
	}
}

func Sign(b *testing.B) {
	for i := 0; i < b.N; i++ {
		store, err := NewLunaKeyStore(ret)
		if err != nil {
			b.FailNow()
		}
		key, _, err := store.GetKey(keyId)
		if err != nil {
			b.FailNow()
		}
		msg := []byte("Message to sign with an RSA key on an HSM!")
		_, err = key.Sign(rand.Reader, msg, nil)
		if err != nil {
			b.FailNow()
		}
	}
}

func RemoveKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		store, err := NewLunaKeyStore(ret)
		if err != nil {
			b.FailNow()
		}
		err = store.RemoveKey(keyId)
		if err != nil {
			b.FailNow()
		}
	}
}

func BenchmarkManyKeysPerformance(b *testing.B) {
	clearAllKeysB(b)
	GenerateKeys(b)
	b.Run("AddKey", AddKey)
	b.Run("GetKey", GetKey)
	b.Run("ListKeys", ListKeys)
	b.Run("Sign", Sign)
	b.Run("RemoveKey", RemoveKey)
	clearAllKeysB(b)
}
