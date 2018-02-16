// +build pkcs11

package luna

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/theupdateframework/notary"
	"github.com/theupdateframework/notary/trustmanager"
	"github.com/theupdateframework/notary/tuf/data"
	"github.com/theupdateframework/notary/tuf/signed"
	"github.com/theupdateframework/notary/tuf/utils"
	"github.com/miekg/pkcs11"
)

//Struct to keep a cache of all of the configuration in the Chrystoki.conf
type Configuration struct {
	loaded      bool
	libraryPath string
	slot        string
	tokenLabel  string
}

type Context struct {
	p           *pkcs11.Ctx
	initialized bool
}

type CleanupInfo struct {
	initialized   bool
	openedSession bool
	loggedIn      bool
}

var (
	userPin       = ""
	context       Context
	configuration Configuration
)

// LunaPrivateKey represents a private key inside of a Luna HSM
type LunaPrivateKey struct {
	data.PublicKey
	sigAlgorithm  data.SigAlgorithm
	passRetriever notary.PassRetriever
	keyID         []byte
}

type LunaSigner struct {
	LunaPrivateKey
}

func NewLunaPrivateKey(keyID []byte, pubKey data.PublicKey, sigAlgorithm data.SigAlgorithm, passRetriever notary.PassRetriever) *LunaPrivateKey {

	return &LunaPrivateKey{
		PublicKey:     pubKey,
		sigAlgorithm:  sigAlgorithm,
		passRetriever: passRetriever,
		keyID:         keyID,
	}
}

func (ls *LunaSigner) Public() crypto.PublicKey {
	publicKey, err := x509.ParsePKIXPublicKey(ls.LunaPrivateKey.Public())
	if err != nil {
		return nil
	}
	return publicKey
}

// CryptoSigner returns a crypto.Signer tha wraps the LunaPrivateKey. Needed for
// Certificate generation
func (l *LunaPrivateKey) CryptoSigner() crypto.Signer {
	return &LunaSigner{LunaPrivateKey: *l}
}

func (l *LunaPrivateKey) Private() []byte {
	// We cannot return the private material from a Luna key
	return nil
}

func (l *LunaPrivateKey) SignatureAlgorithm() data.SigAlgorithm {
	return l.sigAlgorithm
}

func (l *LunaPrivateKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {

	p, session, c, err := SetupLuna(true, l.passRetriever)
	if err != nil {
		return nil, err
	}
	defer CleanupLuna(p, session, c)

	objectHandle, err := getPrivateKeyHandle(p, session, l.keyID)

	v := signed.Verifiers[l.sigAlgorithm]

	sig, err := sign(p, session, objectHandle, msg, l.sigAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to sign using Luna: %v", err)
	}
	if err := v.Verify(l.PublicKey, sig, msg); err == nil {
		return sig, nil
	}

	return nil, errors.New("Failed to generate signature on Luna.")
}

func destroyObjectsIfErr(p *pkcs11.Ctx, session pkcs11.SessionHandle, err error, objectHandles []pkcs11.ObjectHandle) bool {
	if err != nil {
		destroyObjects(p, session, objectHandles)
		return true
	}
	return false
}

//Create a certificate in the HSM for the privateKey
func createCertificate(p *pkcs11.Ctx, session pkcs11.SessionHandle, gun data.GUN, role data.RoleName, id string, privateKey *LunaPrivateKey) (pkcs11.ObjectHandle, error) {

	// Hard-coded policy: the generated certificate expires in 10 years.
	startTime := time.Now()
	template, err := utils.NewCertificate(string(role), startTime, startTime.AddDate(10, 0, 0))
	if err != nil {
		return 0, fmt.Errorf("Failed to create the certificate template: %v", err)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.CryptoSigner().Public(), privateKey.CryptoSigner())
	if err != nil {
		return 0, fmt.Errorf("failed to create the certificate: %v", err)
	}

	certTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, certBytes),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, 0),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, fmt.Sprintf("cn=%s", role)),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, fmt.Sprintf("notary-%s;%s;%s;cert", gun, id, role)),
	}

	certObjectHandle, err := p.CreateObject(session, certTemplate)
	if err != nil {
		return 0, fmt.Errorf("Failed to created certificate object")
	}
	return certObjectHandle, nil
}

//Helper function to set the CKA_ID for a list of object handles
func setIDForObjectHandles(p *pkcs11.Ctx, session pkcs11.SessionHandle, keyID []byte, objectHandles []pkcs11.ObjectHandle) error {
	idTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
	}
	for _, objectHandle := range objectHandles {
		err := p.SetAttributeValue(session, objectHandle, idTemplate)
		if destroyObjectsIfErr(p, session, err, objectHandles) {
			return err
		}
	}
	return nil
}

//Helper function to set the CKA_ID and CKA_LABEL for a list of object handles
func setIDsAndLabels(p *pkcs11.Ctx, session pkcs11.SessionHandle, gun data.GUN, role data.RoleName, id string, labels []string, objects []pkcs11.ObjectHandle) error {

	for i, object := range objects {
		label := labels[i]
		idLabelTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(id)),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(fmt.Sprintf("notary-%s;%s;%s;%s", string(gun), id, string(role), label))),
		}
		err := p.SetAttributeValue(session, object, idLabelTemplate)
		if err != nil {
			return fmt.Errorf("Failed to set id/label for objects: %v", err)
		}
	}
	return nil
}

//Generate an ECDSA key and certificate inside of the HSM
func generateECDSAKey(p *pkcs11.Ctx,
	session pkcs11.SessionHandle,
	gun data.GUN,
	passRetriever notary.PassRetriever,
	role data.RoleName,
) (*LunaPrivateKey, error) {

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, fmt.Sprintf("notary-%s;;%s;public", gun, role)),
	}

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_ECDSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, fmt.Sprintf("notary-%s;;%s;private", gun, role)),
	}

	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA_KEY_PAIR_GEN, nil)}
	pubObjectHandle, privObjectHandle, err := p.GenerateKeyPair(session, mechanism, publicKeyTemplate, privateKeyTemplate)
	if err != nil {
		logrus.Debugf("Failed to generate key pair: %s", err.Error())
		return nil, fmt.Errorf("Failed to generate key pair: %v", err)
	}

	pubKey, _, err := getECDSAKeyFromObjectHandle(p, session, pubObjectHandle)
	if destroyObjectsIfErr(p, session, err, []pkcs11.ObjectHandle{pubObjectHandle, privObjectHandle}) {
		return nil, err
	}

	pubID := []byte(pubKey.ID())
	err = setIDForObjectHandles(p, session, pubID, []pkcs11.ObjectHandle{pubObjectHandle, privObjectHandle})
	if err != nil {
		return nil, err
	}

	privateKey := NewLunaPrivateKey(pubID, pubKey, data.ECDSASignature, passRetriever)
	if privateKey == nil {
		destroyObjects(p, session, []pkcs11.ObjectHandle{pubObjectHandle, privObjectHandle})
		return nil, errors.New("could not initialize new LunaPrivateKey")
	}

	id := pubKey.ID()

	certObjectHandle, err := createCertificate(p, session, gun, role, id, privateKey)
	if err != nil {
		destroyObjects(p, session, []pkcs11.ObjectHandle{pubObjectHandle, privObjectHandle})
		return nil, fmt.Errorf("Error creating certificate: %v", err)
	}

	logrus.Debugf("Setting keyID: %s", id)
	privateKey.keyID = []byte(id)

	objectHandles := []pkcs11.ObjectHandle{pubObjectHandle, privObjectHandle, certObjectHandle}

	err = setIDsAndLabels(p, session, gun, role, id, []string{"public", "private", "cert"}, objectHandles)
	if err != nil {
		destroyObjects(p, session, objectHandles)
		return nil, err
	}

	return privateKey, nil
}

//Generate an RSA key and certificate inside of the HSM
func generateRSAKey(p *pkcs11.Ctx,
	session pkcs11.SessionHandle,
	gun data.GUN,
	passRetriever notary.PassRetriever,
	role data.RoleName,
) (*LunaPrivateKey, error) {

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, fmt.Sprintf("notary-%s;;%s;public", gun, role)),
	}

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, fmt.Sprintf("notary-%s;;%s;private", gun, role)),
	}

	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}
	pubObjectHandle, privObjectHandle, err := p.GenerateKeyPair(session, mechanism, publicKeyTemplate, privateKeyTemplate)
	if err != nil {
		logrus.Debugf("Failed to generate key pair: %s", err.Error())
		return nil, fmt.Errorf("Failed to generate key pair: %v", err)
	}

	pubKey, _, err := getRSAKeyFromObjectHandle(p, session, pubObjectHandle)
	if err != nil {
		destroyObjects(p, session, []pkcs11.ObjectHandle{pubObjectHandle, privObjectHandle})
		return nil, err
	}
	pubID := []byte(pubKey.ID())
	err = setIDForObjectHandles(p, session, pubID, []pkcs11.ObjectHandle{pubObjectHandle, privObjectHandle})
	if err != nil {
		return nil, err
	}

	privateKey := NewLunaPrivateKey(pubID, pubKey, data.RSAPKCS1v15Signature, passRetriever)
	if privateKey == nil {
		destroyObjects(p, session, []pkcs11.ObjectHandle{pubObjectHandle, privObjectHandle})
		return nil, errors.New("could not initialize new LunaPrivateKey")
	}

	id := pubKey.ID()

	certObjectHandle, err := createCertificate(p, session, gun, role, id, privateKey)
	if err != nil {
		destroyObjects(p, session, []pkcs11.ObjectHandle{pubObjectHandle, privObjectHandle})
		return nil, fmt.Errorf("Error creating certificate: %v", err)
	}

	logrus.Debugf("Setting keyID: %s", id)
	privateKey.keyID = []byte(id)

	objectHandles := []pkcs11.ObjectHandle{pubObjectHandle, privObjectHandle, certObjectHandle}

	err = setIDsAndLabels(p, session, gun, role, id, []string{"public", "private", "cert"}, objectHandles)
	if err != nil {
		destroyObjects(p, session, objectHandles)
		return nil, err
	}

	return privateKey, nil
}

//Get an ecdsa.PublicKeyFrom the raw bytes of CKA_EC_POINT
func getECDSAPublicKey(rawPubKey []byte) (*ecdsa.PublicKey, error) {
	tag := rawPubKey[0]
	uncompressed := rawPubKey[2]
	if tag != 0x04 || uncompressed != 0x04 {
		return nil, errors.New("Invalid public key.")
	}
	length := int(rawPubKey[1]) - 1
	if len(rawPubKey) != (3 + length) {
		return nil, errors.New("Invalid public key.")
	}
	x := new(big.Int).SetBytes(rawPubKey[3 : 3+(length/2)])
	y := new(big.Int).SetBytes(rawPubKey[3+(length/2):])
	ecdsaPubKey := ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	return &ecdsaPubKey, nil
}

//Get an rsa.PublicKey from the raw bytes of modulus and exponent
func getRSAPublicKey(modulus []byte, exponent []byte) (*rsa.PublicKey, error) {
	n := new(big.Int).SetBytes(modulus)
	e := new(big.Int).SetBytes(exponent)
	eInt := int(e.Int64())
	rsaPubKey := rsa.PublicKey{N: n, E: eInt}
	return &rsaPubKey, nil
}

//Get a tuf ECDSAPublicKey from an object handle
func getECDSAKeyFromObjectHandle(p *pkcs11.Ctx, session pkcs11.SessionHandle, objectHandle pkcs11.ObjectHandle) (*data.ECDSAPublicKey, data.RoleName, error) {

	attrTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, []byte{0}),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte{0}),
	}

	attr, err := p.GetAttributeValue(session, objectHandle, attrTemplate)
	if err != nil {
		logrus.Debugf("Failed to get Attribute for: %d", objectHandle)
		return nil, "", fmt.Errorf("Failed to get attribute %d: %v", objectHandle, err)
	}

	role := data.CanonicalRootRole

	var rawPubKey []byte
	for _, a := range attr {
		if a.Type == pkcs11.CKA_EC_POINT {
			rawPubKey = a.Value
		}
		if a.Type == pkcs11.CKA_LABEL {
			split := strings.Split(string(a.Value), ";")
			if len(split) != 4 {
				return nil, "", fmt.Errorf("Key contained invalid label.")
			}
			role = data.RoleName(split[2])
		}
	}

	ecdsaPubKey, err := getECDSAPublicKey(rawPubKey)
	if err != nil {
		return nil, "", err
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(ecdsaPubKey)
	if err != nil {
		logrus.Debugf("Failed to Marshal public key")
		return nil, "", err
	}
	return data.NewECDSAPublicKey(pubBytes), role, nil
}

//Get a tuf RSAPublicKey from an object handle
func getRSAKeyFromObjectHandle(p *pkcs11.Ctx, session pkcs11.SessionHandle, objectHandle pkcs11.ObjectHandle) (*data.RSAPublicKey, data.RoleName, error) {

	attrTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, []byte{0}),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{0}),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte{0}),
	}

	attr, err := p.GetAttributeValue(session, objectHandle, attrTemplate)
	if err != nil {
		logrus.Debugf("Failed to get Attribute for: %d", objectHandle)
		return nil, "", fmt.Errorf("Failed to get attribute %d: %v", objectHandle, err)
	}

	role := data.CanonicalRootRole

	var modulus []byte
	var exponent []byte
	for _, a := range attr {
		if a.Type == pkcs11.CKA_MODULUS {
			modulus = a.Value
		} else if a.Type == pkcs11.CKA_PUBLIC_EXPONENT {
			exponent = a.Value
		} else if a.Type == pkcs11.CKA_LABEL {
			split := strings.Split(string(a.Value), ";")
			if len(split) != 4 {
				return nil, "", fmt.Errorf("Key contained invalid label.")
			}
			role = data.RoleName(split[2])
		}
	}

	rsaPubKey, err := getRSAPublicKey(modulus, exponent)
	if err != nil {
		return nil, "", err
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(rsaPubKey)
	if err != nil {
		logrus.Debugf("Failed to Marshal RSA public key")
		return nil, "", err
	}
	return data.NewRSAPublicKey(pubBytes), role, nil
}

//Get a tuf PublicKey from a keyID
func getPublicKey(p *pkcs11.Ctx, session pkcs11.SessionHandle, keyID []byte) (data.PublicKey, data.RoleName, error) {
	findTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
	}

	if err := p.FindObjectsInit(session, findTemplate); err != nil {
		logrus.Debugf("Failed to init: %s", err.Error())
		return nil, "", err
	}
	obj, _, err := p.FindObjects(session, 1)
	if err != nil {
		logrus.Debugf("Failed to find objects: %v", err)
		return nil, "", err
	}
	if err := p.FindObjectsFinal(session); err != nil {
		logrus.Debugf("Failed to finalize: %s", err.Error())
		return nil, "", err
	}
	if len(obj) < 1 {
		logrus.Debugf("Should have found certificate object: %s", string(keyID))
		return nil, "", errors.New("no matching keys found inside of Luna")
	}

	objectHandle := obj[0]

	attrTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, []byte{0}),
	}

	attr, err := p.GetAttributeValue(session, objectHandle, attrTemplate)
	if err != nil {
		logrus.Debugf("Failed to get Attribute for: %d", objectHandle)
		return nil, "", fmt.Errorf("Failed to get attribute %d: %v", objectHandle, err)
	}

	certBytes := attr[0].Value

	certificate, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, "", fmt.Errorf("Failed to parse certificate: %d: %v", objectHandle, err)
	}

	role := data.RoleName(certificate.Subject.CommonName)
	if !data.ValidRole(role) {
		return nil, "", fmt.Errorf("Invalid role in certificate: %s: %s: %v", string(keyID), role, err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		logrus.Debugf("Failed to Marshal public key")
		return nil, "", err
	}
	switch certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		return data.NewRSAPublicKey(pubBytes), role, nil
	case *ecdsa.PublicKey:
		return data.NewECDSAPublicKey(pubBytes), role, nil
	}

	return nil, "", fmt.Errorf("Unable to determine public key from certificate: %s", string(keyID))
}

//Get the object handle of a private key given the keyID
func getPrivateKeyHandle(p *pkcs11.Ctx, session pkcs11.SessionHandle, keyID []byte) (pkcs11.ObjectHandle, error) {
	findTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	}
	if err := p.FindObjectsInit(session, findTemplate); err != nil {
		logrus.Debugf("Failed to init: %s", err.Error())
		return 0, err
	}
	obj, _, err := p.FindObjects(session, 1)
	if err != nil {
		logrus.Debugf("Failed to find objects: %v", err)
		return 0, err
	}
	if err := p.FindObjectsFinal(session); err != nil {
		logrus.Debugf("Failed to finalize: %s", err.Error())
		return 0, err
	}
	if len(obj) != 1 {
		logrus.Debugf("should have found one object")
		return 0, errors.New("no matching keys found inside of Luna")
	}
	return obj[0], nil
}

// Sign returns a signature for a given signature request
func sign(p *pkcs11.Ctx, session pkcs11.SessionHandle, objectHandle pkcs11.ObjectHandle, payload []byte, sigAlgorithm data.SigAlgorithm) ([]byte, error) {

	var (
		mechanism *pkcs11.Mechanism
		digest    []byte
	)

	sha256Prefix := []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}

	hash := sha256.Sum256(payload)

	if sigAlgorithm == data.ECDSASignature {
		mechanism = pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)
		digest = hash[:]
	} else {
		mechanism = pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)
		digest = append(sha256Prefix[:], hash[:]...)
	}

	var sig []byte
	err := p.SignInit(
		session, []*pkcs11.Mechanism{mechanism}, objectHandle)
	if err != nil {
		return nil, err
	}

	sig, err = p.Sign(session, digest[:])
	if err != nil {
		logrus.Debugf("Error while signing: %s", err)
		return nil, err
	}

	if sig == nil {
		return nil, errors.New("Failed to create signature")
	}
	return sig[:], nil
}

//Destroy objects for a list of object handles
func destroyObjects(p *pkcs11.Ctx, session pkcs11.SessionHandle, handles []pkcs11.ObjectHandle) error {
	for _, o := range handles {
		err := p.DestroyObject(session, o)
		if err != nil {
			return fmt.Errorf("Error destroying object %d: %v", o, err)
		}
	}
	return nil
}

//Remove public and private objects for a keyID
func lunaRemoveKey(p *pkcs11.Ctx, session pkcs11.SessionHandle, keyID []byte) error {

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
	}

	objects, err := findObjects(p, session, template)
	if err != nil {
		return fmt.Errorf("Find objects failed: %v", err)
	}

	for _, object := range objects {
		err = p.DestroyObject(session, object)
		if err != nil {
			return fmt.Errorf("Failed to remove object %d: %v", object, err)
		}
	}
	return nil
}

//Find objects given attribute template
func findObjects(p *pkcs11.Ctx, session pkcs11.SessionHandle, template []*pkcs11.Attribute) ([]pkcs11.ObjectHandle, error) {
	err := p.FindObjectsInit(session, template)
	if err != nil {
		return nil, err
	}
	var objects []pkcs11.ObjectHandle
	maxObjects := 1000
	for {
		o, _, err := p.FindObjects(session, maxObjects)
		if err != nil {
			return nil, err
		}
		if len(o) > 0 {
			objects = append(objects, o...)
		}
		if len(o) < maxObjects {
			break
		}
	}
	err = p.FindObjectsFinal(session)
	if err != nil {
		return nil, err
	}
	return objects, nil
}

//Check to see if a root key is to be filtered
func isRootKeyFiltered(id string) bool {
	selectedRootKeyId := os.Getenv("NOTARY_LUNA_ROOT_KEY")
	if selectedRootKeyId != "" && selectedRootKeyId != id {
		return true
	}
	return false
}

//Get the list of keys in the luna
func lunaListKeys(p *pkcs11.Ctx, session pkcs11.SessionHandle) (map[string]trustmanager.KeyInfo, error) {

	keys := make(map[string]trustmanager.KeyInfo)
	findTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
	}

	objects, err := findObjects(p, session, findTemplate)
	if err != nil {
		return nil, fmt.Errorf("Error finding objects: %v", err)
	}

	if len(objects) == 0 {
		return nil, errors.New("No keys found in Luna.")
	}

	attrTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte{0}),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, []byte{0}),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte{0}),
	}

	for _, obj := range objects {
		var (
			cert  *x509.Certificate
			id    []byte
			label string
			gun   string
		)
		// Retrieve the public-key material to be able to create a new ECDSA
		attr, err := p.GetAttributeValue(session, obj, attrTemplate)
		if err != nil {
			logrus.Debugf("Failed to get Attribute for: %v", obj)
			continue
		}

		for _, a := range attr {
			if a.Type == pkcs11.CKA_ID {
				id = a.Value
			}
			if a.Type == pkcs11.CKA_VALUE {
				cert, err = x509.ParseCertificate(a.Value)
				if err != nil {
					continue
				}
				if !data.ValidRole(data.RoleName(cert.Subject.CommonName)) {
					continue
				}
			}
			if a.Type == pkcs11.CKA_LABEL {
				if !strings.HasPrefix(string(a.Value), "notary-") {
					continue
				}
				label = string(a.Value)
			}
		}

		if id == nil {
			continue
		}

		if cert == nil {
			continue
		}

		if cert.PublicKeyAlgorithm != x509.ECDSA && cert.PublicKeyAlgorithm != x509.RSA {
			continue
		}

		fieldsSplit := strings.Split(label, "notary-")
		if len(fieldsSplit) != 2 {
			continue
		}
		split := strings.Split(fieldsSplit[1], ";")
		if len(split) < 1 {
			continue
		}
		gun = split[0]

		if cert.Subject.CommonName == "root" {
			if isRootKeyFiltered(string(id)) {
				continue
			}
		}

		keys[string(id)] = trustmanager.KeyInfo{Role: data.RoleName(cert.Subject.CommonName), Gun: data.GUN(gun)}
	}
	return keys, nil
}

// LunaKeyStore is a KeyStore for private keys inside a Luna HSM
type LunaKeyStore struct {
	passRetriever notary.PassRetriever
}

func NewLunaKeyStore(passphraseRetriever notary.PassRetriever) (
	*LunaKeyStore, error) {

	s := &LunaKeyStore{
		passRetriever: passphraseRetriever,
	}
	return s, nil
}

func (s *LunaKeyStore) Name() string {
	return "luna"
}

func (s *LunaKeyStore) ListKeys() map[string]trustmanager.KeyInfo {
	p, session, c, err := SetupLuna(true, s.passRetriever)
	if err != nil {
		return nil
	}
	defer CleanupLuna(p, session, c)
	keys, err := lunaListKeys(p, session)
	if err != nil {
		return nil
	}
	return keys
}

//Returns a tuf ECDSAPublic key from a tuf PrivateKey
func getECDSAPublicKeyFromPrivateKey(privKey data.PrivateKey) (*data.ECDSAPublicKey, error) {
	ecdsaKey, ok := privKey.(*data.ECDSAPrivateKey)
	if !ok {
		return nil, errors.New("Private key type invalid")
	}

	ecdsaPublicKey, ok := ecdsaKey.PublicKey.(*data.ECDSAPublicKey)
	if !ok {
		return nil, errors.New("Public key type invalid")
	}
	return ecdsaPublicKey, nil
}

//Returns a tuf RSAPublic key from a tuf PrivateKey
func getRSAPublicKeyFromPrivateKey(privKey data.PrivateKey) (*data.RSAPublicKey, error) {
	rsaKey, ok := privKey.(*data.RSAPrivateKey)
	if !ok {
		return nil, errors.New("Private key type invalid")
	}

	rsaPublicKey, ok := rsaKey.PublicKey.(*data.RSAPublicKey)
	if !ok {
		return nil, errors.New("Public key type invalid")
	}
	return rsaPublicKey, nil
}

//AddKey instead generates a key of the same type as opposed to importing the key to the HSM
func (s *LunaKeyStore) AddKey(keyInfo trustmanager.KeyInfo, privKey data.PrivateKey) error {

	var (
		ecdsaPublicKey *data.ECDSAPublicKey
		rsaPublicKey   *data.RSAPublicKey
		err            error
	)

	logrus.Debugf("LunaKeyStore.AddKey")

	role := keyInfo.Role

	generatateRootKeyOnly := strings.ToLower(os.Getenv("NOTARY_LUNA_GENERATE_ROOT_KEYS_ONLY")) == "true"

	if generatateRootKeyOnly && role != data.CanonicalRootRole {
		return errors.New("Can only generate root keys in generate root keys only mode.")
	}

	alg := privKey.Algorithm()

	if alg == data.ECDSAKey {
		ecdsaPublicKey, err = getECDSAPublicKeyFromPrivateKey(privKey)
		if err != nil {
			logrus.Debugf("Error getting ECDSA Public key: %s", err)
			return err
		}
	} else if alg == data.RSAKey {
		rsaPublicKey, err = getRSAPublicKeyFromPrivateKey(privKey)
		if err != nil {
			logrus.Debugf("Error getting RSA Public key: %s", err)
			return err
		}
	} else {
		return errors.New("Invalid key type.")
	}

	p, session, c, err := SetupLuna(true, s.passRetriever)
	if err != nil {
		return err
	}
	defer CleanupLuna(p, session, c)
	gun := keyInfo.Gun

	if alg == data.ECDSAKey {
		lunaPrivateKey, err := generateECDSAKey(p, session, gun, s.passRetriever, role)
		if err != nil {
			return err
		}
		//Store the public key value for the generated key in the public key for the added key.
		lunaECDSAPublicKey, ok := lunaPrivateKey.PublicKey.(*data.ECDSAPublicKey)
		if !ok {
			return errors.New("Unable to get PublicKey from luna private key.")
		}
		ecdsaPublicKey.Value = lunaECDSAPublicKey.Value
		ecdsaPublicKey.ResetID()
	} else if alg == data.RSAKey {
		lunaPrivateKey, err := generateRSAKey(p, session, gun, s.passRetriever, role)
		if err != nil {
			return err
		}
		lunaRSAPublicKey, ok := lunaPrivateKey.PublicKey.(*data.RSAPublicKey)
		if !ok {
			return errors.New("Unable to get PublicKey from luna private key.")
		}
		rsaPublicKey.Value = lunaRSAPublicKey.Value
		rsaPublicKey.ResetID()
	}
	fmt.Printf("Luna: Generated %s key: %s\n", role, privKey.ID())

	return nil
}

func (s *LunaKeyStore) GetKey(keyID string) (data.PrivateKey, data.RoleName, error) {

	logrus.Debugf("LunaKeyStore.GetKey: %s", keyID)

	p, session, c, err := SetupLuna(true, s.passRetriever)
	if err != nil {
		return nil, "", err
	}
	defer CleanupLuna(p, session, c)

	pubKey, alias, err := getPublicKey(p, session, []byte(keyID))
	if err != nil {
		return nil, "", err
	}

	if !strings.Contains(keyID, pubKey.ID()) {
		return nil, "", fmt.Errorf("expected root key: %s, but found: %s", keyID, pubKey.ID())
	}

	var sigAlgorithm data.SigAlgorithm
	sigAlgorithm = data.ECDSASignature
	if pubKey.Algorithm() == data.RSAKey {
		sigAlgorithm = data.RSAPKCS1v15Signature
	}

	privKey := NewLunaPrivateKey([]byte(keyID), pubKey, sigAlgorithm, s.passRetriever)
	if privKey == nil {
		return nil, "", errors.New("could not initialize new LunaPrivateKey")
	}

	return privKey, data.RoleName(alias), err
}

func (s *LunaKeyStore) RemoveKey(keyID string) error {
	logrus.Debugf("LunaKeyStore.RemoveKey: %s", keyID)
	p, session, c, err := SetupLuna(true, s.passRetriever)
	if err != nil {
		return err
	}
	defer CleanupLuna(p, session, c)

	err = lunaRemoveKey(p, session, []byte(keyID))
	if err != nil {
		logrus.Debugf("Failed to remove from the luna key: %s: %s", keyID, err.Error())
	}
	return err
}

func (s *LunaKeyStore) ExportKey(keyID string) ([]byte, error) {
	return nil, nil
}

func (s *LunaKeyStore) ImportKey(pemBytes []byte, keyPath string) error {
	return nil
}

// GetKeyInfo is not yet implemented
func (s *LunaKeyStore) GetKeyInfo(keyID string) (trustmanager.KeyInfo, error) {
	return trustmanager.KeyInfo{}, fmt.Errorf("Not yet implemented")
}

//Logs out, closes session and finalizes the library
func CleanupLuna(p *pkcs11.Ctx, session pkcs11.SessionHandle, cleanupInfo CleanupInfo) {

	if cleanupInfo.loggedIn {
		err := p.Logout(session)
		if err != nil {
			logrus.Debugf("Error logging out: %s", err.Error())
		}
	}
	if cleanupInfo.openedSession {
		err := p.CloseSession(session)
		if err != nil {
			logrus.Debugf("Error closing session: %s", err.Error())
		}
	}
	if cleanupInfo.initialized {
		finalize(p)
	}
}

//Finalize the library
func finalize(p *pkcs11.Ctx) {
	if !context.initialized {
		return
	}
	err := p.Finalize()
	if err != nil {
		logrus.Debugf("Error finalizing: %s", err.Error())
	}
	context.initialized = false
}

func LunaAccessible() bool {
	p, session, c, err := SetupLuna(false, nil)
	if err != nil {
		return false
	}
	defer CleanupLuna(p, session, c)
	return true
}

//Gets the password from the passphrase retriever and attempts to login to the partition
func login(p *pkcs11.Ctx, session pkcs11.SessionHandle, passRetriever notary.PassRetriever) error {

	for attempts := 0; ; attempts++ {
		var (
			giveup bool
			err    error
			passwd string
		)
		if userPin == "" {
			passwd, giveup, err = passRetriever("Partition Password", "luna", false, attempts)
		} else {
			giveup = false
			passwd = userPin
		}

		// Check if the passphrase retriever got an error or if it is telling us to give up
		if giveup || err != nil {
			return trustmanager.ErrPasswordInvalid{}
		}
		if attempts > 2 {
			return trustmanager.ErrAttemptsExceeded{}
		}

		err = p.Login(session, pkcs11.CKU_USER, passwd)
		if err == nil {
			if userPin == "" {
				userPin = passwd
			}
			return nil
		} else {
			userPin = ""
		}
	}
	return fmt.Errorf("Unable to login to the session")
}

//Gets the slot given the label of the token
func getSlotFromTokenLabel(p *pkcs11.Ctx, token string) (int, error) {
	slots, err := p.GetSlotList(true)
	if err != nil {
		return -1, err
	}
	for i := 0; i < len(slots); i++ {
		info, err := p.GetTokenInfo(slots[i])
		if err != nil {
			return -1, err
		}
		if info.Label == token {
			return int(slots[i]), nil
		}
	}
	return -1, fmt.Errorf("Unable to find token %s in any of the slots", token)
}

//Gets the path to Chrystoki.conf
func getConfFile() string {
	conf := "Chrystoki.conf"
	confPath := os.Getenv("ChrystokiConfigurationPath")
	if confPath == "" {
		confPath = "/etc"
	}
	return filepath.Join(confPath, conf)
}

//Reads the Chrystoki.conf file to a string
func readConfFile() string {
	path := getConfFile()
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

//gets a variable from the conf
func getConfVar(conf, section, key string) string {

	var inSection bool
	inSection = false
	lines := strings.Split(conf, "\n")
	for i := range lines {
		line := lines[i]
		m, _ := regexp.MatchString(fmt.Sprintf("^[\\s]*%s[\\s]*=[\\s]*\\{", section), line)
		if m {
			inSection = true
			continue
		}
		if inSection {
			m, _ = regexp.MatchString(".*\\}.*", line)
			if m {
				return ""
			}
			split := strings.Split(line, "=")
			if len(split) != 2 {
				continue
			}
			k := strings.TrimSpace(split[0])
			v := strings.TrimSpace(split[1])
			if key == k {
				return strings.Replace(v, ";", "", 1)
			}
		}
	}
	return ""
}

//Gets the configuration from the Chrystoki.conf file
func getConfiguration() (string, string, string) {
	var (
		libraryPath string
		tokenLabel  string
		slot        string
	)
	conf := readConfFile()
	if strconv.IntSize == 64 {
		libraryPath = getConfVar(conf, "Chrystoki2", "LibUNIX64")
	} else {
		libraryPath = getConfVar(conf, "Chrystoki2", "LibUNIX")
	}
	tokenLabel = getConfVar(conf, "Docker", "TokenLabel")
	slot = getConfVar(conf, "Docker", "Slot")
	return libraryPath, tokenLabel, slot
}

//Loads the configuration and caches
func loadConfiguration() {
	if configuration.loaded {
		return
	}
	libraryPath, tokenLabel, slot := getConfiguration()
	configuration.libraryPath = libraryPath
	logrus.Debugf("LibraryPath: %s", configuration.libraryPath)
	configuration.tokenLabel = tokenLabel
	configuration.slot = slot
	configuration.loaded = true
}

//Gets the token label and slot taking into account environment variables
func getTokenLabelAndSlot() (string, int) {
	var slot int
	slot = -1

	tokenLabel := configuration.tokenLabel
	tokenLabelEnv := os.Getenv("NOTARY_LUNA_TOKEN_LABEL")
	if tokenLabelEnv != "" {
		tokenLabel = tokenLabelEnv
	}
	s := configuration.slot
	slotEnv := os.Getenv("NOTARY_LUNA_SLOT")
	if slotEnv != "" {
		s = slotEnv
		if tokenLabelEnv == "" {
			tokenLabel = ""
		}
	}
	if s != "" {
		sint, err := strconv.Atoi(s)
		if err == nil {
			slot = sint
		}
	}
	return tokenLabel, slot
}

//Sets up an Luna context by loading the library, initializing, opening a session and logging in if needed
func SetupLuna(bLogin bool, passRetriever notary.PassRetriever) (*pkcs11.Ctx, pkcs11.SessionHandle, CleanupInfo, error) {

	var (
		slot       int
		err        error
		p          *pkcs11.Ctx
		tokenLabel string
	)

	cleanupInfo := CleanupInfo{}

	loadConfiguration()
	if context.p == nil && configuration.libraryPath != "" {
		context.p = pkcs11.New(configuration.libraryPath)
	}
	p = context.p

	if p == nil {
		err = fmt.Errorf("Unable to load cryptoki library!")
		logrus.Debugf("SetupLuna: %s", err)
		return nil, 0, cleanupInfo, err
	}

	tokenLabel, slot = getTokenLabelAndSlot()

	if !context.initialized {
		err = p.Initialize()
		if err != nil {
			defer finalize(p)
			err = fmt.Errorf("Unable to initialize cryptoki library: %s", err)
			logrus.Debugf("SetupLuna: %s", err)
			return nil, 0, cleanupInfo, err
		}
		context.initialized = true
		cleanupInfo.initialized = true
	}

	if !bLogin {
		return p, 0, cleanupInfo, nil
	}

	if tokenLabel != "" {
		s, err := getSlotFromTokenLabel(p, tokenLabel)
		if err == nil {
			slot = s
		}
	}

	if slot == -1 {
		slots, err := p.GetSlotList(true)
		if err != nil {
			defer finalize(p)
			err = fmt.Errorf("Unable to access slot list: %s", err)
			logrus.Debugf("SetupLuna: %s", err)
			return nil, 0, cleanupInfo, err
		}
		if len(slots) == 0 {
			err = fmt.Errorf("No available tokens!")
			logrus.Debugf("SetupLuna: %s", err)
			return nil, 0, cleanupInfo, err
		}
		slot = int(slots[0])
	}
	logrus.Debugf("SetupLuna: Using slot %d", slot)
	session, err := p.OpenSession(uint(slot), pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		defer finalize(p)
		return nil, 0, cleanupInfo, fmt.Errorf("Unable to open session in slot: %d", slot, err)
	}
	cleanupInfo.openedSession = true

	sessionInfo, err := p.GetSessionInfo(session)
	if err != nil {
		defer finalize(p)
		return nil, 0, cleanupInfo, fmt.Errorf("Unable to get session info for slot : %d", slot, err)
	}
	//If the session is already in a logged in state because of app ids, etc, no need
	//to login
	loggedInState := uint(3) //CKS_RW_USER_FUNCTIONS
	if sessionInfo.State == loggedInState {
		bLogin = false
	}

	if bLogin {
		err = login(p, session, passRetriever)
		if err != nil {
			defer finalize(p)
			defer p.CloseSession(session)
			return nil, 0, cleanupInfo, fmt.Errorf("Unable to login: %s", err)
		}
		cleanupInfo.loggedIn = true
	}
	return p, session, cleanupInfo, nil
}
