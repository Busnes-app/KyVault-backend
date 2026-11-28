package e2e

// What a Bitwarden client does with the keys the vault stores: derive the master key, unwrap
// the user key, encrypt and decrypt items (type 2 EncStrings), and the KyVault-web Personal
// Recovery Kit envelope (apps/web/src/app/tenancy/personal-recovery-crypto.ts).

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

var std = base64.StdEncoding

// masterKey is PBKDF2-SHA256 over the password, salted with the lowercased email (KDF type 0).
func masterKey(password, email string, iterations int) []byte {
	k, err := pbkdf2.Key(sha256.New, password, []byte(strings.ToLower(strings.TrimSpace(email))), iterations, 32)
	if err != nil {
		panic(err)
	}
	return k
}

// masterPasswordHash is what the client sends the server instead of the password.
func masterPasswordHash(mk []byte, password string) string {
	h, err := pbkdf2.Key(sha256.New, string(mk), []byte(password), 1, 32)
	if err != nil {
		panic(err)
	}
	return std.EncodeToString(h)
}

// stretch expands the master key into the 64-byte enc||mac key that wraps the user key.
func stretch(mk []byte) []byte {
	enc, err1 := hkdf.Expand(sha256.New, mk, "enc", 32)
	mac, err2 := hkdf.Expand(sha256.New, mk, "mac", 32)
	if err := errors.Join(err1, err2); err != nil {
		panic(err)
	}
	return append(enc, mac...)
}

// encString encrypts with AES-256-CBC and HMAC-SHA256 under a 64-byte enc||mac key.
func encString(key, plain []byte) string {
	iv := make([]byte, 16)
	_, _ = rand.Read(iv)
	pad := 16 - len(plain)%16
	data := append(bytes.Clone(plain), bytes.Repeat([]byte{byte(pad)}, pad)...)
	block, _ := aes.NewCipher(key[:32])
	ct := make([]byte, len(data))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, data)
	m := hmac.New(sha256.New, key[32:])
	m.Write(iv)
	m.Write(ct)
	return "2." + std.EncodeToString(iv) + "|" + std.EncodeToString(ct) + "|" + std.EncodeToString(m.Sum(nil))
}

func decString(key []byte, s string) ([]byte, error) {
	parts := strings.Split(strings.TrimPrefix(s, "2."), "|")
	if !strings.HasPrefix(s, "2.") || len(parts) != 3 {
		return nil, errors.New("not a type 2 EncString")
	}
	var raw [3][]byte
	for i, p := range parts {
		b, err := std.DecodeString(p)
		if err != nil {
			return nil, err
		}
		raw[i] = b
	}
	iv, ct, mac := raw[0], raw[1], raw[2]
	m := hmac.New(sha256.New, key[32:])
	m.Write(iv)
	m.Write(ct)
	if !hmac.Equal(m.Sum(nil), mac) || len(iv) != 16 || len(ct) == 0 || len(ct)%16 != 0 {
		return nil, errors.New("EncString MAC or shape mismatch")
	}
	block, _ := aes.NewCipher(key[:32])
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ct)
	pad := int(out[len(out)-1])
	if pad == 0 || pad > 16 {
		return nil, errors.New("bad padding")
	}
	return out[:len(out)-pad], nil
}

// ---------------------------------------------------------------------------
// Personal Recovery Kit, byte-compatible with KyVault-web.

const kitInfo = "KyVault personal recovery v1"

type kitPayload struct {
	Version   int `json:"version"`
	KdfParams struct {
		Name   string `json:"name"`
		Hash   string `json:"hash"`
		Salt   string `json:"salt"`
		Info   string `json:"info"`
		Cipher string `json:"cipher"`
	} `json:"kdfParams"`
	WrappedUserKey    string  `json:"wrappedUserKey"`
	WrappedPrivateKey *string `json:"wrappedPrivateKey,omitempty"`
}

func kitAEAD(secret, salt []byte) cipher.AEAD {
	k, err := hkdf.Key(sha256.New, secret, salt, kitInfo, 32)
	if err != nil {
		panic(err)
	}
	block, _ := aes.NewCipher(k)
	g, _ := cipher.NewGCM(block)
	return g
}

func kitAAD(tenant, user, field string) []byte {
	b, _ := json.Marshal([]string{kitInfo, tenant, user, field})
	return b
}

// newKit wraps the user key and private key as the web client does; it returns the secret
// in the kit's dashed hex form.
func newKit(userKey, privateKey []byte, tenant, user string) (string, kitPayload) {
	secret, salt := make([]byte, 32), make([]byte, 32)
	_, _ = rand.Read(secret)
	_, _ = rand.Read(salt)
	g := kitAEAD(secret, salt)
	wrap := func(b []byte, field string) string {
		iv := make([]byte, 12)
		_, _ = rand.Read(iv)
		return std.EncodeToString(g.Seal(iv, iv, b, kitAAD(tenant, user, field)))
	}
	var p kitPayload
	p.Version = 1
	p.KdfParams.Name, p.KdfParams.Hash, p.KdfParams.Info, p.KdfParams.Cipher = "HKDF", "SHA-256", kitInfo, "AES-256-GCM"
	p.KdfParams.Salt = std.EncodeToString(salt)
	p.WrappedUserKey = wrap(userKey, "userKey")
	pk := wrap(privateKey, "privateKey")
	p.WrappedPrivateKey = &pk
	h := hex.EncodeToString(secret)
	var groups []string
	for i := 0; i < len(h); i += 8 {
		groups = append(groups, h[i:i+8])
	}
	return strings.Join(groups, "-"), p
}

// openKit is the recovery: the kit secret unwraps the user key and private key.
func openKit(p kitPayload, secret, tenant, user string) (userKey, privateKey []byte, err error) {
	kp := p.KdfParams
	if p.Version != 1 || kp.Name != "HKDF" || kp.Hash != "SHA-256" || kp.Info != kitInfo || kp.Cipher != "AES-256-GCM" {
		return nil, nil, errors.New("unsupported kit")
	}
	raw, err := hex.DecodeString(strings.ReplaceAll(secret, "-", ""))
	if err != nil || len(raw) != 32 {
		return nil, nil, errors.New("bad secret")
	}
	salt, err := std.DecodeString(kp.Salt)
	if err != nil || len(salt) != 32 {
		return nil, nil, errors.New("bad salt")
	}
	g := kitAEAD(raw, salt)
	unwrap := func(s, field string) ([]byte, error) {
		b, err := std.DecodeString(s)
		if err != nil || len(b) < 29 {
			return nil, errors.New("bad envelope")
		}
		return g.Open(nil, b[:12], b[12:], kitAAD(tenant, user, field))
	}
	if userKey, err = unwrap(p.WrappedUserKey, "userKey"); err != nil {
		return nil, nil, err
	}
	if p.WrappedPrivateKey != nil {
		if privateKey, err = unwrap(*p.WrappedPrivateKey, "privateKey"); err != nil {
			return nil, nil, err
		}
	}
	return userKey, privateKey, nil
}

// TestRecoveryKitOpensWebClientKit opens a kit made by KyVault-web's own code (testdata), so
// the live journey's recovery uses the web client's format, not just this file's idea of it.
func TestRecoveryKitOpensWebClientKit(t *testing.T) {
	raw, err := os.ReadFile("testdata/recovery-kit-web-v1.json")
	must(t, err)
	var v struct {
		Context struct {
			UserID   string `json:"userId"`
			TenantID string `json:"tenantId"`
		} `json:"context"`
		Secret     string     `json:"secret"`
		Payload    kitPayload `json:"payload"`
		UserKey    string     `json:"userKey"`
		PrivateKey string     `json:"privateKey"`
	}
	must(t, json.Unmarshal(raw, &v))
	uk, pk, err := openKit(v.Payload, v.Secret, v.Context.TenantID, v.Context.UserID)
	must(t, err)
	if std.EncodeToString(uk) != v.UserKey || std.EncodeToString(pk) != v.PrivateKey {
		t.Fatal("web kit opened to the wrong keys")
	}
	if _, _, err := openKit(v.Payload, v.Secret, v.Context.TenantID, "another-user"); err == nil {
		t.Fatal("a kit opened for another user (AAD not bound)")
	}
	if _, _, err := openKit(v.Payload, v.Secret, "another-tenant", v.Context.UserID); err == nil {
		t.Fatal("a kit opened for another tenant (AAD not bound)")
	}
	wrong := "0" + v.Secret[1:]
	if wrong == v.Secret {
		wrong = "1" + v.Secret[1:]
	}
	if _, _, err := openKit(v.Payload, wrong, v.Context.TenantID, v.Context.UserID); err == nil {
		t.Fatal("a kit opened with the wrong secret")
	}

	// And a kit made here opens the same way.
	secret, p := newKit(uk, pk, "t", "u")
	uk2, pk2, err := openKit(p, secret, "t", "u")
	must(t, err)
	if !bytes.Equal(uk, uk2) || !bytes.Equal(pk, pk2) {
		t.Fatal("round trip changed the keys")
	}
}

func TestEncStringRoundTrip(t *testing.T) {
	mk := masterKey("correct horse", "Alice@E2E.test", 5000)
	key := make([]byte, 64)
	_, _ = rand.Read(key)
	s := encString(stretch(mk), key)
	got, err := decString(stretch(mk), s)
	must(t, err)
	if !bytes.Equal(got, key) {
		t.Fatal("round trip changed the key")
	}
	if _, err := decString(stretch(masterKey("wrong", "alice@e2e.test", 5000)), s); err == nil {
		t.Fatal("a wrong password unwrapped the user key")
	}
}
