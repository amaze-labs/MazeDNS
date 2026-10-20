package privacy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"strconv"
	"strings"
	"sync"
)

// PseudonymPrefix starts every client pseudonym, so it never reads as an
// address and is never stored twice.
const PseudonymPrefix = "anon-"

// keyringMetaKey holds the day keys (JSON: UTC day number -> base64 key) in
// app_meta, so pseudonyms stay stable across a control-plane restart.
const keyringMetaKey = "privacy_day_keys"

const dayMs = 24 * 60 * 60 * 1000

// MetaStore persists the keyring.
type MetaStore interface {
	GetMeta(key string) (string, error)
	SetMeta(key, value string) error
}

// Keyring holds one random secret per UTC day. A client's pseudonym is an HMAC
// of its address under its query's day key: the same device keeps one
// pseudonym for the day, and once a day's key is pruned nobody, the operator
// included, can tell which address a pseudonym stood for (hashing alone would
// not do: the address space is small enough to try every address).
type Keyring struct {
	mu     sync.Mutex
	st     MetaStore
	keys   map[int64][]byte
	loaded bool
}

// NewKeyring returns a keyring persisted in st.
func NewKeyring(st MetaStore) *Keyring {
	return &Keyring{st: st, keys: map[int64][]byte{}}
}

// IsPseudonym reports whether client is already a pseudonym.
func IsPseudonym(client string) bool { return strings.HasPrefix(client, PseudonymPrefix) }

// Pseudonym returns client's pseudonym for the day containing tsMs.
func (k *Keyring) Pseudonym(client string, tsMs int64) string {
	mac := hmac.New(sha256.New, k.key(tsMs/dayMs))
	mac.Write([]byte(client))
	return PseudonymPrefix + hex.EncodeToString(mac.Sum(nil)[:5])
}

// key returns the day's key, creating (and persisting) it on first use.
func (k *Keyring) key(day int64) []byte {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.load()
	if key, ok := k.keys[day]; ok {
		return key
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	k.keys[day] = key
	k.save()
	return key
}

// Prune forgets the keys of every day before the one containing beforeMs.
func (k *Keyring) Prune(beforeMs int64) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.load()
	before := beforeMs / dayMs
	changed := false
	for day := range k.keys {
		if day < before {
			delete(k.keys, day)
			changed = true
		}
	}
	if changed {
		k.save()
	}
}

// load reads the persisted keys once; k.mu must be held.
func (k *Keyring) load() {
	if k.loaded {
		return
	}
	k.loaded = true
	raw, err := k.st.GetMeta(keyringMetaKey)
	if err != nil || raw == "" {
		return
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		slog.Warn("privacy keyring unreadable; starting fresh", "err", err)
		return
	}
	for d, v := range m {
		day, err1 := strconv.ParseInt(d, 10, 64)
		key, err2 := base64.StdEncoding.DecodeString(v)
		if err1 == nil && err2 == nil && len(key) == 32 {
			k.keys[day] = key
		}
	}
}

// save persists the keys; k.mu must be held.
func (k *Keyring) save() {
	m := make(map[string]string, len(k.keys))
	for day, key := range k.keys {
		m[strconv.FormatInt(day, 10)] = base64.StdEncoding.EncodeToString(key)
	}
	b, _ := json.Marshal(m)
	if err := k.st.SetMeta(keyringMetaKey, string(b)); err != nil {
		slog.Warn("privacy keyring save failed", "err", err)
	}
}
