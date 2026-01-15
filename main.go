package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"os/signal"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
	"syscall"
)

const (
	dataDir        = ".bos_db"
	sessionTimeout = 15 * time.Minute
	maxRequestSize = 1 << 20
	opTimeout      = 30 * time.Second
	keySaltSize    = 32
	masterKeySize  = 32
	sessionKeySize = 32
	aesKeySize     = 32
	aesNonceSize   = 12
)

type User struct {
	Hash    []byte
	Salt    []byte
	Readers []string
	Writers []string
}

type Session struct {
	User    string
	Created time.Time
}

type DB struct {
	masterKey    []byte
	keySalt      []byte
	users        map[string]*User
	sessions     map[string]*Session
	dataDir      string
	sessionsLock sync.RWMutex
	usersLock    sync.RWMutex
}

var (
	db      *DB
	tlsCert tls.Certificate
)

func initCrypto() error {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return err
	}

	certPath := filepath.Join(dataDir, "tls.crt")
	keyPath := filepath.Join(dataDir, "tls.key")
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		
		notBefore := time.Now()
		notAfter := notBefore.Add(365 * 24 * time.Hour)
		
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			return err
		}
		
		template := x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				Organization: []string{"BoS DB"},
			},
			NotBefore: notBefore,
			NotAfter:  notAfter,
			KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
			},
			BasicConstraintsValid: true,
			IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		}
		
		derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
		if err != nil {
			return err
		}
		
		certOut, err := os.Create(certPath)
		if err != nil {
			return err
		}
		pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
		certOut.Close()
		
		keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		pemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}
		pem.Encode(keyOut, pemBlock)
		keyOut.Close()
	}
	var err error
	tlsCert, err = tls.LoadX509KeyPair(certPath, keyPath)
	return err
}

func (db *DB) initMasterKey() error {
	keyPath := filepath.Join(db.dataDir, "master.key")
	saltPath := filepath.Join(db.dataDir, "key_salt.bin")

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		salt := make([]byte, keySaltSize)
		if _, err := rand.Read(salt); err != nil {
			return err
		}
		
		adminPass := make([]byte, 32)
		if _, err := rand.Read(adminPass); err != nil {
			return err
		}
		
		masterKey, err := scrypt.Key(adminPass, salt, 32768, 8, 1, masterKeySize)
		if err != nil {
			return err
		}
		
		if err := os.WriteFile(keyPath, masterKey, 0600); err != nil {
			return err
		}
		if err := os.WriteFile(saltPath, salt, 0600); err != nil {
			return err
		}
		
		adminSalt := make([]byte, 16)
		rand.Read(adminSalt)
		adminHash := argon2.IDKey(adminPass, adminSalt, 1, 64*1024, 4, 32)
		
		db.masterKey = masterKey
		db.keySalt = salt

		db.users = map[string]*User{
			"admin": {
				Hash: adminHash,
				Salt: adminSalt,
			},
		}
		
		if err := db.saveUsers(); err != nil {
			return fmt.Errorf("failed to save initial users: %w", err)
		}
		
		log.Printf("ADMIN CREDENTIALS (save this!): admin:%s", base64.StdEncoding.EncodeToString(adminPass))
	} else {
		masterKey, err := os.ReadFile(keyPath)
		if err != nil {
			return err
		}
		salt, err := os.ReadFile(saltPath)
		if err != nil {
			return err
		}
		db.masterKey = masterKey
		db.keySalt = salt
		
		if err := db.loadUsers(); err != nil {
			log.Printf("Warning: failed to load users: %v. Starting with empty user database.", err)
			db.users = make(map[string]*User)
		}
	}
	
	if err := os.MkdirAll(filepath.Join(db.dataDir, "data"), 0700); err != nil {
		return err
	}
	
	return nil
}

func (db *DB) hashKey(key string) string {
	h := sha512.New()
	h.Write(db.keySalt)
	h.Write([]byte(key))
	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}

func (db *DB) encryptLayer(plaintext []byte, key []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

func (db *DB) decryptLayer(data []byte, key []byte, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	
	return gcm.Open(nil, nonce, data, nil)
}

func (db *DB) encryptValue(value []byte) ([]byte, error) {
	current := value
	
	for i := 0; i < 3; i++ {
		layerKey := make([]byte, aesKeySize)
		if _, err := rand.Read(layerKey); err != nil {
			return nil, err
		}
		
		encrypted, nonce, err := db.encryptLayer(current, layerKey)
		if err != nil {
			return nil, err
		}
		
		metadata := append(layerKey, nonce...)
		encryptedMeta, metaNonce, err := db.encryptLayer(metadata, db.masterKey)
		if err != nil {
			return nil, err
		}
		
		prefix := make([]byte, 12+len(encryptedMeta))
		copy(prefix[:12], metaNonce)
		copy(prefix[12:], encryptedMeta)
		
		current = append(prefix, encrypted...)
	}
	
	return current, nil
}

func (db *DB) decryptValue(data []byte) ([]byte, error) {
	current := data

	for i := 0; i < 3; i++ {
		if len(current) < 12 {
			return nil, errors.New("corrupted data: too short for nonce")
		}

		metaNonce := current[:12]
		rest := current[12:]

		metaPlaintextSize := aesKeySize + aesNonceSize
		block, err := aes.NewCipher(db.masterKey)
		if err != nil {
			return nil, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		encryptedMetaSize := metaPlaintextSize + gcm.Overhead()

		if len(rest) < encryptedMetaSize {
			return nil, fmt.Errorf("corrupted data: insufficient metadata size (have %d, need %d)", len(rest), encryptedMetaSize)
		}

		encryptedMeta := rest[:encryptedMetaSize]
		ciphertext := rest[encryptedMetaSize:]

		metadata, err := db.decryptLayer(encryptedMeta, db.masterKey, metaNonce)
		if err != nil {
			return nil, fmt.Errorf("metadata decryption failed at level %d: %w", i, err)
		}

		if len(metadata) < aesKeySize+aesNonceSize {
			return nil, fmt.Errorf("invalid metadata length at level %d: got %d, need %d", i, len(metadata), aesKeySize+aesNonceSize)
		}

		layerKey := metadata[:aesKeySize]
		nonce := metadata[aesKeySize : aesKeySize+aesNonceSize]

		decrypted, err := db.decryptLayer(ciphertext, layerKey, nonce)
		if err != nil {
			return nil, fmt.Errorf("layer decryption failed at level %d: %w", i, err)
		}

		current = decrypted
	}

	return current, nil
}

func (db *DB) authenticate(user, pass string) (string, error) {
	db.usersLock.RLock()
	u, exists := db.users[user]
	db.usersLock.RUnlock()
	if !exists {
		time.Sleep(100 * time.Millisecond)
		return "", errors.New("invalid credentials")
	}
	
	decodedPass, err := base64.StdEncoding.DecodeString(pass)
    if err != nil {
        return "", errors.New("invalid admin password format")
    }
    hash := argon2.IDKey(decodedPass, u.Salt, 1, 64*1024, 4, 32)
	if subtle.ConstantTimeCompare(hash, u.Hash) != 1 {
		time.Sleep(100 * time.Millisecond)
		return "", errors.New("invalid credentials")
	}
	
	sessionToken := make([]byte, sessionKeySize)
	if _, err := rand.Read(sessionToken); err != nil {
		return "", err
	}
	token := base64.URLEncoding.EncodeToString(sessionToken)
	
	db.sessionsLock.Lock()
	db.sessions[token] = &Session{
		User:    user,
		Created: time.Now(),
	}
	db.sessionsLock.Unlock()
	return token, nil
}

func (db *DB) validateSession(token string) (string, error) {
	db.sessionsLock.RLock()
	defer db.sessionsLock.RUnlock()
	session, exists := db.sessions[token]
	if !exists {
		return "", errors.New("invalid session")
	}
	if time.Since(session.Created) > sessionTimeout {
		return "", errors.New("session expired")
	}
	return session.User, nil
}

func (db *DB) saveUsers() error {
	db.usersLock.RLock()
	defer db.usersLock.RUnlock()
	
	usersData, err := json.Marshal(db.users)
	if err != nil {
		return err
	}
	
	encrypted, err := db.encryptValue(usersData)
	if err != nil {
		return err
	}
	
	return os.WriteFile(filepath.Join(db.dataDir, "users.enc"), encrypted, 0600)
}

func (db *DB) loadUsers() error {
	data, err := os.ReadFile(filepath.Join(db.dataDir, "users.enc"))
	if err != nil {
		if os.IsNotExist(err) {
			db.users = make(map[string]*User)
			return nil
		}
		return err
	}
	
	decrypted, err := db.decryptValue(data)
	if err != nil {
		return fmt.Errorf("failed to decrypt users file: %w", err)
	}
	
	users := make(map[string]*User)
	if err := json.Unmarshal(decrypted, &users); err != nil {
		return fmt.Errorf("failed to unmarshal users: %w", err)
	}
	
	db.usersLock.Lock()
	db.users = users
	db.usersLock.Unlock()
	return nil
}

func (db *DB) handleConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(opTimeout))
	
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, maxRequestSize), maxRequestSize)
	
	var currentUser string
	
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) > maxRequestSize {
			conn.Write([]byte("ERROR request too large\n"))
			return
		}
		
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		cmd := strings.ToUpper(parts[0])
		switch cmd {
		case "AUTH":
			if len(parts) != 3 {
				conn.Write([]byte("ERROR invalid AUTH format\n"))
				continue
			}
			token, err := db.authenticate(parts[1], parts[2])
			if err != nil {
				conn.Write([]byte("ERROR authentication failed\n"))
				continue
			}
			currentUser = parts[1]
			conn.Write([]byte("OK " + token + "\n"))
		
		case "SET", "GET", "CREATE_USER":
			if len(parts) < 2 {
				conn.Write([]byte("ERROR missing token\n"))
				continue
			}
			user, err := db.validateSession(parts[1])
			if err != nil {
				conn.Write([]byte("ERROR " + err.Error() + "\n"))
				continue
			}
			currentUser = user
			
			switch cmd {
			case "SET":
				if len(parts) < 4 {
					conn.Write([]byte("ERROR invalid SET format\n"))
					continue
				}
				key := db.hashKey(parts[2])
				value := []byte(strings.Join(parts[3:], " "))
				encrypted, err := db.encryptValue(value)
				if err != nil {
					conn.Write([]byte("ERROR encryption failed\n"))
					continue
				}
				if err := os.WriteFile(filepath.Join(db.dataDir, "data", key), encrypted, 0600); err != nil {
					conn.Write([]byte("ERROR write failed\n"))
					continue
				}
				conn.Write([]byte("OK\n"))
			
			case "GET":
				if len(parts) != 3 {
					conn.Write([]byte("ERROR invalid GET format\n"))
					continue
				}
				key := db.hashKey(parts[2])
				data, err := os.ReadFile(filepath.Join(db.dataDir, "data", key))
				if err != nil {
					conn.Write([]byte("ERROR key not found\n"))
					continue
				}
				value, err := db.decryptValue(data)
				if err != nil {
					conn.Write([]byte("ERROR decryption failed\n"))
					continue
				}
				conn.Write(append(value, '\n'))
			
			case "CREATE_USER":
				if currentUser != "admin" {
					conn.Write([]byte("ERROR permission denied\n"))
					continue
				}
				if len(parts) != 4 {
					conn.Write([]byte("ERROR invalid CREATE_USER format\n"))
					continue
				}
				
				db.usersLock.Lock()
				if _, exists := db.users[parts[2]]; exists {
					db.usersLock.Unlock()
					conn.Write([]byte("ERROR user already exists\n"))
					continue
				}
				
				salt := make([]byte, 16)
				rand.Read(salt)
				hash := argon2.IDKey([]byte(parts[3]), salt, 1, 64*1024, 4, 32)
				
				db.users[parts[2]] = &User{
					Hash: hash,
					Salt: salt,
				}
				db.usersLock.Unlock()
				
				if err := db.saveUsers(); err != nil {
					conn.Write([]byte("ERROR failed to save user\n"))
					continue
				}
				conn.Write([]byte("OK\n"))
			}
		
		default:
			conn.Write([]byte("ERROR unknown command\n"))
		}
		
		conn.SetDeadline(time.Now().Add(opTimeout))
	}
}

func sessionCleanup() {
	for {
		time.Sleep(5 * time.Minute)
		now := time.Now()
		db.sessionsLock.Lock()
		for token, session := range db.sessions {
			if now.Sub(session.Created) > sessionTimeout {
				delete(db.sessions, token)
			}
		}
		db.sessionsLock.Unlock()
	}
}

func wipeSecrets() {
	if db != nil {
		if db.masterKey != nil {
			for i := range db.masterKey {
				db.masterKey[i] = 0
			}
		}
		if db.keySalt != nil {
			for i := range db.keySalt {
				db.keySalt[i] = 0
			}
		}
	}
}

func main() {
	port := flag.String("port", "6379", "server port")
	flag.Parse()
	
	if err := initCrypto(); err != nil {
		log.Fatal("crypto init failed:", err)
	}
	
	db = &DB{
		sessions: make(map[string]*Session),
		dataDir:  dataDir,
	}
	
	if err := db.initMasterKey(); err != nil {
		log.Fatal("master key init failed:", err)
	}
	
	go sessionCleanup()
	
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
		},
	}
	
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	
	listener, err := tls.Listen("tcp", ":"+*port, tlsConfig)
	if err != nil {
		log.Fatal("listen failed:", err)
	}
	defer listener.Close()
	log.Printf("Server started on :%s with TLS 1.3", *port)
	
	go func() {
		<-ctx.Done()
		log.Println("Shutting down gracefully...")
		
		if err := db.saveUsers(); err != nil {
			log.Printf("Warning: failed to save users on shutdown: %v", err)
		}
		
		listener.Close()
		wipeSecrets()
		os.Exit(0)
	}()
	
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Println("accept error:", err)
				continue
			}
		}
		conn.SetReadDeadline(time.Now().Add(opTimeout))
		conn.SetWriteDeadline(time.Now().Add(opTimeout))
		go db.handleConn(conn)
	}
}