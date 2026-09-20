package protocol

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

var (
	serverMap = make(map[string]interface{})
	mutex     sync.Mutex
)

type Handler interface {
	Index(
		conn,
		Get_Msg,
		switch_key,
		download,
		result,
		net,
		info,
		upload,
		list,
		option,
		uid,
		hostname,
		keyPart,
		filekey,
		windows_pro,
		port string,
	) http.HandlerFunc
}

type Putserver interface {
	PutServer(
		port,
		path,
		connPath,
		msgPath,
		switch_key,
		download,
		result,
		net,
		info,
		upload,
		list,
		option,
		protocol,
		remark,
		cert,
		key,
		uid,
		hostname,
		keyPart,
		filekey,
		windows_pro,
		baseRounds,
		resphead,
		username string,
	) bool
}

type WLog interface {
	WriteLog(logStr string)
}

type ServerConfig struct {
	RespHead atomic.Value
}

type serverHandle struct {
	closeOnce     sync.Once
	closeErr      error
	closeFn       func() error
	stopRequested bool
	stoppedOnce   sync.Once
	onStopped     func()
}

func (h *serverHandle) Close() error {
	if h == nil {
		return nil
	}

	h.closeOnce.Do(func() {
		if h.closeFn != nil {
			h.closeErr = h.closeFn()
		}
	})
	return h.closeErr
}

func (h *serverHandle) runStopped() {
	if h == nil || h.onStopped == nil {
		return
	}
	h.stoppedOnce.Do(h.onStopped)
}

var (
	serverConfigMu sync.RWMutex
	serverConfigs  = make(map[string]*ServerConfig)
)

func logf(writeLog WLog, format string, args ...interface{}) {
	if writeLog != nil {
		writeLog.WriteLog(fmt.Sprintf(format, args...))
	}
}

func isClosedError(err error) bool {
	return err != nil &&
		(errors.Is(err, http.ErrServerClosed) ||
			errors.Is(err, net.ErrClosed) ||
			errors.Is(err, quic.ErrServerClosed))
}

func closeErrors(errs ...error) error {
	filtered := make([]error, 0, len(errs))
	for _, err := range errs {
		if err != nil && !isClosedError(err) {
			filtered = append(filtered, err)
		}
	}
	return errors.Join(filtered...)
}

func unregisterServer(port string, server interface{}) bool {
	if server == nil {
		return false
	}

	mutex.Lock()
	current, exists := serverMap[port]
	if !exists || current != server {
		mutex.Unlock()
		return false
	}

	if handle, ok := server.(*serverHandle); ok && handle.stopRequested {
		mutex.Unlock()
		return true
	}
	handle, _ := server.(*serverHandle)
	mutex.Unlock()

	if handle != nil {
		handle.runStopped()
	}

	mutex.Lock()
	if current, stillExists := serverMap[port]; stillExists && current == server {
		delete(serverMap, port)
	}
	mutex.Unlock()
	return true
}
func startRegisteredServerLocked(
	port string,
	handle *serverHandle,
	serveFn func() error,
	commitFn func() error,
	onServeError func(error),
	onStopped func(),
) error {
	if handle == nil || serveFn == nil {
		return errors.New("invalid server startup state")
	}

	if _, exists := serverMap[port]; exists {
		return fmt.Errorf("server already exists on port %s", port)
	}

	serverMap[port] = handle
	handle.onStopped = onStopped

	if commitFn != nil {
		if err := commitFn(); err != nil {
			delete(serverMap, port)
			_ = handle.Close()
			return err
		}
	}

	go func() {
		err := serveFn()
		if err != nil && !isClosedError(err) && onServeError != nil {
			onServeError(err)
		}

		_ = handle.Close()
		unregisterServer(port, handle)
	}()

	return nil
}

func GetOrCreateConfig(port string) *ServerConfig {
	serverConfigMu.RLock()
	if cfg, ok := serverConfigs[port]; ok {
		serverConfigMu.RUnlock()
		return cfg
	}
	serverConfigMu.RUnlock()

	serverConfigMu.Lock()
	defer serverConfigMu.Unlock()

	if cfg, ok := serverConfigs[port]; ok {
		return cfg
	}

	cfg := &ServerConfig{}
	cfg.RespHead.Store("")
	serverConfigs[port] = cfg
	return cfg
}

func UpdateRespHead(port, resphead string) {
	cfg := GetOrCreateConfig(port)
	cfg.RespHead.Store(resphead)
}

func Http_server(
	handler Handler,
	ServerManager Putserver,
	writeLog WLog,
	port,
	path,
	connPath,
	getMsg,
	switchKey,
	download,
	result,
	netPath,
	info,
	upload,
	list,
	option,
	protocolName,
	uid,
	hostname,
	keyPart,
	filekey,
	remark,
	certPEM,
	keyPEM,
	windowsPro,
	baseRounds,
	resphead,
	username string,
	logWord map[string]string,
	onReady func(),
	onStopped func(),
) error {
	if handler == nil {
		return errors.New("nil request handler")
	}
	if ServerManager == nil {
		return errors.New("nil server manager")
	}
	if port == "" {
		return errors.New("empty server port")
	}
	if path == "" {
		return errors.New("empty server path")
	}

	switch protocolName {
	case "http", "https", "quic":
	default:
		return fmt.Errorf("unsupported protocol %q", protocolName)
	}

	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	cfg := GetOrCreateConfig(port)

	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		currentRespHead, _ := cfg.RespHead.Load().(string)

		var headers map[string]string
		var statusCode int
		if currentRespHead != "" {
			if err := json.Unmarshal([]byte(currentRespHead), &headers); err == nil {
				for key, value := range headers {
					if strings.EqualFold(key, "status") {
						if code, err := strconv.Atoi(value); err == nil {
							statusCode = code
						}
						continue
					}
					w.Header().Set(key, value)
				}
			}
		}
		if statusCode != 0 {
			w.WriteHeader(statusCode)
		}

		handler.Index(
			connPath,
			getMsg,
			switchKey,
			download,
			result,
			netPath,
			info,
			upload,
			list,
			option,
			uid,
			hostname,
			keyPart,
			filekey,
			windowsPro,
			port,
		).ServeHTTP(w, r)
	})

	commitServer := func(certPath, keyPath string) error {
		if ok := ServerManager.PutServer(
			port,
			path,
			connPath,
			getMsg,
			switchKey,
			download,
			result,
			netPath,
			info,
			upload,
			list,
			option,
			protocolName,
			remark,
			certPath,
			keyPath,
			uid,
			hostname,
			keyPart,
			filekey,
			windowsPro,
			baseRounds,
			resphead,
			username,
		); !ok {
			return fmt.Errorf("failed to save server metadata on port %s", port)
		}

		if onReady != nil {
			onReady()
		}
		return nil
	}

	mutex.Lock()
	defer mutex.Unlock()

	if _, exists := serverMap[port]; exists {
		return fmt.Errorf("server already exists on port %s", port)
	}

	switch protocolName {
	case "http":
		server := &http.Server{
			Addr:         ":" + port,
			Handler:      mux,
			IdleTimeout:  0,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		}

		listener, err := net.Listen("tcp", server.Addr)
		if err != nil {
			logf(writeLog, logWord["http_err"], err)
			return err
		}
		cfg.RespHead.Store(resphead)

		handle := &serverHandle{
			closeFn: func() error {
				return closeErrors(server.Close(), listener.Close())
			},
		}
		if err := startRegisteredServerLocked(
			port,
			handle,
			func() error {
				return server.Serve(listener)
			},
			func() error {
				return commitServer("null", "null")
			},
			func(err error) {
				logf(writeLog, logWord["http_err"], err)
			},
			onStopped,
		); err != nil {
			_ = handle.Close()
			logf(writeLog, logWord["http_err"], err)
			return err
		}

		logf(
			writeLog,
			logWord["http_server"],
			port,
			path,
			connPath,
			getMsg,
			switchKey,
			download,
			result,
			netPath,
			info,
			upload,
			list,
			option,
		)
		return nil

	case "https":
		cert, certLabel, keyLabel, err := loadCertificate(
			certPEM,
			keyPEM,
			func(port string, err error) {
				logf(writeLog, logWord["cert_err"], port, err)
			},
			func(port string) {
				logf(writeLog, logWord["provided_cert"], port)
			},
			func(port string, err error) {
				logf(writeLog, logWord["default_cert"], port, err)
			},
			port,
		)
		if err != nil {
			return err
		}

		tlsConfig := &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.NoClientCert,
		}
		server := &http.Server{
			Addr:         ":" + port,
			Handler:      mux,
			IdleTimeout:  0,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			TLSConfig:    tlsConfig,
		}

		listener, err := net.Listen("tcp", server.Addr)
		if err != nil {
			logf(writeLog, logWord["https_err"], err)
			return err
		}
		tlsListener := tls.NewListener(listener, tlsConfig)
		cfg.RespHead.Store(resphead)

		handle := &serverHandle{
			closeFn: func() error {
				return closeErrors(server.Close(), tlsListener.Close())
			},
		}
		if err := startRegisteredServerLocked(
			port,
			handle,
			func() error {
				return server.Serve(tlsListener)
			},
			func() error {
				return commitServer(certLabel, keyLabel)
			},
			func(err error) {
				logf(writeLog, logWord["https_err"], err)
			},
			onStopped,
		); err != nil {
			_ = handle.Close()
			logf(writeLog, logWord["https_err"], err)
			return err
		}

		logf(
			writeLog,
			logWord["https_server"],
			port,
			path,
			connPath,
			getMsg,
			switchKey,
			download,
			result,
			netPath,
			info,
			upload,
			list,
			option,
		)
		return nil

	case "quic":
		cert, certLabel, keyLabel, err := loadCertificate(
			certPEM,
			keyPEM,
			func(port string, err error) {
				logf(writeLog, logWord["cert_err"], port, err)
			},
			func(port string) {
				logf(writeLog, logWord["provided_cert"], port)
			},
			func(port string, err error) {
				logf(writeLog, logWord["default_cert"], port, err)
			},
			port,
		)
		if err != nil {
			return err
		}

		tlsConfig := http3.ConfigureTLSConfig(&tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cert},
		})
		quicConfig := &quic.Config{
			MaxIdleTimeout: 60 * time.Second,
		}
		server := &http3.Server{
			Addr:       ":" + port,
			Handler:    mux,
			TLSConfig:  tlsConfig,
			QUICConfig: quicConfig,
		}

		listener, err := quic.ListenAddr(server.Addr, tlsConfig, quicConfig)
		if err != nil {
			logf(writeLog, logWord["quic_err"], err)
			return err
		}
		cfg.RespHead.Store(resphead)

		handle := &serverHandle{
			closeFn: func() error {
				return closeErrors(listener.Close(), server.Close())
			},
		}
		if err := startRegisteredServerLocked(
			port,
			handle,
			func() error {
				return server.ServeListener(listener)
			},
			func() error {
				return commitServer(certLabel, keyLabel)
			},
			func(err error) {
				logf(writeLog, logWord["quic_err"], err)
			},
			onStopped,
		); err != nil {
			_ = handle.Close()
			logf(writeLog, logWord["quic_err"], err)
			return err
		}

		logf(
			writeLog,
			logWord["quic_server"],
			port,
			path,
			connPath,
			getMsg,
			switchKey,
			download,
			result,
			netPath,
			info,
			upload,
			list,
			option,
		)
		return nil
	}

	return fmt.Errorf("unsupported protocol %q", protocolName)
}

func loadCertificate(
	certPEM,
	keyPEM string,
	onProvidedError func(string, error),
	onProvided func(string),
	onDefaultError func(string, error),
	port string,
) (tls.Certificate, string, string, error) {
	if certPEM != "" && keyPEM != "" {
		cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
		if err != nil {
			if onProvidedError != nil {
				onProvidedError(port, err)
			}
			return tls.Certificate{}, "", "", err
		}
		if onProvided != nil {
			onProvided(port)
		}
		return cert, certPEM, keyPEM, nil
	}

	cert, err := tls.X509KeyPair([]byte(DefaultCert), []byte(DefaultKey))
	if err != nil {
		if onDefaultError != nil {
			onDefaultError(port, err)
		}
		return tls.Certificate{}, "", "", err
	}
	return cert, "defaultCert", "defaultKey", nil
}

func StopServer(port string) {
	mutex.Lock()
	server, exists := serverMap[port]
	if handle, ok := server.(*serverHandle); ok {
		handle.stopRequested = true
	}
	mutex.Unlock()

	if !exists {
		return
	}

	if closer, ok := server.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
	var stoppedHandle *serverHandle
	mutex.Lock()
	if current, stillExists := serverMap[port]; stillExists && current == server {
		stoppedHandle, _ = server.(*serverHandle)
	}
	mutex.Unlock()

	if stoppedHandle != nil {
		stoppedHandle.runStopped()
	}

	mutex.Lock()
	if current, stillExists := serverMap[port]; stillExists && current == server {
		delete(serverMap, port)
	}
	mutex.Unlock()
}
