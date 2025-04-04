package protocol

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
	"strings"
	"mime/multipart"
    "sync"
)
var (
    serverMap = make(map[string]*http.Server)
    mutex     sync.Mutex
)
type Handler interface {
    Index(conn, Get_Msg string) http.HandlerFunc
}
type Putserver interface {
    PutServer(port, path, connPath, msgPath, protocol,username,remark string, certFile, keyFile multipart.File, clients int) bool
}
type WLog interface{
    WriteLog(logStr string)
}
func Http_server(handler Handler, ServerManager Putserver, writeLog WLog, port, path, conn_path, GetMsg, protocol, username,remark, defaultCert, defaultKey string, certFile, keyFile multipart.File) {
    var err error
    var return_str string

    // 确保 path 以 "/" 开头
    if !strings.HasPrefix(path, "/") {
        path = "/" + path
    }

    mux := http.NewServeMux()
    mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Connection", "keep-alive")
        handler.Index(conn_path, GetMsg).ServeHTTP(w, r)
    })
    if protocol == "http" {
        server := &http.Server{
            Addr:         ":" + port,
            Handler:      mux,
            IdleTimeout:  0,
            ReadTimeout:  30 * time.Second,
            WriteTimeout: 30 * time.Second,
        }

        serverMap[port] = server

        current := time.Now()
        formattedTime := current.Format("2006.01.02 15:04")
        return_str = fmt.Sprintf("%v [*] Start HTTP server successful, access address :%s%s\n", formattedTime, port, path)
        writeLog.WriteLog(return_str)
        ServerManager.PutServer(port, path, conn_path, GetMsg, protocol, username,remark, certFile, keyFile, 0)
        err = server.ListenAndServe()
        if err != nil {
            return_str = fmt.Sprintf("FAIL TO START HTTP SERVER: %v\n", err)
            writeLog.WriteLog(return_str)
        }
    } else if protocol == "https" {
        var cert tls.Certificate
        var certBytes, keyBytes []byte

        // 检查是否提供了 certFile 和 keyFile
        if certFile != nil && keyFile != nil {
            certBytes, err = loadCertificate(certFile)
            if err != nil {
                return_str = fmt.Sprintf("[*] Failed to load provided certificate: %v\n", err)
                writeLog.WriteLog(return_str)
            }
            keyBytes, err = loadKey(keyFile)
            if err != nil {
                return_str = fmt.Sprintf("[*] Failed to load provided key: %v\n", err)
                writeLog.WriteLog(return_str)
            }
        } else {
            // 使用默认证书
            certBytes = []byte(defaultCert)
            keyBytes = []byte(defaultKey)
            return_str = "[*] Using default certificate and key\n"
            writeLog.WriteLog(return_str)
            ServerManager.PutServer(port, path, conn_path, GetMsg, protocol,username,remark, nil, nil, 0)
        }

        // 创建临时文件存储证书和私钥
        certPath, err := writeTempFile(certBytes)
        if err != nil {
            return_str = fmt.Sprintf("[*] Failed to write certificate to temp file: %v\n", err)
            writeLog.WriteLog(return_str)
        }
        keyPath, err := writeTempFile(keyBytes)
        if err != nil {
            return_str = fmt.Sprintf("[*] Failed to write key to temp file: %v\n", err)
            writeLog.WriteLog(return_str)
        }

        cert, err = tls.LoadX509KeyPair(certPath, keyPath)
        if err != nil {
            return_str = fmt.Sprintf("[*] Failed to load certificate from file: %v\n", err)
            writeLog.WriteLog(return_str)
        }

        tlsConfig := &tls.Config{
            MinVersion:         tls.VersionTLS12,
            GetCertificate:     func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil },
            ClientAuth:         tls.NoClientCert,
            InsecureSkipVerify: true,
        }

        server := &http.Server{
            Addr:         ":" + port,
            Handler:      mux,
            IdleTimeout:  0,
            ReadTimeout:  30 * time.Second,
            WriteTimeout: 30 * time.Second,
            TLSConfig:    tlsConfig,
        }

        serverMap[port] = server

        current := time.Now()
        formattedTime := current.Format("2006.01.02 15:04")
        return_str = fmt.Sprintf("%v [*] Start HTTPS server successful, access address :%s%s\n", formattedTime, port, path)
        writeLog.WriteLog(return_str)

        ServerManager.PutServer(port, path, conn_path, GetMsg, protocol, username,remark, certFile, keyFile, 0)
        err = server.ListenAndServeTLS(certPath, keyPath)
        if err != nil {
            return_str = fmt.Sprintf("FAIL TO START HTTPS SERVER: %v\n", err)
            writeLog.WriteLog(return_str)
        }
    }
}
func StopServer(port string) {
    mutex.Lock()
    defer mutex.Unlock()
    if server, exists := serverMap[port]; exists {
        server.Close()
        delete(serverMap, port)
    }
}


// 将证书文件流写入临时文件
func writeTempFile(fileBytes []byte) (string, error) {
	tempFile, err := os.CreateTemp("", "cert_*.pem")
	if err != nil {
		return "", err
	}
	defer tempFile.Close()

	_, err = tempFile.Write(fileBytes)
	if err != nil {
		return "", err
	}

	return tempFile.Name(), nil
}

// 从证书文件流加载证书
func loadCertificate(certFile io.Reader) ([]byte, error) {
	certBytes, err := io.ReadAll(certFile)
	if err != nil {
		return nil, err
	}
	return certBytes, nil
}

// 从密钥文件流加载密钥
func loadKey(keyFile io.Reader) ([]byte, error) {
	keyBytes, err := io.ReadAll(keyFile)
	if err != nil {
		return nil, err
	}
	return keyBytes, nil
}
