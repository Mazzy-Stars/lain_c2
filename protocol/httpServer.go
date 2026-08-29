package protocol

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
	"strings"
    "sync"
    "encoding/json"
    "strconv"
    "sync/atomic"
    "os"
    // quic-go
    "github.com/quic-go/quic-go"
    "github.com/quic-go/quic-go/http3"
)
var (
    serverMap = make(map[string]interface{})
    mutex     sync.Mutex
)
type Handler interface {
    Index(conn, Get_Msg,switch_key,encry_key,download,result,net,info,upload,list,option,uid,hostname,keyPart,filekey,windows_pro,port string) http.HandlerFunc
}
type Putserver interface {
    PutServer(port, path, connPath, msgPath,switch_key,encry_key,download,result,net,info,upload,list,option,protocol,remark,cert, key,uid,hostname,keyPart,filekey,windows_pro,baseRounds,resphead,username string) bool
}
type WLog interface{
    WriteLog(logStr string)
}
type ServerConfig struct {
    RespHead atomic.Value // 存 string
}
var (
    serverConfigMu sync.RWMutex
    serverConfigs  = make(map[string]*ServerConfig)
)
func writeTempCertFiles(certPEM, keyPEM string) (certPath, keyPath string, err error) {
    cf, err := os.CreateTemp("", "lain_cert_*.pem")
    if err != nil {
        return "", "", err
    }
    if _, err = cf.Write([]byte(certPEM)); err != nil {
        cf.Close()
        os.Remove(cf.Name())
        return "", "", err
    }
    cf.Close()
    kf, err := os.CreateTemp("", "lain_key_*.pem")
    if err != nil {
        os.Remove(cf.Name())
        return "", "", err
    }
    if _, err = kf.Write([]byte(keyPEM)); err != nil {
        kf.Close()
        os.Remove(cf.Name())
        os.Remove(kf.Name())
        return "", "", err
    }
    kf.Close()
    return cf.Name(), kf.Name(), nil
}
func GetOrCreateConfig(port string) *ServerConfig {
    // 先用读锁查
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
// 供 main.go 调用的更新函数
func UpdateRespHead(port, resphead string) {
    cfg := GetOrCreateConfig(port)
    cfg.RespHead.Store(resphead)
}
func Http_server(handler Handler, ServerManager Putserver, writeLog WLog,
    port, path, conn_path, GetMsg,switch_key,encry_key,download,result,net,info,upload,list,option,
    protocol,uid,hostname,keyPart,filekey,remark,certPEM, keyPEM,windows_pro,baseRounds,resphead,username string,log_word map[string]string) {
    var err error
    var returnStr string
    // 确保 path 以 "/" 开头
    if !strings.HasPrefix(path, "/") {
        path = "/" + path
    }
    cfg := GetOrCreateConfig(port)
    // 初始值写进去
    cfg.RespHead.Store(resphead)
    mux := http.NewServeMux()
    mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
        // 每次请求都从 atomic 读最新值
        currentRespHead := cfg.RespHead.Load().(string)
        
        var headers map[string]string
        var statusCode int
        if currentRespHead != "" {
            if err := json.Unmarshal([]byte(currentRespHead), &headers); err == nil {
                for k, v := range headers {
                    if strings.ToLower(k) == "status" {
                        if code, err := strconv.Atoi(v); err == nil {
                            statusCode = code
                        }
                        continue
                    }
                    w.Header().Set(k, v)
                }
            }
        }
        if statusCode != 0 {
            w.WriteHeader(statusCode)
        }
        handler.Index(
            conn_path, GetMsg, switch_key, encry_key,
            download, result, net, info, upload, list, option,
            uid, hostname, keyPart, filekey, windows_pro, port,
        ).ServeHTTP(w, r)
    })
    if protocol == "http" {
        server := &http.Server{
            Addr:         ":" + port,
            Handler:      mux,
            IdleTimeout:  0,
            ReadTimeout:  30 * time.Second,
            WriteTimeout: 30 * time.Second,
        }
        mutex.Lock()
        serverMap[port] = server
        mutex.Unlock()
        returnStr = fmt.Sprintf(log_word["http_server"],
        port, path,conn_path,GetMsg,switch_key,encry_key,download,result,net,info,upload,list,option)
        writeLog.WriteLog(returnStr)
        go func(){
			ServerManager.PutServer(port, path, conn_path, GetMsg, switch_key, encry_key, download, result, net, info, upload, list, option, protocol, remark,"null","null",uid,hostname,keyPart,filekey,windows_pro,baseRounds,resphead,username)
		}()
		err = server.ListenAndServe()
		if err != nil {
			returnStr = fmt.Sprintf(log_word["http_err"], err)
			writeLog.WriteLog(returnStr)
		}
    } else if protocol == "https" {
        var cert tls.Certificate
        var cert_g, key_g string
        if certPEM != "" && keyPEM != "" {
            cert, err = tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
            if err != nil {
                returnStr = fmt.Sprintf(log_word["cert_err"], err)
                writeLog.WriteLog(returnStr)
                return
            }
            //获取组织
            cert_g, key_g = certPEM, keyPEM
            returnStr = log_word["provided_cert"]
            writeLog.WriteLog(returnStr)
        } else {
            cert, err = tls.X509KeyPair([]byte(DefaultCert), []byte(DefaultKey))
            if err != nil {
                returnStr = fmt.Sprintf(log_word["default_cert"], err)
                writeLog.WriteLog(returnStr)
                return
            }
            //获取组织
            cert_g, key_g = "defaultCert", "defaultKey"
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
        mutex.Lock()
        serverMap[port] = server
        mutex.Unlock()
        returnStr = fmt.Sprintf(log_word["https_server"],
        port, path,conn_path,GetMsg,switch_key,encry_key,download,result,net,info,upload,list,option)
        writeLog.WriteLog(returnStr)
        go func (){
			ServerManager.PutServer(port,path,conn_path,GetMsg,switch_key,encry_key,download,result,net,info,upload,list,option,protocol,remark,cert_g,key_g,uid,hostname,keyPart,filekey,windows_pro,baseRounds,resphead,username)
		}()
		err = server.ListenAndServeTLS("", "")
		if err != nil {
			returnStr = fmt.Sprintf(log_word["https_err"], err)
			writeLog.WriteLog(returnStr)
		}
        }else if protocol == "quic" {
            var cert tls.Certificate
            var cert_g, key_g string
            if certPEM != "" && keyPEM != "" {
                cert, err = tls.X509KeyPair(
                    []byte(certPEM),
                    []byte(keyPEM),
                )
                if err != nil {
                    returnStr = fmt.Sprintf(log_word["cert_err"], err)
                    writeLog.WriteLog(returnStr)
                    return
                }
                cert_g = certPEM
                key_g = keyPEM
                returnStr = log_word["provided_cert"]
                writeLog.WriteLog(returnStr)
            } else {
                cert, err = tls.X509KeyPair(
                    []byte(DefaultCert),
                    []byte(DefaultKey),
                )
                if err != nil {
                    returnStr = fmt.Sprintf(log_word["default_cert"], err)
                    writeLog.WriteLog(returnStr)
                    return
                }
                cert_g = "defaultCert"
                key_g = "defaultKey"
            }
            tlsConfig := &tls.Config{
                MinVersion: tls.VersionTLS13,
                Certificates: []tls.Certificate{
                    cert,
                },
                NextProtos: []string{
                    "h3",
                },
            }
            server := &http3.Server{
                Addr: ":" + port,
                Handler: mux,
                TLSConfig: tlsConfig,
                QUICConfig:&quic.Config{
                    MaxIdleTimeout: 60 * time.Second,
                },
            }
            mutex.Lock()
            serverMap[port] = server
            mutex.Unlock()
            // 修正日志拼接，避免 EXTRA 输出
            returnStr = fmt.Sprintf(log_word["quic_server"],
            port, path,conn_path,GetMsg,switch_key,encry_key,download,result,net,info,upload,list,option,
            )
            writeLog.WriteLog(returnStr)
            go func(){
                ServerManager.PutServer(port,path,conn_path,GetMsg,switch_key,encry_key,download,result,net,info,upload,list,option,protocol,remark,cert_g,key_g,uid,hostname,keyPart,filekey,windows_pro,baseRounds,resphead,username)
            }()
            // 写临时证书文件并启动（避免传空路径导致底层尝试打开空路径出错）
            certFilePath, keyFilePath, werr := writeTempCertFiles(
                func() string {
                    if certPEM != "" && keyPEM != "" { return certPEM }
                    return DefaultCert
                }(),
                func() string {
                    if certPEM != "" && keyPEM != "" { return keyPEM }
                    return DefaultKey
                }(),
            )
            if werr == nil {
                err = server.ListenAndServeTLS(certFilePath, keyFilePath)
                _ = os.Remove(certFilePath)
                _ = os.Remove(keyFilePath)
            } else {
                writeLog.WriteLog(fmt.Sprintf("failed to write temp cert files: %v", werr))
                err = server.ListenAndServeTLS("", "")
            }
            if err != nil {
                returnStr = fmt.Sprintf(log_word["quic_err"], err)
                writeLog.WriteLog(returnStr)
            }
        }
}
// 关闭服务器
func StopServer(port string) {
    mutex.Lock()
    defer mutex.Unlock()
    if server, exists := serverMap[port]; exists {
        switch s := server.(type) {
        case *http.Server:
            s.Close()
        case *http3.Server:
            s.Close()
        default:
            // 未知类型
        }
        delete(serverMap, port)
    }
}
