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
)
var (
    serverMap = make(map[string]*http.Server)
    mutex     sync.Mutex
)
type Handler interface {
    Index(conn, Get_Msg,switch_key,encry_key,download,result,net,info,upload,list,option,uid,username,hostname,keyPart,filekey,windows_pro,port string) http.HandlerFunc
}
type Putserver interface {
    PutServer(port, path, connPath, msgPath,switch_key,encry_key,download,result,net,info,upload,list,option,protocol,username,remark,cert, key,uid,hostname,keyPart,filekey,windows_pro,baseRounds,resphead string) bool
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
    protocol,uid,user,hostname,keyPart,filekey,remark,certPEM, keyPEM,windows_pro,baseRounds,resphead string,log_word map[string]string) {
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
        w.Header().Set("Connection", "keep-alive")
        
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
            uid, user, hostname, keyPart, filekey, windows_pro, port,
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
			ServerManager.PutServer(port, path, conn_path, GetMsg, switch_key, encry_key, download, result, net, info, upload, list, option, protocol, user, remark,"null","null",uid,hostname,keyPart,filekey,windows_pro,baseRounds,resphead)
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
            returnStr = log_word["provided_cert"]
            writeLog.WriteLog(returnStr)
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
			ServerManager.PutServer(port,path,conn_path,GetMsg,switch_key,encry_key,download,result,net,info,upload,list,option,protocol,user,remark,cert_g,key_g,uid,hostname,keyPart,filekey,windows_pro,baseRounds,resphead)
		}()
		err = server.ListenAndServeTLS("", "")
		if err != nil {
			returnStr = fmt.Sprintf(log_word["https_err"], err)
			writeLog.WriteLog(returnStr)
		}
    }
}
// 关闭服务器
func StopServer(port string) {
	mutex.Lock()
	defer mutex.Unlock()
	if server, exists := serverMap[port]; exists {
		server.Close()
		delete(serverMap, port)
	}
}
