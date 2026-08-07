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
                <a href="#" data-target="chat">
                    <span class="icon">📟</span><span class="text">Chat</span>
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
                    <a href="#" data-target="chat">📟 chat</a>
                </div>
                <div id="server" class="hidden server-page">
                    <div id="online_teammates_mount" class="server-teammates-slot"></div>
                    <div id="server_index" class="server-grid"></div>
                    <script>
                        async function downLog() {
                            try {
                                await webSocketClient.ensureConnected();
                                await webSocketClient.downloadLog();
                            } catch (err) {
                                customLog("Download log failed: " + err.message);
                            }
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
                                '<div class="server-dialog">' +
                                    '<button class="close-x" onclick="closeStartServerDialog()" ' +
                                        'style="position:absolute;' +
                                        'right:10px;' +
                                        'top:8px;' +
                                        'width:32px;' +
                                        'height:32px;' +
                                        'padding:0;' +
                                        'border:none;' +
                                        'background:transparent;' +
                                        'font-size:28px;' +
                                        'line-height:28px;' +
                                        'color:#666;' +
                                        'cursor:pointer;">×</button>' +
                                    '<div class="server-header">' +
                                        '<h3>Start Server</h3>' +
                                    '</div>' +

                                    '<form id="serverForm" method="POST" class="server-form">' +

                                        '<input name="port" placeholder="Port" required>' +
                                        '<input name="path" placeholder="Path" required>' +

                                        '<input name="connPath" placeholder="Conn parameter">' +
                                        '<input name="msgPath" placeholder="Msg parameter">' +
                                        '<input name="switch_key" placeholder="Switch parameter">' +
                                        '<input name="encry_key" placeholder="Key parameter">' +

                                        '<input name="download" placeholder="Download parameter">' +
                                        '<input name="result" placeholder="Result parameter">' +
                                        '<input name="net" placeholder="Net parameter">' +
                                        '<input name="info" placeholder="Info parameter">' +

                                        '<input name="upload" placeholder="Upload parameter">' +
                                        '<input name="list" placeholder="List parameter">' +
                                        '<input name="remark" placeholder="Remark">' +

                                        '<select id="protocol" name="protocol">' +
                                            '<option value="">Select Protocol</option>' +
                                            '<option value="http">HTTP</option>' +
                                            '<option value="https">HTTPS</option>' +
                                            '<option value="quic">HTTP3</option>' +
                                        '</select>' +

                                        '<select id="Group_pro" name="Group_pro">' +
                                            '<option value="">Normal Version</option>' +
                                            '<option value="group_pro">Windows Enhanced Version</option>' +
                                        '</select>' +

                                        '<input name="option" placeholder="Parameter Option">' +
                                        '<input name="uid" placeholder="Parameter UID">' +
                                        '<input name="user" placeholder="Parameter User">' +
                                        '<input name="hostname" placeholder="Parameter Hostname">' +
                                        '<input name="keyPart" placeholder="Parameter keyPart">' +
                                        '<input name="filekey" placeholder="Parameter filekey">' +

                                        '<input name="response_head" placeholder=\'{"set-cookie":"a98cb4fed"}\'>' +

                                        '<label>Base64Table</label>' +

                                        '<select id="base_rounds_mode" name="base_rounds_mode" onchange="toggleBaseRoundsInput()">' +
                                            '<option value="auto">Auto Generate</option>' +
                                            '<option value="custom">Custom</option>' +
                                        '</select>' +

                                        '<input name="base_rounds" id="base_rounds_input" ' +
                                            'placeholder="Custom Base64Table (64 characters)" ' +
                                            'style="display:none;">' +

                                        '<textarea name="cert" placeholder="Cert Content"></textarea>' +

                                        '<textarea name="key" placeholder="Key Content"></textarea>' +

                                        '<div class="server-buttons">' +
                                            '<button type="button" id="submitBtn" onclick="startServer()">' +
                                                'Send' +
                                            '</button>' +
                                        '</div>' +

                                    '</form>' +
                                '</div>';
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
                        window.plugin = function(remark) {
                            if (typeof window.submitPlugin !== "function") {
                                customAlert("submitPlugin is not available");
                                return;
                            }
                            return window.submitPlugin(remark);
                        };

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
                        window.server = new lain_server();
                        const server = window.server;
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
                            async function get_conn(uid, shellname) {
                                const sent = await l_index.get(uid, shellname);
                                if (!sent) {
                                    return;
                                }
                                if (!shell_list.includes(uid)) {
                                    shell_list.push(uid);
                                }
                            }
                            function del_conn(uid) {
                                l_index.del(uid);
                            }
                        </script>
                </div>
                <div id="userIndex" class="hidden">
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
                        net_init()
                        const net = new lain_net();
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
                    </script>
                </div>
                <div id="chat" class="hidden">
                    <div class="chat">
                        <div id="chat_div" class="chat_container"></div>
                        <div class="chat_input_wrapper">
                            <button class="chat_icon_left" id="chat_file_btn">📎</button>
                            <input type="file" id="chat_file" style="display:none">
                            <input class="chat_input" type="text" id="chat_input" placeholder="team chat">
                            <button id="chat_send_btn" class="chat_icon_right">➤</button>
                        </div>
                    </div>
                    <script>
                        const app = new lain_chat();

                        // 🔹 发送按钮点击逻辑
                        document.getElementById("chat_send_btn").onclick = function () {
                            var fileInput = document.getElementById("chat_file");
                            var chatInput = document.getElementById("chat_input");

                            // 如果选择了文件，优先发送文件
                            if (fileInput.files.length > 0) {
                                var file = fileInput.files[0];

                                // 创建文件占位消息
                                var chatDiv = document.getElementById("chat_div");
                                var msg = document.createElement("div");
                                msg.className = "chat_message pending_file me";
                                msg.innerText = "📎 " + file.name + " (" + Math.round(file.size / 1024) + " KB) - Sending...";
                                chatDiv.appendChild(msg);
                                chatDiv.scrollTop = chatDiv.scrollHeight;

                                // 执行上传逻辑
                                app.sendChatFile(file, msg);
                                return;
                            }

                            // 否则发送普通文本消息
                            var text = chatInput.value.trim();
                            if (text.length === 0) return;
                            app.sendChat();
                        };

                        // 🔹 输入框回车键
                        document.getElementById("chat_input").addEventListener("keydown", function (e) {
                            if (e.key === "Enter") {
                                e.preventDefault(); // 阻止换行
                                document.getElementById("chat_send_btn").click();
                            }
                        });

                        // 🔹 打开文件选择框
                        document.getElementById("chat_file_btn").onclick = function () {
                            document.getElementById("chat_file").click();
                        };

                        // 🔹 文件选择后不立刻发送，只是缓存
                        document.getElementById("chat_file").onchange = function () {
                            var file = document.getElementById("chat_file").files[0];
                            if (!file) return;
                            var chatDiv = document.getElementById("chat_div");
                            var old = chatDiv.querySelector(".pending_file_preview");
                            if (old) old.remove();

                            var msg = document.createElement("div");
                            msg.className = "chat_message pending_file_preview me";
                            msg.innerText = "📎 " + file.name + " (" + Math.round(file.size / 1024) + " KB) - Ready to send";
                            chatDiv.appendChild(msg);

                            chatDiv.scrollTop = chatDiv.scrollHeight;
                        };
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
</body>
</html>

            `,web_title)
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, html)
			return
		}
	}
}
