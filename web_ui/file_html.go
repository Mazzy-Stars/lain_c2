package web_ui

import (
	"fmt"
	"net/http"
)
func File_html(error_str string, sessionSlice []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		//必须先登录
		_, ok := CheckUserSession(r, sessionSlice,error_str)
        if !ok {
            fmt.Fprint(w, error_str)
            return
        }
		if r.Method == http.MethodGet {
			html := `<!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta http-equiv="X-UA-Compatible" content="IE=edge">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <link rel="stylesheet" href="/lain.css">
            </head>
            <body>
            <div style="display: flex; width: 100%;">
                <div id="history" class="file-history"></div>
                <div class="filecontainer">
                    <div>
                        <div style="display: flex; align-items: center;">
                            <p id='hostname' style='margin-right: 25px;'></p>
                            <label for="splitSize">Enter the split size (each part in MB): </label>
                            <input type="number" id="splitSize" min="1" placeholder="Enter part" />
                        </div>
                    </div>
                    <div id="file" class="file-manager"></div>
                    <form id="uploadForm">
                        <input type="file" id="uploadFile" name="uploadFile" required>
                        <input class="fileinput" type="submit" class="dir-btn" value="Upload">
                    </form>
                    <div class="dir-btn" onclick="get_dir(1)">&#x21B6; ../</div>
                    <div class="dir-controls">
                        <p id="cur_dir_p"></p>
                        <input type="text" id="directoryInput">
                        <button id="moveDirButton" onclick="move_dir()">Goto folder</button>
                    </div>
                </div>
            </div>
                <script src="/lain.js"></script>
                <script>
                    let urlParams = new URLSearchParams(window.location.search);
                    let host = urlParams.get('host');
                    let hostname = document.getElementById('hostname');
                    hostname.innerText = "Host:" + host;
                    document.addEventListener("DOMContentLoaded", function () {
                    const historyDiv = document.getElementById("history");
                    const fileContainer = document.querySelector(".filecontainer");

                    // 创建拖动条
                    const dragBar = document.createElement("div");
                    dragBar.style.width = "6px";
                    dragBar.style.cursor = "ew-resize";
                    dragBar.style.background = "#ccc";
                    dragBar.style.position = "relative";
                    dragBar.style.zIndex = "10";
                    dragBar.style.height = "100%";
                    dragBar.style.flexShrink = "0";
                    dragBar.style.userSelect = "none";
                    dragBar.style.touchAction = "none";
                    dragBar.id = "dragBar";

                    // 插入拖动条
                    historyDiv.parentNode.insertBefore(dragBar, fileContainer);

                    let isDragging = false, startX, startHistoryWidth, startFileWidth;

                    function startDrag(e) {
                        isDragging = true;
                        startX = e.touches ? e.touches[0].clientX : e.clientX;
                        startHistoryWidth = historyDiv.offsetWidth;
                        startFileWidth = fileContainer.offsetWidth;
                        document.addEventListener("mousemove", dragMove);
                        document.addEventListener("mouseup", stopDrag);
                        document.addEventListener("touchmove", dragMove);
                        document.addEventListener("touchend", stopDrag);
                    }

                    function dragMove(e) {
                        if (!isDragging) return;
                        let currentX = e.touches ? e.touches[0].clientX : e.clientX;
                        let deltaX = currentX - startX;
                        let minWidth = 80;
                        let maxWidth = historyDiv.parentNode.offsetWidth - minWidth;
                        let newHistoryWidth = Math.max(minWidth, Math.min(startHistoryWidth + deltaX, maxWidth));
                        let newFileWidth = Math.max(minWidth, historyDiv.parentNode.offsetWidth - newHistoryWidth - dragBar.offsetWidth);

                        historyDiv.style.width = newHistoryWidth + "px";
                        fileContainer.style.width = newFileWidth + "px";
                        fileContainer.style.flex = "none";
                        historyDiv.style.flex = "none";
                    }

                    function stopDrag() {
                        isDragging = false;
                        document.removeEventListener("mousemove", dragMove);
                        document.removeEventListener("mouseup", stopDrag);
                        document.removeEventListener("touchmove", dragMove);
                        document.removeEventListener("touchend", stopDrag);
                    }

                    dragBar.addEventListener("mousedown", startDrag);
                    dragBar.addEventListener("touchstart", startDrag);
                });
                    const shell_file = new lain_shell();
                    document.getElementById('uploadForm').addEventListener('submit', function(event) {
                        event.preventDefault(); // 阻止表单默认提交行为
                        var fileInput = document.getElementById('uploadFile');
                        var file = fileInput.files[0];
                        var splitSizeInput = document.getElementById('splitSize');
                        var splitSize = splitSizeInput.value ? parseFloat(splitSizeInput.value) * 1024 * 1024 : 0;
                        if (file) {
                            let file_name = shell_file.shell_dir + "/" + file.name;
                            var fileSize = file.size;
                            var formData = new FormData();
                            formData.append('uploadFile', file);
                            formData.append('uid', shell_file.uid);
                            formData.append('filename',file_name);
                            formData.append('splitSize',splitSize);
                            var xhr = new XMLHttpRequest();
                            xhr.open('POST', '/user_index?op=uploadFile', true);
                            xhr.onload = function() {
                                if (xhr.status === 200) {
                                    console.log('File uploaded successfully');
                                    shell_file.loadFile(file_name,fileSize);
                                } else {
                                    alert('The file is being used');
                                }
                            };
                            xhr.send(formData);
                        } else {
                            alert("Please select a file");
                        }
                    });
                    shell_file.history_file();
                    shell_file.look_file("./");
                    function get_dir(get_switch) {
                        let cur_dir = "no";
                        shell_file.move_file(get_switch, cur_dir);
                    }
                    function move_dir(){
                        shell_file.move_dir();
                    }
                    document.addEventListener('DOMContentLoaded', function() {
                        let username = shell_file.username;
                        if (username) {
                            // document.getElementById("username").textContent = username;
                        } else {
                            window.location.href = "about:blank";
                        }
                    });
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