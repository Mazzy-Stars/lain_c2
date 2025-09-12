package web_ui

import (
	"fmt"
	"net/http"
)
func Cmd_html(error_str string, sessionSlice []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		//必须先登录
		_, ok := CheckUserSession(r, sessionSlice, error_str)
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
	<div class="shell-container">
		<label for='options' style='margin-right: 10px;'>Select Shell:</label>
		<select id='options' name='options' style='margin-left: 10px;'></select>
		<p id='hostname' style='margin-left: 10px; font-size: 10px;'></p>
	</div>
	<div class="terminal" id="terminal">
		<div class="input-container">
			<div class="prompt">Command></div>
			<input type="text" class="shell-input" id="input" autofocus>
		</div>
	</div>

	<script src="/lain.js"></script>
	<script>
		const shell = new lain_shell();
		const inputElement = document.getElementById('input');
		const terminal = document.getElementById('terminal');
		const inputContainer = terminal.querySelector('.input-container');
		let currentInput = inputElement;
		inputElement.addEventListener('keydown', async function (event) {
			if (event.key === 'Enter') {
				event.preventDefault();
				const command = currentInput.value.trim();
				if (command) {
					shell.get(command);
				}
			}
		});
		document.addEventListener('DOMContentLoaded', function() {
		let urlParams = new URLSearchParams(window.location.search);
		let uid = urlParams.get('uid');
		let host = urlParams.get('host');
		let hostname = document.getElementById('hostname');
		hostname.innerText = "Host:" + host;
		if (!shell.username) {
			window.location.href = "about:blank";
		}
		fetch('/user_index?op=getOs&uid=' + uid)
		.then(response => response.text())
		.then(data => {
			const optionsElement = document.getElementById('options');
			if (data === 'win') {
				optionsElement.innerHTML = "<option>Shell</option><option value='cmd'>cmd</option><option value='powershell'>powershell</option><option value='custom'>customize shell</option>";
			} else if (data === 'linux' || data === 'macos') {
				optionsElement.innerHTML = "<option>Shell</option><option value='bash'>bash</option><option value='sh'>sh</option><option value='custom'>customize shell</option>";
			} else if (data === 'android') {
				optionsElement.innerHTML = "<option>Shell</option><option value='/system/bin/bash'>/system/bin/bash</option><option value='/system/bin/sh'>/system/bin/sh</option><option value='custom'>customize shell</option>";
			}
		});
	});

	document.getElementById('options').addEventListener('change', function() {
		let selectedValue = this.value;

		if (selectedValue === 'custom') {
			// 用户选择了“自定义...”
			let customEnv = prompt("enter a shell:");

			if (customEnv) {
				// 创建一个新的 <option> 元素
				const newOption = document.createElement("option");
				newOption.value = customEnv;
				newOption.textContent = customEnv;

				// 将新的选项插入到下拉框中
				this.insertBefore(newOption, this.querySelector("option[value='custom']"));

				// 设置新的选项为选中状态
				this.value = customEnv;

				// 通知 shell 切换到自定义环境
				shell.switchVer(customEnv);
			} else {
				// 如果用户取消输入或未输入内容，重置为默认选项
				this.value = "Shell";
			}
		} else {
			// 通知 shell 切换到选定的环境
			shell.switchVer(selectedValue);
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