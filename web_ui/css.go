
package web_ui
import (
	"fmt"
	"io/ioutil"
	"net/http"
)
func Css(css_file,error_str string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			var cssContent string
			if css_file != "" {
				content, err := ioutil.ReadFile(css_file)
				if err != nil {
                    w.WriteHeader(http.StatusNotFound)
					fmt.Fprint(w, error_str)
					return
				}
				cssContent = string(content)
			} else {
				cssContent = `
				html, body {
    margin: 0;
    height: 100%;
    font-family: Arial, sans-serif;
    display: flex;
    flex-direction: column;
}
.server_index {
    display: flex;
    flex-direction: column;
    height: 100vh;
    /* 让内容和日志区撑满整个可视区 */
}
.container {
    display: flex; /* 使用flexbox布局 */
    width: 100vw; /* 父容器宽度为视口宽度 */
    height: 100vh; /* 父容器高度为视口高度 */
}
.startBtn {
    background-color:rgb(0, 225, 255);
    color: white;
    font-size: 12px;
    position: absolute;
    top:auto;
    left: 186px;
    border: none;
    padding: 10px 20px;
    border-radius: 5px;
    cursor: pointer;
    z-index: 1000;
}
.startBtn:hover {
    background-color:rgb(48, 53, 102);
} 
.clearMemoryBtn {
    background-color:rgb(0, 225, 255);
    color: white;
    font-size: 12px;
    /*靠在最左侧*/
    position: absolute;
    top:auto;
    left: 70px;
    border: none;
    padding: 10px 20px;
    border-radius: 5px;
    cursor: pointer;
}
.clearMemoryBtn:hover {
    background-color:rgb(48, 53, 102);
}       
.logBtn{
    background-color:rgb(0, 225, 255);
    color: white;
    font-size: 12px;
    position: absolute;
    top:auto;
    left: 254px;
    border: none;
    padding: 10px 20px;
    border-radius: 5px;
    cursor: pointer;
}        
.logBtn:hover {
    background-color:rgb(48, 53, 102);
}
.sidebar {
    width: 180px;
    background-color: rgb(194, 226, 226);
    color: #000;
    height: 100%;
    padding: 20px 10px;
    box-sizing: border-box;
    box-shadow: 2px 0 10px rgba(0, 0, 0, 0.2);
    overflow-y: auto;
    overflow-x: hidden; /* 防止文字撑出来 */
    top: 0;
    left: 0;
    position: fixed;
    border-radius: 0 10px 10px 0;
    transition: width 0.3s ease-in-out;
    z-index: 999;
}

.sidebar.shrink {
    width: 50px; /* 收缩后只保留图标区 */
}
.sidebar.shrink .sidebar-title {
    color: transparent;     /* 隐藏文字 */
    line-height: 0;         /* 压缩文字高度 */
    padding-top: 0;         /* 去掉多余内边距 */
    padding-bottom: 0;
    height: 0;              /* 让元素高度收缩 */
    overflow: hidden;       /* 防止内容撑开 */
    transition: all 0.2s;   /* 添加过渡动画会更丝滑 */
}
.sidebar a {
    display: flex;
    align-items: center;
    color: #000;
    text-decoration: none;
    padding: 10px;
    border-radius: 4px;
    white-space: nowrap;
    overflow: hidden;
    transition: background-color 0.2s, transform 0.2s;
    margin-left: -8px;
}
/* 图标部分（第一个字符 🎛️ 📶 💬 …） */
.sidebar a span.icon {
    display: inline-block;
    width: 24px;
    text-align: center;
    margin-right: 10px;
    font-size: 18px;
}

/* 文字部分 */
.sidebar a span.text {
    display: inline-block;
    transition: opacity 0.3s;
}

/* 收缩时隐藏文字 */
.sidebar.shrink a span.text {
    opacity: 0;
    width: 0;
    margin: 0;
    overflow: hidden;
}
.sidebar-title {
    font-size: 20px;
    font-weight: bold;
    margin-bottom: 10px;
    color: #000;
    text-align: center;
    font-family: 'Arial', sans-serif;
    margin-bottom: 20px !important;
}
.sidebar a i {
    margin-right: 23px; /* 调整这个值来增加或减少图标和文字之间的距离 */
}
.sidebar a:hover {
    transform: translateX(5px);
    background-color:rgb(117, 175, 182);
}
.sidebar.hidden {
    width: 0;
}
.content {
    flex: 1;
    height: 100vh;
    padding: 20px;
    box-sizing: border-box;
    overflow-y: auto;
    position: relative; /* 使 .toggle-button 相对这个父元素定位 */
    margin-left: 155px; /* 展开时和 sidebar 同步 */
    transition: margin-left 0.3s ease-in-out, width 0.3s ease-in-out;
    width: calc(100% - 180px);
}
.sidebar.shrink ~ .content {
    margin-left: 100px; /* 收缩时缩到 50px */
    width: calc(100% - 50px);
}
.serverDialog {
    position: fixed;
    background: #fff;
    border: 5px solid #ccc;
    padding: 20px;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    margin: 0;
    z-index: 9999;
    max-height: 700px;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
    opacity: 0;
    overflow: auto;
    display: flex;               /* 新增 */
    flex-direction: column;     /* 纵向排列子元素 */
    align-items: center;        /* 水平居中子元素 */
}
.serverDialog input {
    width: 90%;
    max-height: 60%;
    margin-bottom: 10px;
    padding: 5px;
    box-sizing: border-box; /* 包括内边距和边框在内的宽度和高度 */
    border: 1px solid #ccc;
    border-radius: 4px; /* 添加圆角 */
    font-size: 14px; /* 设置字体大小 */
    background-color: #f9f9f9; /* 设置背景颜色 */
    overflow: auto; /* 允许滚动 */
    margin-left: auto;
    margin-right: auto;
}
.serverDialog textarea {
    width: 90%;
    height: 30px;
    resize: none; /* 禁止调整大小 */
}
.log {
    height: 200px;
    background-color:rgb(202, 202, 202);
    font-size: 15px;
    box-sizing: border-box;
    overflow: auto; /* 允许滚动 */
    display: flex;
    flex-direction: column; /* 更改为上下分布 */
    position: fixed; /* 固定位置 */
    bottom: 0;
    left: 180px; /* 侧边栏的宽度 */
    width: 100%; /* 全宽减去侧边栏宽度 */
    overflow-y: auto;
    padding-left: 5px;
    padding-right: 5px;
    border-radius: 10px; /* 添加圆角 */
}
#log-content {
    flex: 1; /* 占据剩余的高度 */
    overflow-y: auto;
    box-sizing: border-box;
}
/* 自定义滚动条样式 */
#log-content::-webkit-scrollbar {
    width: 8px; /* 滚动条宽度 */
}

#log-content::-webkit-scrollbar-track {
    background: #f1f1f1; /* 滚动条轨道背景色 */
}

#log-content::-webkit-scrollbar-thumb {
    background: #888; /* 滚动条滑块背景色 */
    border-radius: 10%; /* 滑块圆角 */
}
.rename-btn, .time-btn {
    padding: 2px 6px;
    font-size: 13px;
    border: none;
    background: #f3f3f3;
    border-radius: 4px;
    cursor: pointer;
    box-shadow: 0 1px 2px #ccc;
    margin-left: 3px;
    transition: background 0.2s;
}
.rename-btn:hover, .time-btn:hover {
    background: #e0e0e0;
}
#log-content::-webkit-scrollbar-thumb:hover {
    background: #555; /* 滑块悬停时背景色 */
}
#log .resize-handle {
    width: 100%;
    height: 10px;
    top: 0px;
    background-color: transparent;
    position: sticky; /* 固定 handle 在 log 容器的底部 */
    bottom: 0;
    z-index: 10;
    cursor: ns-resize;
}
.hidden {
    display: none;
}
.toggle-button {
    position: absolute;
    top: 0px;
    right: 5px; /* 挨着边界 */
    width: 10px;
    height: 28px;
    border-radius: 25%;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
    font-size: 18px;
    z-index: 1000;
    background-color:rgb(194, 226, 226);
    cursor: pointer;
    border: none;
    display: flex;
    justify-content: center;
    align-items: center;
}
.sidebar, .toggle-button {
    transition: transform 0.3s ease-in-out;
}
.iframe-panel {
    position: absolute; /* 使用绝对定位 */
    top: 100px; /* 初始位置 */
    left: 100px; /* 初始位置 */
    width: 60%;
    height: 80%;
    border: 1px solid #ccc;
    background: #fff;
    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
    z-index: 1000;
    display: none; /* 默认隐藏 */
}
.iframe-panel .close-button {
    position: absolute;
    top: 5px;
    right: 5px;
}
.iframe-panel .drag-handle {
    width: 100%;
    height: 30px; /* 固定高度 */
    background-color: #f1f1f1;
    cursor: move;
    position: absolute;
    top: 0;
    left: 0;
    z-index: 1005;
}
.iframe-panel iframe {
    position: absolute;
    top: 30px; /* 避开 drag-handle */
    width: 100%;
    height: calc(100% - 30px); /* 减去 drag-handle 的高度 */
    border: none;
}
.close-button {
    position: absolute;
    top: 0px;
    height: 23px;
    right: 5px;
    cursor: pointer;
    background-color: #f00; /* 使用 background-color 代替 background */
    color: #fff;
    border: none;
    padding: 5px 10px;
    border-radius: 3px; /* 添加圆角 */
    font-size: 14px; /* 设置字体大小 */
    z-index: 1010; /* 确保 z-index 一致 */
}
.close-button:hover {
    background-color: #d00; /* 添加悬停效果 */
}
.tle-sidebar {
    display: none; /* 初始隐藏 */
}
.tel-toggleBtn {
    display: none; /* 初始隐藏 */
}
/* 为移动设备设置 sidebar 的宽度 */
@media (max-width: 768px) {
    .content {
        margin-left: 0; /* 移动端取消左侧间距 */
        width: 100%; /* 内容区宽度 100% */
    }
    .sidebar {
        display: none; /* 为移动端设置较窄的 sidebar */
    }
    .sidebar-title{
        font-size: 16px;
        font-weight: bold;
        margin-bottom: 10px;
        color: #000;
        text-align: center;
        font-family: 'Arial', sans-serif;
        font-style: italic; /* 斜体 */
        text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.3); /* 添加阴影 */
        background-color: #fff; /* 设置背景颜色 */
        padding: 5px; /* 添加内边距 */
    }
    .toggle-button{
        display: none;
    }
    .log{
        left: 0px;
        width: 100%; /* 调整日志部分的宽度 */
    }
    .tle-sidebar {
        display: none; /* 初始隐藏 */
        background: #f4f4f4;
        padding: 10px;
        border: 1px solid #ccc;
        width: 200px;
        position: absolute;
        top: 50px;
    }
    .tel-toggleBtn {
        display: block; /* 移动端显示按钮 */
        padding: 10px 15px;
        background: #007bff;
        color: white;
        border: none;
        cursor: pointer;
        font-size: 16px;
        width: 50px;
    }
    .tel-toggleBtn:hover {
        background: #0056b3;
    }
}
.server-container {
    display: flex;
    align-items: center;
    justify-content: flex-start; /* 水平排列 */
    border: 1px solid #ccc;
    padding: 7px;
    margin: 5px 0;
    border-radius: 5px;
    background-color: #f9f9f9;
    width: 98%;
    flex-wrap: nowrap; /* 禁止子元素换行 */
}
.server-container > * {
                    /* 确保子元素适应父容器宽度 */
    max-width: 100%;
    flex-shrink: 0; /* 防止子元素压缩 */
}
.conn-container {
    display: flex;
    align-items: center;
    justify-content: flex-start; /* 使子元素水平排列 */
    border: 1px solid #ccc;
    padding: 7px;
    margin: 5px 0;
    border-radius: 5px;
    background-color: #f9f9f9;
    width: 95%;
    flex-wrap: wrap; /* 允许子元素换行 */
    min-height: 65px;
}
.conn-container > * {
    /* 确保子元素适应父容器宽度 */
    max-width: 100%;
    flex-shrink: 0; /* 防止子元素压缩 */
}
.client-card {
    width: 1000px;
    margin: 18px 50px;
    padding: 12px 15px;

    background: rgb(225,225,225);
    color:#000;

    border-radius:8px;
    border:1px solid #dfdfdf;

    box-shadow:0 3px 10px rgba(0,0,0,.2);

    display:flex;
    align-items:center;
    gap:12px;
    flex-wrap:nowrap;
    transition:.25s ease;
    box-sizing:border-box;
    /* 靠页面右边一点 */
}


.client-card:hover {
    background:#cdcdcd;
    border-color:#aaa;
}


/* 信息 */
.client-card p {
    margin:0;
    padding:0 8px;

    font-size:14px;

    white-space:nowrap;

    flex:1;

    min-width:0;

    overflow:hidden;
    text-overflow:ellipsis;
}


/* 标签 */
.client-card p span {
    color:#4e9cff;
    font-weight:bold;
    margin-right:5px;
}


/* 按钮区域 */
.btn-box {

    display:flex;

    gap:8px;

    flex-shrink:0;
}


/* 按钮 */
.btn {

    padding:6px 12px;

    border:none;

    border-radius:6px;

    cursor:pointer;

    font-size:14px;

    white-space:nowrap;

}


.receive {
    background:#2196f3;
    color:white;
}


.remove {
    background:#e53935;
    color:white;
}
@media(max-width:700px){

    .client-card {
        width:calc(100% - 20px);
        margin:10px;
        padding:12px;
        flex-wrap:wrap;
        gap:8px;
    }


    .client-card p {
        width:100%;
        flex:none;
        padding:3px 0;

    }
    .btn-box {

        width:100%;
        margin-top:8px;

    }

    .btn {

        flex:1;

        padding:8px;

    }

}
.os-container{ 
    display: flex;
    align-items: center;
    padding: 10px;
    margin-left: auto;
    background-color: #f9f9f9;
}
.host-container{
    white-space: nowrap; /* 防止内部元素换行 */
}
.ip-address, .online-time, .shell-address {
    display: inline-block;
    margin-right: 10px;
    font-size: 1em;
    font-weight: bold;
}
.let-it-in-button {
    padding: 8px 12px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    background-color: #4CAF50;
    color: white;
    display: inline-block;
    margin-right: 10px;
}
.button-container {
    width: 40%;
}
.server-info {
    display: inline-block;
    min-width: 1020px;
    padding: 10px;
    background: #fff;
    margin: 15px 0 15px 50px; /* 替代 top-margin */
    border-radius: 8px;
    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    border: none;
}
/*植入物气泡样式*/
.ip-info {
    display: inline-block;
    background: #fff;
    padding: 10px;
    width: 90%;
    margin: 10px;
    margin-left: 50px;  /* 将元素推到右边 */
    border-radius: 8px;
    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    align-items: center;
    border: none;
}
.info-content {
    display: none;
    margin-top: 10px;
    padding: 10px;
    background-color: #f0f0f0;
    border-radius: 5px;
}
/* 让 info-content 内部的 p 标签变成 flex 布局，左右对齐 */
.info-content p {
    display: flex;
    align-items: flex-start; /* 让左侧和右侧内容上对齐 */
    gap: 10px; /* 左右内容间距 */
    margin: 5px 0;
}
/* 统一左侧 strong 的样式 */
.s_left {
    font-size: 14px;
    width: 120px; /* 设定统一宽度，保证左侧对齐 */
    text-align: left;
    flex-shrink: 0; /* 防止左侧文本被压缩 */
    margin-right: 20px;
}
/* 右侧文本和输入框统一 */
.s_right {
    font-size: 14px;
    text-align: left;
    word-break: break-all; /* 让长内容自动换行 */
}
/* 右侧 input 统一样式 */
input.s_right_input.custom-remarks {
    font-size: 14px;
    height: 20px; /* 设置固定高度，避免太高 */
    line-height: 20px; /* 确保文字居中 */
    text-align: left;
    background-color: transparent;
    border: none !important; /* 强制去掉边框 */
    outline: none !important; /* 去掉聚焦时的默认高亮 */
    box-shadow: none !important; /* 去掉可能的默认阴影 */
    appearance: none; /* 禁用某些浏览器默认样式 */
    -webkit-appearance: none; /* 兼容 Webkit 内核浏览器 */
    -moz-appearance: none; /* 兼容 Firefox */
    padding: 0; /* 避免额外的内边距撑高输入框 */
}               
input.s_right_input.custom-remarks:focu {
    outline: none;
    border: none;
    box-shadow: none;
    -webkit-tap-highlight-color: transparent; /* 禁止移动端高亮 */
}                
/* 显示时的样式 */
.info-content.show {
    display: block;
}
.choose-content {
    display: none;              /* 初始隐藏 */
    flex-wrap: wrap;            /* 子项自动换行 */
    gap: 8px;

    margin-top: 10px;
    padding: 10px;
    background-color: #f0f0f0;
    border-radius: 5px;
    max-width: 100%;

    box-sizing: border-box;
    overflow-x: hidden;
}

/* 显示时的类 */
.choose-content.show {
    display: flex;
}
@media (max-width: 768px) {
    .s_left {
        font-size: 12px; /* 调整左侧字体大小 */
        width: auto; /* 宽度自适应 */
        margin-right: 10px; /* 缩小右侧间距 */
    }

    .s_right {
        font-size: 12px; /* 调整右侧文本大小 */
        margin-left: 0; /* 去掉左侧间距 */
    }

    input.s_right_input.custom-remarks {
        font-size: 14px; /* 调整输入框文字大小 */
        height: 15px; /* 调整高度适应手机 */
        line-height: 30px; /* 确保文字居中 */
        padding-left: 5px; /* 添加左内边距 */
    }

    .info-content {
        padding: 8px; /* 手机端调整内边距 */
    }
}

/* 更小的手机端适配 */
@media (max-width: 480px) {
    .s_left {
        font-size: 10px; /* 更小的字体 */
    }

    .s_right {
        font-size: 10px; /* 更小的字体 */
    }

    input.s_right_input.custom-remarks {
        font-size: 10px; /* 更小的字体 */
        height: 28px; /* 调整高度 */
        line-height: 28px; /* 确保文字居中 */
    }
}
.ip-address, .action-button, .console-link {
    margin-right: 3.5px; /* 元素之间的间隔 */
    white-space: nowrap;  /*防止换行 */
    border: none; /* 去掉边框 */
}
.ip-address {
    font-size: 12px;
    color: #555;
    margin-right: 8px;
}
.host-name { /* 主机名特殊样式 */
    font-weight: bold; /* 加粗显示 */
}
.action-button {
    padding: 5px 10px;
    border-radius: 5px;
    cursor: pointer;
    justify-content: center;
    gap: 25px; /* 按钮之间的间距 */
    font-size: 12px;
    background-color: #ccc; /* 浅灰色 */
    color: #fff;
    border: none; /* 去掉按钮边框 */
    transition: background-color 0.3s; /* 平滑过渡效果 */
}
.action-button:hover {
    background-color: #fff; /* 鼠标悬浮时背景变为白色 */
    color: #333; /* 鼠标悬浮时文字颜色变为深色 */
}
.console-link {
    justify-content: center;
    gap: 25px; /* 按钮之间的间距 */
    text-decoration: none; /* 去掉下划线 */
    color: #007BFF; /* 设置链接颜色 */
    font-size: 12px; /* 设置字体大小 */
    margin-left: 5px; /* 设置与前一个元素的间隔 */
    border: none; /* 去掉边框 */
    padding: 8px 15px; /* 设置内边距 */
    border-radius: 4px; /* 设置边框圆角 */
    background-color: #f8f9fa; /* 设置背景颜色 */
    transition: background-color 0.3s, color 0.3s; /* 平滑过渡效果 */
    cursor: pointer; /* 鼠标悬停时显示手形图标 */
    outline: none; /* 点击时不显示轮廓 */
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1); /* 添加阴影效果 */
}
.console-link:hover,
.console-link:focus {
    background-color: #0069d9; /* 鼠标悬停或聚焦时的背景颜色 */
    color: white; /* 文字颜色 */
    text-decoration: none; /* 鼠标悬停时不显示下划线 */
    }
.console-link:active {
    background-color: #0062cc; /* 鼠标按下时的背景颜色 */
    box-shadow: none; /* 移除阴影 */
}
.external-address {
    margin-left: 5px; /* 与前面的元素保持间隔 */
    border: none; /* 去掉边框 */
}
.external-address .ip-address {
    margin-left: 10px; /* 与前面的按钮保持间隔 */
}
.server_form {
    background: #fff;
    padding: 10px;
    width: 95%;
    border-radius: 8px;
    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
    display: flex;
    flex-direction: row; /* 横向排列 */
    gap: 3px; /* 元素之间的间距 */
    align-items: center; /* 元素垂直居中 */
    margin-left: 20px;
}
.keyput{
    width: 20px;
    height: 20px;
    opacity: 0;
    position: absolute;
    z-index: -1;
}
.custom-file-upload {
    display: inline-block;
    padding: 6px 12px;
    cursor: pointer;
    background-color: #007bff;
    color: #fff;
    border-radius: 5px;
    font-size: 14px;
    font-weight: bold;
    text-align: center;
    border: none;
    transition: background-color 0.3s ease;
}
.custom-file-upload:hover {
    background-color: #0056b3;
}
/* 让按钮看起来更像其他输入框 */
.file-upload-container {
    display: flex;
    align-items: center;
    gap: 5px;
}                
.form {
    background: #fff;
    padding: 10px;
    width: 100%;
    border-radius: 8px;
    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
    display: flex;
    flex-direction: row; /* 横向排列 */
    gap: 15px; /* 元素之间的间距 */
    align-items: center; /* 元素垂直居中 */
}input[type="text"] {
    width: 45%; /* 输入框宽度调整 */
    padding: 10px;
    border: 1px solid #ddd;
    border-radius: 5px;
    font-size: 14px;
    transition: border-color 0.3s;
}
input[type="text"]:focus {
    border-color: #007BFF;
    outline: none;
}
label {
    font-size: 14px;
    color: #333;
}
select {
    width: 25%; /* 下拉菜单宽度调整 */
    padding: 10px;
    border: 1px solid #ddd;
    border-radius: 5px;
    font-size: 14px;
    background-color: #fff;
    transition: border-color 0.3s;
}
select:focus {
    border-color: #007BFF;
    outline: none;
}
button {
    padding: 10px 15px;
    background-color: #007BFF;
    color: white;
    border: none;
    border-radius: 5px;
    cursor: pointer;
    font-size: 14px;
    transition: background-color 0.3s;
}
button:hover {
    background-color: #0056b3;
}
#div_index {
    margin-top: 15px;
}
/* 为移动设备设置 sidebar 的宽度 */
@media (max-width: 768px) {
    .server-info {
        max-width: 400px; /* 让 ip-info 在移动端填满整个屏幕 */
        margin: 0;
    }
    .ip-info {
        max-width: 400px; /* 让 ip-info 在移动端填满整个屏幕 */
        margin: 0;
    }
    .server-container {
        flex-direction: row; /* 确保子元素在一行内 */
        flex-wrap: wrap; /* 允许换行 */
        max-width: 100%; /* 防止超出 */
        overflow: hidden; /* 避免溢出 */
        background-color: #f9f9f9;
    }
    .conn-container {
        flex-direction: row; /* 确保子元素在一行内 */
        flex-wrap: wrap; /* 允许换行 */
        max-width: 100%; /* 防止超出 */
        overflow: hidden; /* 避免溢出 */
        background-color: #f9f9f9;
    }
    .os-container {
        display: flex;
        align-items: center;
        padding: 10px;
        background-color: #f9f9f9;
        margin-left: 0; /* 取消自动推到右侧 */
    }                    
    .ip-address, .action-button, .console-link {
        margin-right: 0; /* 移动端去掉右侧的间隔 */
        margin-bottom: 10px; /* 元素之间增加垂直间隔 */
        font-size: 14px; /* 调整字体大小 */
    }
    .action-button, .console-link {
        width: 100%; /* 在移动设备上按钮占满整个行 */
        text-align: center; /* 按钮内文字居中 */
    }
    .host-name, .ip-address {
        font-size: 14px; /* 调整主机名和 IP 的字体大小 */
    }
    .let-it-in-button {
        width: 100%; /* 按钮宽度 100% 占据一整行 */
        margin-bottom: 10px;
    }
    .server_form{
        background: #fff;
        padding: 10px;
        width: 100%;
        border-radius: 8px;
        box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        display: flex;
        flex-direction: row; /* 横向排列 */
        align-items: center; /* 元素垂直居中 */
        margin: 0 auto;
    }
    .custom-file-upload {
        display: inline-block;
        padding: 3px 6px;
        cursor: pointer;
        background-color: #007bff;
        color: #fff;
        border-radius: 5px;
        font-size: 7px;
        font-weight: bold;
        text-align: center;
        border: none;
        transition: background-color 0.3s ease;
    }
    .form {
        background: #fff;
        padding: 10px;
        width: 100%;
        border-radius: 8px;
        box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        display: flex;
        flex-direction: row; /* 横向排列 */
        gap: 15px; /* 元素之间的间距 */
        align-items: center; /* 元素垂直居中 */
    }
    .button-container {
        width: 40%;
    }
}
.net_div {
    height: 20%;
    background-color: lightgray; /* 添加背景色以便于查看 */
    width: 95%;
    margin-left: 40px;
}
.net_scan{
    display: flex;
    gap: 10px; 
    margin-bottom: 2%;
    margin-left: 50px;
}
.net_div_son {
    background-color: #f9f9f9; /* 浅灰色背景 */
    border: 1px solid #ddd; /* 轻微的边框 */
    border-radius: 5px; /* 圆角边框 */
    box-shadow: 0 2px 4px rgba(0,0,0,0.1); /* 轻微的阴影，增加层次感 */
    padding: 15px; /* 内边距 */
    margin-bottom: 10px; /* 与下一个元素的间距 */
    transition: transform 0.3s ease, box-shadow 0.3s ease; /* 动态效果 */
}
.net_div_son:hover {
    transform: translateY(-3px); /* 鼠标悬停时轻微上移 */
    box-shadow: 0 4px 8px rgba(0,0,0,0.2); /* 鼠标悬停时更深的阴影 */
}
.net_div_son strong {
    color: #333; /* 强调文字颜色 */
    margin-right: 5px; /* 与内容的间距 */
}
.net_div_son hr {
    border: 0; /* 移除边框 */
    height: 1px; /* 高度 */
    background-color: #eaeaea; /* 颜色 */
    margin: 10px 0; /* 与内容的间距 */
}
.net_div_son button {
    margin-left: auto; /* 按钮靠右 */
    min-height: 60%;
}
#have_ip {
    display: flex; /* 设置为flex布局 */
    flex-wrap: wrap; /* 允许子元素自动换行 */
    gap: 10px; /* 设置子元素之间的间距 */
    margin-top: 10px; /* 与选择框的间距 */
    font-family: 'Arial', sans-serif; /* 设置字体 */
    margin-left: 15px;
}
#have_ip div {
    background-color: #f0f0f0; /* 浅灰色背景 */
    border: 1px solid #ddd; /* 边框颜色 */
    border-radius: 4px; /* 圆角边框 */
    padding: 5px 10px; /* 内边距 */
    display: inline-block; /* 内联块级元素 */
}
#have_ip div:hover {
    background-color: #e0e0e0; /* 鼠标悬停时的背景颜色 */
    cursor: pointer; /* 鼠标悬停时的光标样式 */
}
.file-history{
    width: 20%;
    font-size: 14px;
    color: #555;
}
.history-item {
    padding: 8px;
    border-bottom: 1px solid #eee;
    cursor: pointer;
    hight: 45px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    transition: background-color 0.3s;
}
.history-item:hover {
    background-color: #f0f0f0;
}
.history-item-label {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}
.history-delete-btn {
    flex-shrink: 0;
    border: none;
    background: transparent;
    color: #cc5a5a;
    cursor: pointer;
    font-size: 16px;
    line-height: 1;
    padding: 4px 6px;
    border-radius: 6px;
    transition: background-color 0.2s ease, color 0.2s ease;
}
.history-delete-btn:hover {
    background: rgba(204, 90, 90, 0.08);
    color: #a93f3f;
}
.filecontainer {
    width: 100%;
    margin: 0;
    padding: 15px;
    background-color: white;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    height: 92%;
    overflow-y: auto;
}
.file-manager {
    display: flex;
    flex-wrap: wrap;
    justify-content: center;
    gap: 10px;
    margin-top: 20px;
    width: 100%;
    min-hight: 100%;
}
.directory, .file {
    display: flex;
    align-items: center;
    padding: 10px;
    width: 100%;
    background-color: white;
    border: 1px solid #ccc;
    border-radius: 5px;
    cursor: pointer;
    text-decoration: none;
    color: inherit;
    transition: box-shadow 0.3s, transform 0.3s;
}
.directory:hover, .file:hover {
    box-shadow: 0 4px 12px rgba(0,0,0,0.2);
    transform: translateY(-2px);
}
.loot-list {
    max-width: 980px;
    margin: 0 0 0 42px;
    padding-right: 18px;
    box-sizing: border-box;
}
.loot-empty-state {
    padding: 18px 0;
    color: #666;
}
.loot-card {
    border: 1px solid #ddd;
    border-radius: 8px;
    padding: 14px;
    margin-bottom: 12px;
    background: #fff;
    box-shadow: 0 2px 6px rgba(0, 0, 0, 0.04);
}
.loot-card-title {
    margin-bottom: 8px;
    color: #222;
    word-break: break-word;
}
.loot-card-uid {
    margin-left: 12px;
}
.loot-empty {
    color: #666;
    padding: 6px 0 2px;
}
.loot-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    padding: 8px 0;
    border-top: 1px solid #f0f0f0;
}
.loot-info {
    flex: 1;
    min-width: 0;
}
.loot-file-name {
    color: #1f1f1f;
    word-break: break-all;
}
.loot-meta {
    font-size: 12px;
    color: #666;
    margin-top: 3px;
    word-break: break-word;
}
.loot-download-btn {
    padding: 6px 10px;
    cursor: pointer;
    border: 1px solid #d6d6d6;
    border-radius: 6px;
    background: #f7f7f7;
    color: #222;
    transition: background-color 0.2s ease, border-color 0.2s ease;
    white-space: nowrap;
}
.loot-download-btn:hover {
    background: #ececec;
    border-color: #bdbdbd;
}
.loot-download-btn:active {
    background: #e3e3e3;
}
.icon {
    font-size: 1.5em;
    margin-right: 10px;
    color: #555;
}
.dir-btn {
    padding: 10px 20px;
    font-size: 1em;
    color: #fff;
    background-color: #007bff;
    border: none;
    border-radius: 5px;
    cursor: pointer;
    transition: background-color 0.3s, transform 0.3s;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 1%;
}
.dir-btn:hover {
    background-color: #0056b3;
}
.dir-btn:active {
    background-color: #004085;
    transform: translateY(2px);
}
#cur_dir {
    background-color: #f9f9f9;
    border: 1px solid #e1e4e8;
    border-radius: 8px;
    padding: 15px 20px;
    margin: 20px 0;
    font-size: 16px;
}
#cur_dir_p{
    margin-right: 2%;
}
#uploadForm {
    margin-bottom: 20px;
    justify-content: center;
    align-items: center;
    display: flex;
    flex-direction: column;  /* 垂直排列 */
    gap: 10px;
}
.fileinput{
    padding: 10px;
    border: 1px solid #ccc;
    border-radius: 5px;
    cursor: pointer;
}
#uploadForm input[type="submit"] {
    padding: 10px 20px;
    font-size: 1em;
    color: #fff;
    background-color: #007bff;
    border: none;
    border-radius: 5px;
    cursor: pointer;
    transition: background-color 0.3s;
}
#uploadForm input[type="submit"]:hover {
    background-color: #0056b3;
}
#uploadForm input[type="submit"]:active {
    background-color: #004085;
    transform: translateY(2px);
}
.dir-controls {
    display: flex;       /* 使用flex布局 */
    align-items: center; /* 垂直居中对齐子元素 */
    margin-top: 20px;   /* 根据需要调整上边距 */
}
    /* 输入框样式 */
#directoryInput {
    padding: 10px;
    border: 1px solid #ccc;
    border-radius: 5px;
    font-size: 16px;
    margin-right: 10px; /* 与按钮保持间距 */
    width: 200px; /* 设置一个合适的宽度 */
    transition: border-color 0.3s, box-shadow 0.3s;
}
#directoryInput:focus {
    border-color: #007bff;
    box-shadow: 0 0 8px rgba(0, 123, 255, 0.2);
    outline: none; /* 移除默认的焦点轮廓 */
}
/* 按钮样式 */
#moveDirButton {
    padding: 10px 20px;
    font-size: 16px;
    color: #fff;
    background-color: #007bff;
    border: none;
    border-radius: 5px;
    cursor: pointer;
    transition: background-color 0.3s, transform 0.3s;
}
#moveDirButton:hover {
    background-color: #0056b3;
}
#moveDirButton:active {
    background-color: #004085;
    transform: translateY(2px);
}
/* 响应式设计 */
@media (max-width: 768px) {
    .directory, .file {
        width: 100%;
        font-size: 12px;
        padding: 6px;
    }
    .file-history {
        width: 60px !important;
        overflow: auto;
        margin-right: 12px;
    }
    .filecontainer {
        width: 92%;
        margin: 0;
        padding: 15px;
        background-color: white;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        overflow-y: auto;
    }
    .file-manager {
        margin-top: 10px;
        width: 100%;
    }
    .loot-list {
        max-width: 100%;
        margin-left: 0;
        padding-right: 0;
    }
    .loot-card {
        padding: 12px;
    }
    .loot-card-title {
        display: flex;
        flex-direction: column;
        gap: 4px;
    }
    .loot-card-uid {
        margin-left: 0;
    }
    .loot-row {
        flex-direction: column;
        align-items: flex-start;
    }
    .loot-download-btn {
        width: 100%;
    }
}
.shell-container {
    display: flex; /* 使用 flexbox 布局 */
    align-items: center; /* 垂直居中对齐 */
    top: 0;
}
.terminal {
    width: 100%;
    height: 75vh;
    padding: 10px;
    box-sizing: border-box;
    overflow-y: auto;
    background-color:rgb(255, 255, 255);
}
#terminal .shell-input  {
    width: 95%;
    border: none;
    background: transparent;
    border: 1px solid #ddd;
    color: #000;
    outline: none;
    font-size: 16px;
    margin-left: 10px;
}
.prompt {
    margin-right: 5px;
    color: #000;
    display: inline-block;
    width: 30px;
    font-size: 12px;
}
.input-container {
    margin-top: 10px;
}
.output {
    white-space: pre-wrap;
    margin: 5px 0;
    font-size: 12px;
}
.form-in {
    background-color: #ffffff;
    padding: 30px; 
    border-radius: 10px;
    box-shadow: 0px 4px 15px rgba(0, 0, 0, 0.2); 
    width: 300px;
    height: auto; 
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    position: absolute;
    top: 50%; /* 距离页面顶部 50% */
    left: 50%; /* 距离页面左侧 50% */
    transform: translate(-50%, -50%); /* 使用 transform 来居中 */
}
.form-in input[type="text"],
.form-in input[type="password"] {
    width: 100%; 
    padding: 10px; /* 增加内边距 */
    margin: 10px 0; /* 增加垂直方向的间距 */
    border-radius: 5px; /* 设置输入框的圆角 */
    border: 1px solid #ccc; /* 边框颜色 */
    font-size: 16px; /* 设置字体大小 */
    box-sizing: border-box; /* 包含内边距和边框 */
}
.form-in button {
    width: 100%; 
    padding: 10px; /* 增加内边距 */
    background-color: #ffaec6; 
    color: white; /* 按钮文字颜色 */
    border: none;
    border-radius: 5px;
    font-size: 16px; /* 字体大小 */
    cursor: pointer; 
    margin-top: 10px; /* 按钮与输入框之间的间距 */
    transition: background-color 0.3s ease; /* 添加平滑过渡效果 */
}
.form-in button:hover {
    background-color: #ff75ba; /* 悬停时的背景颜色 */
}
.form-in h1 {
    font-size: 24px; /* 设置标题的字体大小 */
    margin-bottom: 20px; /* 标题与输入框之间的间距 */
    color: #333; /* 标题颜色 */
}
.chat {
    width: 100%;
    height: 100%;            /* 占满整个可视高度 */
    box-sizing: border-box;
}
.chat_container {
    margin: 0 auto;
    width: 65%;
    max-height: 80vh; /* 留出输入框高度+间距 */
    padding: 10px;
    box-sizing: border-box;
    display: flex;
    flex-direction: column;
    overflow-y: auto;  /* 内容多了滚动 */
}
/* 输入框容器 */
.chat_input_wrapper {
    position: absolute;
    left: 15%; 
    bottom: 20px !important; 
    width: 75%;
    background: #fff;
    border: 1px solid #ccc;
    border-radius: 50px;
    display: flex;
    align-items: center;
    padding: 5px 10px;
    box-sizing: border-box;
    z-index: 2;
}

/* 输入框 */
.chat_input {
    flex: 1;
    border: none;
    font-size: 14px;
    outline: none;
    margin: 0 5px;
}

/* 左右按钮 */
.chat_icon_left,
.chat_icon_right {
    padding: 4px 8px;
    background-color: rgb(255, 255, 255);
    color: #000;
    border: none;
    border-radius: 5px;
    cursor: pointer;
    font-size: 15px;
    transition: background-color 0.3s, transform 0.2s;
}

.chat_icon_left:hover,
.chat_icon_right:hover {
    background-color: #e5e5e5;
    transform: scale(1.05);
}

.chat_icon_left:active,
.chat_icon_right:active {
    transform: scale(0.9);
}

/* 公共气泡样式 */
.chat_message {
    display: inline-block;
    max-width: 60%;
    min-width: 100px;
    background: #ffffff;
    padding: 10px 14px;
    border-radius: 8px;
    border: 1px solid #eee;
    font-size: 14px;
    line-height: 1.4;
    box-shadow: 0 1px 2px rgba(0,0,0,0.08);
    word-wrap: break-word;
    position: relative;
    margin: 6px 0;             /* 上下间距 */
    align-self: flex-start;     /* 默认靠左 */
}

/* 自己发送的消息靠右 */
.chat_message.me {
    background: #DCF2FF;
    border-color: #c8e6ff;
    text-align: right;
    align-self: flex-end;       /* 靠右 */
}
/* 用户名 */
.chat_message strong {
    display: block;
    margin-bottom: 4px;
    font-weight: 600;
    color: #333;
}
.chat_message.me strong {
    color: #2A7FD6;
}

/* 消息文本 */
.chat_message span,
.chat_message div,
.chat_message p {
    word-break: break-word;
    white-space: pre-wrap;
    margin: 0;
}

/* 时间戳 */
.chat_time {
    margin-top: 6px;
    color: #999;
    font-size: 12px;
    text-align: right;
}

/* 文件链接 */
.chat_message a {
    color: #007BFF;
    text-decoration: none;
}

.chat_message a:hover {
    text-decoration: underline;
}

/* 鼠标悬浮略微高亮 */
.chat_message:hover {
    box-shadow: 0 2px 6px rgba(0,0,0,0.12);
}

/* 选中文本高亮 */
.chat_message::selection {
    background: rgba(0, 120, 215, 0.3);
}
.pending_file {
    opacity: 0.6;
    font-style: italic;
}
.pending_file_preview {
    opacity: 0.7;
    background: #444;
    padding: 6px 10px;
    margin: 6px 0;
    border-radius: 4px;
    font-size: 14px;
}
#modify-server-dialog {
    position: fixed;
    top: 10%;
    left: 50%;
    transform: translateX(-50%);
    background: #fff;
    z-index: 9999;
    width: 400px;
    padding: 16px;
    border: 1px solid #ccc;
    border-radius: 8px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
    font-family: monospace;
}

#modify-server-dialog h3 {
    margin-top: 0;
}

#modify-server-dialog textarea {
    width: 100%;
    height: 200px;
    box-sizing: border-box;
    font-family: monospace;
}

#modify-server-dialog .button-container {
    display: flex;
    justify-content: space-between;
    margin-top: 16px;
}

#modify-server-dialog .button-container button {
    padding: 8px 16px;
    cursor: pointer;
}

/* plugin dialog */
.serverDialog {
    background: linear-gradient(180deg, #ffffff 0%, #f7fbfd 100%);
    border: 1px solid #cfdde7;
    border-radius: 18px;
    padding: 22px 24px 28px;
    width: min(720px, calc(100vw - 40px));
    max-height: 80vh;
    box-shadow: 0 18px 48px rgba(53, 83, 102, 0.22);
    align-items: stretch;
}

.serverDialog select,
.serverDialog button {
    font-size: 14px;
}

.plugin-dialog-header {
    position: relative;
    width: 100%;
    margin-bottom: 16px;
    text-align: center;
}

.plugin-dialog-header h3 {
    margin: 0;
    color: #23435a;
    font-size: 22px;
    letter-spacing: 0.04em;
    text-transform: uppercase;
}

.plugin-close-btn {
    position: absolute;
    top: 0;
    right: 0;
    width: 38px;
    height: 38px;
    border: none;
    border-radius: 999px;
    background: #e7f1f7;
    color: #35536b;
    font-size: 24px;
    line-height: 1;
    cursor: pointer;
    transition: background-color 0.2s ease, transform 0.2s ease;
}

.plugin-close-btn:hover {
    background: #d5e6f1;
    transform: translateY(-1px);
}

.plugin-form {
    width: 100%;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 10px;
}

.plugin-form select,
.plugin-form input,
.plugin-form button {
    width: 90%;
    box-sizing: border-box;
    border-radius: 10px;
}

.plugin-form select {
    padding: 10px 12px;
    border: 1px solid #c7d7e2;
    background: #f9fcfe;
    color: #26455c;
}

.plugin-form button {
    border: 1px solid #c8d6df;
    padding: 10px 14px;
    background: #eef5f9;
    color: #24455e;
    cursor: pointer;
    transition: background-color 0.2s ease, border-color 0.2s ease;
}

.plugin-form button:hover {
    background: #dcecf4;
    border-color: #aac7d8;
}

#submitBtn {
    background: linear-gradient(135deg, #3a87b1 0%, #295f7b 100%);
    border-color: #295f7b;
    color: #fff;
    font-weight: 600;
}

#submitBtn:hover {
    background: linear-gradient(135deg, #34799f 0%, #244f66 100%);
    border-color: #244f66;
}

#parameterContainer {
    width: 90%;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-wrap: wrap;
    gap: 8px;
    padding: 12px;
    border: 1px solid #d7e4ec;
    border-radius: 12px;
    background: #f5fafc;
    color: #2b4f67;
}

#parameterContainer button {
    width: auto;
    min-width: 40px;
    padding: 6px 12px;
}

.plugin-panel {
    width: 100%;
    margin-top: 18px;
}

.plugin-empty {
    padding: 18px;
    text-align: center;
    color: #5f7382;
    background: #f3f8fb;
    border: 1px dashed #c6d7e0;
    border-radius: 14px;
}

.plugin-section {
    width: 100%;
}

.plugin-section-title {
    margin: 0 0 14px;
    color: #2a4860;
    font-size: 18px;
}

.plugin-os-group {
    margin-bottom: 14px;
    padding: 14px;
    border: 1px solid #d5e2ea;
    border-radius: 16px;
    background: linear-gradient(180deg, #f9fcfe 0%, #eef5f9 100%);
}

.plugin-os-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    margin-bottom: 12px;
}

.plugin-os-badge {
    display: inline-flex;
    align-items: center;
    padding: 6px 12px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 0.04em;
    text-transform: uppercase;
}

.plugin-os-win {
    background: #d9ecfb;
    color: #1f5c88;
}

.plugin-os-linux {
    background: #e0f1df;
    color: #2f6c31;
}

.plugin-os-macos {
    background: #f3e4d7;
    color: #8b5a30;
}

.plugin-os-android {
    background: #e0f5de;
    color: #2b7b3d;
}

.plugin-os-unknown {
    background: #ebedf2;
    color: #4f5d6c;
}

.plugin-os-count {
    color: #607684;
    font-size: 12px;
}

.plugin-os-tools {
    display: flex;
    align-items: center;
    gap: 10px;
}

.plugin-os-list {
    display: flex;
    flex-direction: column;
    gap: 12px;
}

.plugin-item {
    background: #fff;
    border: 1px solid #d9e4eb;
    border-radius: 14px;
    padding: 14px;
    box-shadow: 0 8px 18px rgba(43, 70, 88, 0.05);
}

.plugin-item-top {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 12px;
}

.plugin-item-meta {
    min-width: 0;
    flex: 1;
}

.plugin-codeword {
    display: inline-block;
    margin-bottom: 8px;
    padding: 4px 10px;
    border-radius: 999px;
    background: #23435a;
    color: #fff;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 0.03em;
}

.plugin-meta-text {
    color: #567081;
    font-size: 12px;
    line-height: 1.6;
}

.plugin-item-actions {
    display: flex;
    gap: 8px;
    flex-shrink: 0;
}

.plugin-item-actions button {
    width: auto;
    min-width: 76px;
    padding: 8px 12px;
    border: 1px solid #c9d9e4;
    border-radius: 10px;
    background: #f2f7fa;
    color: #27465f;
    cursor: pointer;
}

.plugin-item-actions button:hover {
    background: #e3edf3;
}

.plugin-delete-btn {
    min-width: 72px;
    padding: 6px 12px;
    border: 1px solid #e1b4b4;
    border-radius: 10px;
    background: #fff1f1;
    color: #8b3030;
    cursor: pointer;
}

.plugin-delete-btn:hover {
    background: #ffe1e1;
    border-color: #d88f8f;
}

.plugin-code-preview {
    margin: 12px 0 0;
    padding: 12px 14px;
    border-radius: 12px;
    background: #0f2230;
    color: #eaf5ff;
    font-size: 12px;
    line-height: 1.55;
    white-space: pre-wrap;
    word-break: break-word;
    overflow: hidden;
    max-height: 72px;
    transition: max-height 0.25s ease;
}

.plugin-code-preview.collapsed {
    max-height: 72px;
}

.plugin-code-preview.expanded {
    max-height: 320px;
    overflow: auto;
}

@media (max-width: 768px) {
    .serverDialog {
        width: calc(100vw - 24px);
        padding: 18px 16px 20px;
        top: 3%;
    }

    .plugin-dialog-header h3 {
        font-size: 18px;
    }

    .plugin-close-btn {
        width: 34px;
        height: 34px;
        font-size: 22px;
    }

    .plugin-form select,
    .plugin-form input,
    .plugin-form button,
    #parameterContainer {
        width: 100%;
    }

    .plugin-os-header,
    .plugin-item-top {
        flex-direction: column;
        align-items: flex-start;
    }

    .plugin-os-tools {
        width: 100%;
        justify-content: space-between;
    }

    .plugin-item-actions {
        width: 100%;
    }

.plugin-item-actions button {
        flex: 1;
    }
}

.dialog-close-btn {
    position: absolute;
    top: 1px;
    right: 4px;
    z-index: 10002;
    width: 15px;
    height: 29px;
    border: 1px solid rgba(130, 154, 170, 0.22);
    border-radius: 999px;
    background: rgba(255, 255, 255, 0.55);
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
    color: #617485;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 20px;
    line-height: 1;
    cursor: pointer;
    box-shadow: 0 6px 18px rgba(72, 94, 109, 0.10);
    transition: background-color 0.2s ease, border-color 0.2s ease, color 0.2s ease, transform 0.2s ease;
}

.dialog-close-btn:hover {
    background: rgba(255, 255, 255, 0.82);
    border-color: rgba(111, 136, 153, 0.34);
    color: #314657;
    transform: translateY(-1px);
}

.dialog-close-btn:active {
    transform: translateY(0);
    background: rgba(242, 247, 250, 0.88);
}

@media (max-width: 768px) {
    .dialog-close-btn {
        top: 8px;
        right: 8px;
        width: 34px;
        height: 34px;
        font-size: 22px;
        background: rgba(255, 255, 255, 0.72);
    }
}

@media (max-width: 480px) {
    .dialog-close-btn {
        top: 6px;
        right: 6px;
        width: 32px;
        height: 32px;
        font-size: 20px;
    }
}

.server-page {
    padding: 24px 24px 40px;
    min-height: 100%;
    box-sizing: border-box;
}

.server-toolbar {
    position: sticky;
    top: 18px;
    z-index: 5;
    display: flex;
    justify-content: flex-start;
    align-items: center;
    margin: 0 0 18px;
    padding: 0;
    border: none;
    background: transparent;
    box-shadow: none;
    backdrop-filter: none;
    -webkit-backdrop-filter: none;
}

.server-toolbar-group {
    display: inline-flex;
    flex-wrap: wrap;
    gap: 10px;
    align-items: center;
    padding: 10px;
    border: 1px solid rgba(180, 201, 217, 0.65);
    border-radius: 999px;
    background: rgba(255, 255, 255, 0.88);
    box-shadow: 0 16px 40px rgba(60, 86, 110, 0.08);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
}

.server-toolbar-btn,
.server-page .startBtn,
.server-page .clearMemoryBtn,
.server-page .logBtn {
    position: static;
    left: auto;
    top: auto;
    margin: 0;
    border: 1px solid rgba(126, 155, 178, 0.28);
    border-radius: 999px;
    padding: 10px 16px;
    background: linear-gradient(180deg, #ffffff 0%, #eef5fb 100%);
    color: #24435b;
    font-size: 13px;
    font-weight: 600;
    letter-spacing: 0.01em;
    cursor: pointer;
    box-shadow: 0 8px 24px rgba(72, 102, 128, 0.10);
    transition: transform 0.18s ease, box-shadow 0.18s ease, border-color 0.18s ease, background-color 0.18s ease;
}

.server-toolbar-btn:hover,
.server-page .startBtn:hover,
.server-page .clearMemoryBtn:hover,
.server-page .logBtn:hover {
    background: linear-gradient(180deg, #ffffff 0%, #e7f2fb 100%);
    border-color: rgba(96, 139, 171, 0.38);
    color: #16344c;
    transform: translateY(-1px);
    box-shadow: 0 12px 28px rgba(72, 102, 128, 0.14);
}

.server-toolbar-btn:active,
.server-page .startBtn:active,
.server-page .clearMemoryBtn:active,
.server-page .logBtn:active {
    transform: translateY(0);
}

.server-teammates-slot {
    margin-bottom: 18px;
}

#server_index.server-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
    gap: 18px;
    align-items: start;
}

.server-card {
    border: 1px solid rgba(198, 214, 226, 0.72);
    border-radius: 20px;
    background: rgba(255, 255, 255, 0.94);
    padding: 18px;
    box-shadow: 0 18px 45px rgba(60, 86, 110, 0.08);
    transition: transform 0.2s ease, box-shadow 0.2s ease, border-color 0.2s ease;
}

.server-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 22px 50px rgba(60, 86, 110, 0.12);
    border-color: rgba(140, 174, 197, 0.78);
}

.server-card-head {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 14px;
    margin-bottom: 16px;
}

.server-card-copy {
    min-width: 0;
}

.server-card-title {
    font-size: 18px;
    font-weight: 700;
    color: #22384a;
    word-break: break-word;
}

.server-card-subtitle {
    margin-top: 6px;
    color: #6f8190;
    font-size: 13px;
    line-height: 1.5;
    word-break: break-word;
}

.server-card-badges {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    justify-content: flex-end;
}

.server-badge {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 7px 11px;
    border-radius: 999px;
    background: #edf5fb;
    color: #315674;
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
}

.server-badge-accent {
    background: #fff1e6;
    color: #a64d18;
}

.server-meta-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 12px;
    margin-bottom: 16px;
}

.server-meta-item {
    padding: 12px 14px;
    border: 1px solid #edf3f8;
    border-radius: 14px;
    background: #f9fbfd;
}

.server-meta-label {
    display: block;
    margin-bottom: 6px;
    color: #7c8f9f;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.05em;
    text-transform: uppercase;
}

.server-meta-value {
    display: block;
    color: #2a4457;
    font-size: 13px;
    font-family: Consolas, Monaco, monospace;
    word-break: break-word;
}

.server-action-groups {
    display: flex;
    flex-direction: column;
    gap: 10px;
}

.server-action-row {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
}

.server-action-pill {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 9px 14px;
    border-radius: 999px;
    text-decoration: none;
    border: 1px solid rgba(171, 195, 214, 0.40);
    background: linear-gradient(180deg, #ffffff 0%, #edf4fa 100%);
    color: #25445b;
    font-size: 13px;
    font-weight: 600;
    transition: transform 0.18s ease, box-shadow 0.18s ease, background-color 0.18s ease, border-color 0.18s ease;
}

.server-action-pill:hover {
    transform: translateY(-1px);
    background: linear-gradient(180deg, #ffffff 0%, #e6f0f8 100%);
    border-color: rgba(124, 162, 191, 0.50);
    box-shadow: 0 10px 20px rgba(70, 102, 128, 0.10);
}

.server-action-pill-secondary {
    background: #f8fbfd;
    color: #476479;
}

.server-action-pill-danger {
    background: #fff4f4;
    border-color: rgba(220, 141, 141, 0.45);
    color: #a44949;
}

.server-action-pill-danger:hover {
    background: #ffeaea;
    border-color: rgba(205, 111, 111, 0.52);
}

@media (max-width: 768px) {
    .server-page {
        padding: 18px 14px 32px;
    }

    .server-toolbar {
        top: 10px;
    }

    .server-toolbar-group {
        width: 100%;
        border-radius: 18px;
        padding: 12px;
    }

    .server-toolbar-btn,
    .server-page .startBtn,
    .server-page .clearMemoryBtn,
    .server-page .logBtn {
        width: 100%;
    }

    #server_index.server-grid {
        grid-template-columns: 1fr;
        gap: 14px;
    }

    .server-card {
        padding: 15px;
    }

    .server-card-head {
        flex-direction: column;
    }

    .server-card-badges {
        justify-content: flex-start;
    }

    .server-meta-grid {
        grid-template-columns: 1fr;
    }

    .server-action-row {
        gap: 8px;
    }

    .server-action-pill {
        flex: 1 1 calc(50% - 8px);
        text-align: center;
    }
}
.online-teammates-card {
    border: 1px solid #dbe6ef;
    background: linear-gradient(180deg, #fdfefe 0%, #f5f9fc 100%);
    border-radius: 12px;
    padding: 14px 16px;
    margin-bottom: 14px;
    box-shadow: 0 8px 24px rgba(64, 92, 118, 0.08);
    width: min(100%, 860px);
}

.online-teammates-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    flex-wrap: wrap;
}

.online-teammates-copy {
    min-width: 0;
}

.online-teammates-title {
    font-size: 16px;
    font-weight: 600;
    color: #243746;
}

.online-teammates-subtitle {
    font-size: 13px;
    color: #6b7d8c;
    margin-top: 3px;
}

.online-teammates-actions {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
}

.online-teammates-count {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 42px;
    padding: 8px 12px;
    border-radius: 999px;
    background: #eaf4ff;
    color: #1d5f95;
    font-weight: 600;
}

.online-teammates-action {
    border: 1px solid #c9d8e6;
    background: #ffffff;
    color: #2e536f;
    border-radius: 999px;
    padding: 8px 14px;
    cursor: pointer;
    transition: background-color 0.2s ease, border-color 0.2s ease, color 0.2s ease;
}

.online-teammates-action:hover {
    background: #f3f8fc;
    border-color: #aac0d4;
    color: #183b56;
}

.online-teammates-action-strong {
    background: linear-gradient(180deg, #ffffff 0%, #eaf4ff 100%);
    border-color: #b8d3ea;
    color: #18486a;
}

.online-teammates-toolbar {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
    margin-top: 14px;
    padding-top: 12px;
    border-top: 1px solid #e7eef5;
}

.online-teammates-list {
    display: none;
    margin-top: 14px;
    padding-top: 10px;
    border-top: 1px solid #e7eef5;
}

.online-teammates-list-label {
    font-size: 12px;
    font-weight: 600;
    color: #6f8191;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    margin-bottom: 8px;
}

.online-teammates-list-body {
    list-style: none;
    padding: 0;
    margin: 0;
}

.online-teammate-item {
    padding: 6px 0;
    border-bottom: 1px solid #eef3f8;
    color: #314657;
}

.online-teammate-empty {
    padding: 6px 0;
    color: #7a8b99;
}

@media (max-width: 768px) {
    .online-teammates-card {
        padding: 12px;
    }

    .online-teammates-actions {
        width: 100%;
    }

    .online-teammates-toolbar {
        width: 100%;
    }

    .online-teammates-action {
        flex: 1 1 auto;
        text-align: center;
    }
}

#modify-server-dialog {
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    width: min(92vw, 560px);
    padding: 22px 22px 18px;
    border: 1px solid rgba(188, 205, 219, 0.72);
    border-radius: 22px;
    background: linear-gradient(180deg, rgba(255, 255, 255, 0.96) 0%, rgba(244, 249, 253, 0.98) 100%);
    box-shadow: 0 28px 60px rgba(54, 79, 101, 0.18);
    backdrop-filter: blur(14px);
    -webkit-backdrop-filter: blur(14px);
    z-index: 10030;
    box-sizing: border-box;
}

#modify-server-dialog h3 {
    margin: 0 0 14px;
    font-size: 20px;
    font-weight: 700;
    color: #22384a;
    letter-spacing: 0.01em;
}

#modify-server-dialog textarea {
    width: 100%;
    min-height: 220px;
    resize: vertical;
    box-sizing: border-box;
    padding: 14px 16px;
    border: 1px solid #d7e3ed;
    border-radius: 16px;
    background: #fbfdff;
    color: #243848;
    font-size: 14px;
    line-height: 1.6;
    font-family: Consolas, Monaco, "Courier New", monospace;
    box-shadow: inset 0 1px 2px rgba(98, 126, 149, 0.06);
    transition: border-color 0.2s ease, box-shadow 0.2s ease, background-color 0.2s ease;
}

#modify-server-dialog textarea:focus {
    outline: none;
    border-color: #8fb8d6;
    background: #ffffff;
    box-shadow: 0 0 0 4px rgba(111, 170, 213, 0.14);
}

#modify-server-dialog .button-container {
    display: flex;
    justify-content: flex-end;
    gap: 10px;
    margin-top: 16px;
    flex-wrap: wrap;
}

#modify-server-dialog .modify-server-close-btn {
    top: 10px;
    right: 10px;
    width: 34px;
    height: 34px;
    font-size: 22px;
    background: rgba(255, 255, 255, 0.72);
}

#modify-server-dialog .button-container button {
    border: 1px solid rgba(170, 192, 208, 0.42);
    border-radius: 999px;
    padding: 10px 18px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    transition: transform 0.18s ease, background-color 0.18s ease, border-color 0.18s ease, color 0.18s ease, box-shadow 0.18s ease;
}

#modify-server-dialog .button-container button:first-child {
    background: #ffffff;
    color: #4e667a;
}

#modify-server-dialog .button-container button:last-child {
    background: linear-gradient(180deg, #ffffff 0%, #e8f3fd 100%);
    color: #1f4f73;
}

#modify-server-dialog .button-container button:hover {
    transform: translateY(-1px);
    border-color: rgba(121, 160, 189, 0.5);
    box-shadow: 0 10px 22px rgba(70, 103, 128, 0.10);
}

#modify-server-dialog .button-container button:first-child:hover {
    background: #f5f9fc;
    color: #294257;
}

#modify-server-dialog .button-container button:last-child:hover {
    background: linear-gradient(180deg, #ffffff 0%, #dceeff 100%);
    color: #133e60;
}

#modify-server-dialog .button-container button:active {
    transform: translateY(0);
}

@media (max-width: 768px) {
    #modify-server-dialog {
        width: min(94vw, 560px);
        padding: 18px 16px 16px;
        border-radius: 18px;
    }

    #modify-server-dialog textarea {
        min-height: 180px;
        font-size: 13px;
    }

    #modify-server-dialog .button-container {
        justify-content: stretch;
    }

    #modify-server-dialog .modify-server-close-btn {
        top: 8px;
        right: 8px;
    }

    #modify-server-dialog .button-container button {
        flex: 1 1 calc(50% - 10px);
        text-align: center;
    }
}

                    `
        }
        w.Header().Set("Content-Type", "text/css")
        fmt.Fprint(w, cssContent)
        }
    }
}
