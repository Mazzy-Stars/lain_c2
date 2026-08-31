
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
    /* 鐠佲晛鍞寸€圭懓鎷伴弮銉ョ箶閸栫儤鎷哄鈩冩殻娑擃亜褰茬憴鍡楀隘 */
}
.container {
    display: flex; /* 娴ｈ法鏁lexbox鐢啫鐪?*/
    width: 100vw; /* 閻栬泛顔愰崳銊ヮ啍鎼达缚璐熺憴鍡楀經鐎硅棄瀹?*/
    height: 100vh; /* 閻栬泛顔愰崳銊╃彯鎼达缚璐熺憴鍡楀經妤傛ê瀹?*/
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
    overflow-x: hidden; /* 闂冨弶顒涢弬鍥х摟閹炬垵鍤弶锟?*/
    top: 0;
    left: 0;
    position: fixed;
    border-radius: 0 10px 10px 0;
    transition: width 0.3s ease-in-out;
    z-index: 999;
}

.sidebar.shrink {
    width: 50px; /* 閺€鍓佺級閸氬骸褰ф穱婵堟殌閸ョ偓鐖ｉ崠锟?*/
}
.sidebar.shrink .sidebar-title {
    color: transparent;     /* 闂呮劘妫岄弬鍥х摟 */
    line-height: 0;         /* 閸樺缂夐弬鍥х摟妤傛ê瀹?*/
    padding-top: 0;         /* 閸樼粯甯€婢舵矮缍戦崘鍛扮珶鐠猴拷 */
    padding-bottom: 0;
    height: 0;              /* 鐠佲晛鍘撶槐鐘荤彯鎼达附鏁圭紓锟?*/
    overflow: hidden;       /* 闂冨弶顒涢崘鍛啇閹炬垵绱?*/
    transition: all 0.2s;   /* 濞ｈ濮炴潻鍥ㄦ诞閸斻劎鏁炬导姘纯娑撴繃绮?*/
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
/* 閸ョ偓鐖ｉ柈銊ュ瀻閿涘牏顑囨稉鈧稉顏勭摟缁楋拷 棣冨弗閿旓拷 棣冩懕 棣冩尠 閳ワ讣绱?*/
.sidebar a span.icon {
    display: inline-block;
    width: 24px;
    text-align: center;
    margin-right: 10px;
    font-size: 18px;
}

/* 閺傚洤鐡ч柈銊ュ瀻 */
.sidebar a span.text {
    display: inline-block;
    transition: opacity 0.3s;
}

/* 閺€鍓佺級閺冨爼娈ｉ挊蹇旀瀮鐎涳拷 */
.sidebar.shrink a span.text {
    opacity: 0;
    width: 0;
    margin: 0;
    overflow: hidden;
}
.sidebar-title {
    font-size: 20px;
    font-weight: bold;
    color: #000;
    text-align: center;
    font-family: 'Arial', sans-serif;
    margin-bottom: 20px !important;
}
.sidebar a i {
    margin-right: 23px; /* 鐠嬪啯鏆ｆ潻娆庨嚋閸婂吋娼垫晶鐐插閹存牕鍣虹亸鎴濇禈閺嶅洤鎷伴弬鍥х摟娑斿妫块惃鍕獩缁傦拷 */
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
    position: relative; /* 娴ｏ拷 .toggle-button 閻╃顕潻娆庨嚋閻栬泛鍘撶槐鐘茬暰娴ｏ拷 */
    margin-left: 155px; /* 鐏炴洖绱戦弮璺烘嫲 sidebar 閸氬本顒?*/
    transition: margin-left 0.3s ease-in-out, width 0.3s ease-in-out;
    width: calc(100% - 180px);
}
.sidebar.shrink ~ .content {
    margin-left: 100px; /* 閺€鍓佺級閺冨墎缂夐崚锟?50px */
    width: calc(100% - 50px);
}
.server-header {
    width: 100%;
    margin-bottom: 16px;
    text-align: center;
}

.server-header h3 {
    margin: 0;
    color: #23435a;
    font-size: 22px;
    letter-spacing: 0.04em;
    text-transform: uppercase;
}

.server-form {
    width: 100%;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 10px;
}

.server-form input,
.server-form select,
.server-form textarea {
    width: 90%;
    margin: 0;
    padding: 10px 12px;
    box-sizing: border-box;
    border: 1px solid #c7d7e2;
    border-radius: 10px;
    background: #f9fcfe;
    color: #26455c;
}

.server-form textarea {
    min-height: 72px;
    resize: vertical;
}

.server-buttons {
    width: 90%;
    margin-top: 4px;
}

.server-buttons button {
    width: 100%;
}
.log {
    height: 200px;
    background-color:rgb(202, 202, 202);
    font-size: 15px;
    box-sizing: border-box;
    overflow: auto; /* 閸忎浇顔忓姘З */
    display: flex;
    flex-direction: column; /* 閺囧瓨鏁兼稉杞扮瑐娑撳鍨庣敮锟?*/
    position: fixed; /* 閸ュ搫鐣炬担宥囩枂 */
    bottom: 0;
    left: 180px; /* 娓氀嗙珶閺嶅繒娈戠€硅棄瀹?*/
    width: 100%; /* 閸忋劌顔旈崙蹇撳箵娓氀嗙珶閺嶅繐顔旀惔锟?*/
    overflow-y: auto;
    padding-left: 5px;
    padding-right: 5px;
    border-radius: 10px; /* 濞ｈ濮為崷鍡氼潡 */
}
#log-content {
    flex: 1; /* 閸楃姵宓侀崜鈺€缍戦惃鍕彯鎼达拷 */
    overflow-y: auto;
    box-sizing: border-box;
}
/* 閼奉亜鐣炬稊澶嬬泊閸斻劍娼弽宄扮础 */
#log-content::-webkit-scrollbar {
    width: 8px; /* 濠婃艾濮╅弶鈥愁啍鎼达拷 */
}

#log-content::-webkit-scrollbar-track {
    background: #f1f1f1; /* 濠婃艾濮╅弶陇寤洪柆鎾瑰剹閺咁垵澹?*/
}

#log-content::-webkit-scrollbar-thumb {
    background: #888; /* 濠婃艾濮╅弶鈩冪拨閸ф鍎楅弲顖濆 */
    border-radius: 10%; /* 濠婃垵娼￠崷鍡氼潡 */
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
    background: #555; /* 濠婃垵娼￠幃顒€浠犻弮鎯板剹閺咁垵澹?*/
}
#log .resize-handle {
    width: 100%;
    height: 10px;
    top: 0px;
    background-color: transparent;
    position: sticky; /* 閸ュ搫鐣?handle 閸︼拷 log 鐎圭懓娅掗惃鍕俺闁拷 */
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
    right: 5px; /* 閹搞劎娼冩潏鍦櫕 */
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
    position: absolute; /* 娴ｈ法鏁ょ紒婵嗩嚠鐎规矮缍?*/
    top: 100px; /* 閸掓繂顫愭担宥囩枂 */
    left: 100px; /* 閸掓繂顫愭担宥囩枂 */
    width: 60%;
    height: 80%;
    border: 1px solid #ccc;
    background: #fff;
    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
    z-index: 1000;
    display: none; /* 姒涙顓婚梾鎰 */
}
.iframe-panel .close-button {
    position: absolute;
    top: 5px;
    right: 5px;
}
.iframe-panel .drag-handle {
    width: 100%;
    height: 30px; /* 閸ュ搫鐣炬妯哄 */
    background-color: #f1f1f1;
    cursor: move;
    position: absolute;
    top: 0;
    left: 0;
    z-index: 1005;
}
.iframe-panel iframe {
    position: absolute;
    top: 30px; /* 闁灝绱?drag-handle */
    width: 100%;
    height: calc(100% - 30px); /* 閸戝繐骞?drag-handle 閻ㄥ嫰鐝惔锟?*/
    border: none;
}
.close-button {
    position: absolute;
    top: 0px;
    height: 23px;
    right: 5px;
    cursor: pointer;
    background-color: #f00; /* 娴ｈ法鏁?background-color 娴狅絾娴?background */
    color: #fff;
    border: none;
    padding: 5px 10px;
    border-radius: 3px; /* 濞ｈ濮為崷鍡氼潡 */
    font-size: 14px; /* 鐠佸墽鐤嗙€涙ぞ缍嬫径褍鐨?*/
    z-index: 1010; /* 绾喕绻?z-index 娑撯偓閼凤拷 */
}
.close-button:hover {
    background-color: #d00; /* 濞ｈ濮為幃顒€浠犻弫鍫熺亯 */
}
.tle-sidebar {
    display: none; /* 閸掓繂顫愰梾鎰 */
}
.tel-toggleBtn {
    display: none; /* 閸掓繂顫愰梾鎰 */
}
/* 娑撹櫣些閸斻劏顔曟径鍥啎缂冿拷 sidebar 閻ㄥ嫬顔旀惔锟?*/
@media (max-width: 768px) {
    .content {
        margin-left: 0; /* 缁夎濮╃粩顖氬絿濞戝牆涔忔笟褔妫跨捄锟?*/
        width: 100%; /* 閸愬懎顔愰崠鍝勵啍鎼达拷 100% */
    }
    .sidebar {
        display: none; /* 娑撹櫣些閸斻劎顏拋鍓х枂鏉堝啰鐛庨惃锟?sidebar */
    }
    .sidebar-title{
        font-size: 16px;
        font-weight: bold;
        margin-bottom: 10px;
        color: #000;
        text-align: center;
        font-family: 'Arial', sans-serif;
        font-style: italic; /* 閺傛粈缍?*/
        text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.3); /* 濞ｈ濮為梼鏉戝 */
        background-color: #fff; /* 鐠佸墽鐤嗛懗灞炬珯妫版粏澹?*/
        padding: 5px; /* 濞ｈ濮為崘鍛扮珶鐠猴拷 */
    }
    .toggle-button{
        display: none;
    }
    .log{
        left: 0px;
        width: 100%; /* 鐠嬪啯鏆ｉ弮銉ョ箶闁劌鍨庨惃鍕啍鎼达拷 */
    }
    .tle-sidebar {
        display: none; /* 閸掓繂顫愰梾鎰 */
        background: #f4f4f4;
        padding: 10px;
        border: 1px solid #ccc;
        width: 200px;
        position: absolute;
        top: 50px;
    }
    .tel-toggleBtn {
        display: block; /* 缁夎濮╃粩顖涙▔缁€鐑樺瘻闁斤拷 */
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
.conn-container {
    display: flex;
    align-items: center;
    justify-content: flex-start; /* 娴ｅ灝鐡欓崗鍐濮樻潙閽╅幒鎺戝灙 */
    border: 1px solid #ccc;
    padding: 7px;
    margin: 5px 0;
    border-radius: 5px;
    background-color: #f9f9f9;
    width: 95%;
    flex-wrap: wrap; /* 閸忎浇顔忕€涙劕鍘撶槐鐘冲床鐞涳拷 */
    min-height: 65px;
}
.conn-container > * {
    /* 绾喕绻氱€涙劕鍘撶槐鐘烩偓鍌氱安閻栬泛顔愰崳銊ヮ啍鎼达拷 */
    max-width: 100%;
    flex-shrink: 0; /* 闂冨弶顒涚€涙劕鍘撶槐鐘插竾缂傦拷 */
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
    /* 闂堢娀銆夐棃銏犲礁鏉堥€涚閻愶拷 */
}


.client-card:hover {
    background:#cdcdcd;
    border-color:#aaa;
}


/* 娣団剝浼?*/
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


/* 閺嶅洨顒?*/
.client-card p span {
    color:#4e9cff;
    font-weight:bold;
    margin-right:5px;
}


/* 閹稿鎸抽崠鍝勭厵 */
.btn-box {

    display:flex;

    gap:8px;

    flex-shrink:0;
}


/* 閹稿鎸?*/
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
.ip-address, .shell-address {
    display: inline-block;
    margin-right: 10px;
    font-size: 1em;
    font-weight: bold;
}
.button-container {
    width: 40%;
}
/* /*濡炲秴鍙嗛悧鈺傜毜濞夆剝鐗卞锟 */
.ip-info {
    display: inline-block;
    background: #fff;
    padding: 10px;
    width: 90%;
    margin: 10px;
    margin-left: 50px;  /* 鐏忓棗鍘撶槐鐘冲腹閸掓澘褰告潏锟?*/
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
/* 鐠侊拷 info-content 閸愬懘鍎撮惃锟?p 閺嶅洨顒烽崣妯诲灇 flex 鐢啫鐪敍灞戒箯閸欏啿顕锟?*/
.info-content p {
    display: flex;
    align-items: flex-start; /* 鐠佲晛涔忔笟褍鎷伴崣鍏呮櫠閸愬懎顔愭稉濠傤嚠姒伙拷 */
    gap: 10px; /* 瀹革箑褰搁崘鍛啇闂傜绐?*/
    margin: 5px 0;
}
/* 缂佺喍绔村锔挎櫠 strong 閻ㄥ嫭鐗卞锟?*/
.s_left {
    font-size: 14px;
    width: 120px; /* 鐠佹儳鐣剧紒鐔剁鐎硅棄瀹抽敍灞肩箽鐠囦礁涔忔笟褍顕锟?*/
    text-align: left;
    flex-shrink: 0; /* 闂冨弶顒涘锔挎櫠閺傚洦婀扮悮顐㈠竾缂傦拷 */
    margin-right: 20px;
}
/* 閸欏厖鏅堕弬鍥ㄦ拱閸滃矁绶崗銉︻攱缂佺喍绔?*/
.s_right {
    font-size: 14px;
    text-align: left;
    word-break: break-all; /* 鐠佲晠鏆遍崘鍛啇閼奉亜濮╅幑銏ｎ攽 */
}
/* 閸欏厖鏅?input 缂佺喍绔撮弽宄扮础 */
input.s_right_input.custom-remarks {
    font-size: 14px;
    height: 20px; /* 鐠佸墽鐤嗛崶鍝勭暰妤傛ê瀹抽敍宀勪缉閸忓秴銇婃锟?*/
    line-height: 20px; /* 绾喕绻氶弬鍥х摟鐏炲懍鑵?*/
    text-align: left;
    background-color: transparent;
    border: none !important; /* 瀵搫鍩楅崢缁樺竴鏉堣顢?*/
    outline: none !important; /* 閸樼粯甯€閼辨氨鍔嶉弮鍓佹畱姒涙顓绘妯瑰瘨 */
    box-shadow: none !important; /* 閸樼粯甯€閸欘垵鍏橀惃鍕帛鐠併倝妲捐ぐ锟?*/
    appearance: none; /* 缁備胶鏁ら弻鎰昂濞村繗顫嶉崳銊╃帛鐠併倖鐗卞锟?*/
    -webkit-appearance: none; /* 閸忕厧顔?Webkit 閸愬懏鐗冲ù蹇氼潔閸ｏ拷 */
    -moz-appearance: none; /* 閸忕厧顔?Firefox */
    padding: 0; /* 闁灝鍘ゆ０婵嗩樆閻ㄥ嫬鍞存潏纭呯獩閹炬垿鐝潏鎾冲弳濡楋拷 */
}                             
/* 閺勫墽銇氶弮鍓佹畱閺嶅嘲绱?*/
.info-content.show {
    display: block;
}
.choose-content {
    display: none;              /* 閸掓繂顫愰梾鎰 */
    flex-wrap: wrap;            /* 鐎涙劙銆嶉懛顏勫З閹广垼顢?*/
    gap: 8px;

    margin-top: 10px;
    padding: 10px;
    background-color: #f0f0f0;
    border-radius: 5px;
    max-width: 100%;

    box-sizing: border-box;
    overflow-x: hidden;
}

/* 閺勫墽銇氶弮鍓佹畱缁拷 */
.choose-content.show {
    display: flex;
}
@media (max-width: 768px) {
    .s_left {
        font-size: 12px; /* 鐠嬪啯鏆ｅ锔挎櫠鐎涙ぞ缍嬫径褍鐨?*/
        width: auto; /* 鐎硅棄瀹抽懛顏堚偓鍌氱安 */
        margin-right: 10px; /* 缂傗晛鐨崣鍏呮櫠闂傜绐?*/
    }

    .s_right {
        font-size: 12px; /* 鐠嬪啯鏆ｉ崣鍏呮櫠閺傚洦婀版径褍鐨?*/
        margin-left: 0; /* 閸樼粯甯€瀹革缚鏅堕梻纾嬬獩 */
    }

    input.s_right_input.custom-remarks {
        font-size: 14px; /* 鐠嬪啯鏆ｆ潏鎾冲弳濡楀棙鏋冪€涙銇囩亸锟?*/
        height: 15px; /* 鐠嬪啯鏆ｆ妯哄闁倸绨查幍瀣簚 */
        line-height: 30px; /* 绾喕绻氶弬鍥х摟鐏炲懍鑵?*/
        padding-left: 5px; /* 濞ｈ濮炲锕€鍞存潏纭呯獩 */
    }

    .info-content {
        padding: 8px; /* 閹靛婧€缁旑垵鐨熼弫鏉戝敶鏉堢绐?*/
    }
}

/* 閺囨潙鐨惃鍕閺堣櫣顏柅鍌炲帳 */
@media (max-width: 480px) {
    .s_left {
        font-size: 10px; /* 閺囨潙鐨惃鍕摟娴ｏ拷 */
    }

    .s_right {
        font-size: 10px; /* 閺囨潙鐨惃鍕摟娴ｏ拷 */
    }

    input.s_right_input.custom-remarks {
        font-size: 10px; /* 閺囨潙鐨惃鍕摟娴ｏ拷 */
        height: 28px; /* 鐠嬪啯鏆ｆ妯哄 */
        line-height: 28px; /* 绾喕绻氶弬鍥х摟鐏炲懍鑵?*/
    }
}
.ip-address, .console-link {
    margin-right: 3.5px; /* 閸忓啰绀屾稊瀣？閻ㄥ嫰妫块梾锟?*/
    white-space: nowrap;  /*闂冨弶顒涢幑銏ｎ攽 */
    border: none; /* 閸樼粯甯€鏉堣顢?*/
}
.ip-address {
    font-size: 12px;
    color: #555;
    margin-right: 8px;
}
.console-link {
    justify-content: center;
    gap: 25px; /* 閹稿鎸虫稊瀣？閻ㄥ嫰妫跨捄锟?*/
    text-decoration: none; /* 閸樼粯甯€娑撳鍨濈痪锟?*/
    color: #007BFF; /* 鐠佸墽鐤嗛柧鐐复妫版粏澹?*/
    font-size: 12px; /* 鐠佸墽鐤嗙€涙ぞ缍嬫径褍鐨?*/
    margin-left: 5px; /* 鐠佸墽鐤嗘稉搴″娑撯偓娑擃亜鍘撶槐鐘垫畱闂傛挳娈?*/
    border: none; /* 閸樼粯甯€鏉堣顢?*/
    padding: 8px 15px; /* 鐠佸墽鐤嗛崘鍛扮珶鐠猴拷 */
    border-radius: 4px; /* 鐠佸墽鐤嗘潏瑙勵攱閸﹀棜顫?*/
    background-color: #f8f9fa; /* 鐠佸墽鐤嗛懗灞炬珯妫版粏澹?*/
    transition: background-color 0.3s, color 0.3s; /* 楠炶櫕绮︽潻鍥ㄦ诞閺佸牊鐏?*/
    cursor: pointer; /* 姒х姵鐖ｉ幃顒€浠犻弮鑸垫▔缁€鐑樺瑜般垹娴橀弽锟?*/
    outline: none; /* 閻愮懓鍤弮鏈电瑝閺勫墽銇氭潪顔肩波 */
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1); /* 濞ｈ濮為梼鏉戝閺佸牊鐏?*/
}
.console-link:hover,
.console-link:focus {
    background-color: #0069d9; /* 姒х姵鐖ｉ幃顒€浠犻幋鏍粵閻掞附妞傞惃鍕剹閺咁垶顤侀懝锟?*/
    color: white; /* 閺傚洤鐡ф０婊嗗 */
    text-decoration: none; /* 姒х姵鐖ｉ幃顒€浠犻弮鏈电瑝閺勫墽銇氭稉瀣灊缁撅拷 */
    }
.console-link:active {
    background-color: #0062cc; /* 姒х姵鐖ｉ幐澶夌瑓閺冨墎娈戦懗灞炬珯妫版粏澹?*/
    box-shadow: none; /* 缁夊娅庨梼鏉戝 */
}
.form-in {
    background-color: #ffffff;
    padding: 30px;
    border-radius: 10px;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
    width: 300px;
    height: auto;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
}
.form-in input[type="text"],
.form-in input[type="password"] {
    width: 100%;
    padding: 10px;
    margin: 10px 0;
    border-radius: 5px;
    border: 1px solid #ccc;
    font-size: 16px;
    box-sizing: border-box;
}
.form-in button {
    width: 100%;
    padding: 10px;
    background-color: #ffaec6;
    color: white;
    border: none;
    border-radius: 5px;
    font-size: 16px;
    cursor: pointer;
    margin-top: 10px;
    transition: background-color 0.3s ease;
}
.form-in button:hover {
    background-color: #ff75ba;
}
.form-in h1 {
    font-size: 24px;
    margin-bottom: 20px;
    color: #333;
}
.form {
    background: #fff;
    padding: 10px;
    width: 100%;
    border-radius: 8px;
    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
    display: flex;
    flex-direction: row; /* 濡亜鎮滈幒鎺戝灙 */
    gap: 15px; /* 閸忓啰绀屾稊瀣？閻ㄥ嫰妫跨捄锟?*/
    align-items: center; /* 閸忓啰绀岄崹鍌滄纯鐏炲懍鑵?*/
}input[type="text"] {
    width: 45%; /* 鏉堟挸鍙嗗鍡楊啍鎼达箒鐨熼弫锟?*/
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
    width: 25%; /* 娑撳濯洪懣婊冨礋鐎硅棄瀹崇拫鍐╂殻 */
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
/* 娑撹櫣些閸斻劏顔曟径鍥啎缂冿拷 sidebar 閻ㄥ嫬顔旀惔锟?*/
@media (max-width: 768px) {
    .ip-info {
        max-width: 400px; /* 鐠侊拷 ip-info 閸︺劎些閸斻劎顏繅顐ｅ姬閺佺繝閲滅仦蹇撶 */
        margin: 0;
    }
    .conn-container {
        flex-direction: row; /* 绾喕绻氱€涙劕鍘撶槐鐘叉躬娑撯偓鐞涘苯鍞?*/
        flex-wrap: wrap; /* 閸忎浇顔忛幑銏ｎ攽 */
        max-width: 100%; /* 闂冨弶顒涚搾鍛毉 */
        overflow: hidden; /* 闁灝鍘ゅ┃銏犲毉 */
        background-color: #f9f9f9;
    }
    .os-container {
        display: flex;
        align-items: center;
        padding: 10px;
        background-color: #f9f9f9;
        margin-left: 0; /* 閸欐牗绉烽懛顏勫З閹恒劌鍩岄崣鍏呮櫠 */
    }                    
}
#net {
    width: 100%;
    box-sizing: border-box;
    padding: 0 20px 20px;
}
.net_div {
    height: 20%;
    width: 100%;
    margin: 0 auto;
    border-radius: 14px;
    box-sizing: border-box;
    padding: 12px;
}
.net_scan{
    display: flex;
    gap: 10px;
    margin: 0 auto 14px;
    width: 100%;
    align-items: center;
    flex-wrap: wrap;
}
.net_scan select,
.net_scan input,
.net_scan button,
#net_uid {
    min-height: 40px;
    box-sizing: border-box;
}
.net_scan select,
.net_scan input {
    flex: 1 1 180px;
    padding: 0 12px;
    border: 1px solid #cfd9e2;
    border-radius: 10px;
    background: #fff;
}
.net_scan button {
    padding: 0 18px;
    border-radius: 10px;
    border: none;
    background: linear-gradient(135deg, #2f7fb4 0%, #1d5f8d 100%);
    color: #fff;
    font-weight: 600;
}
.net_scan button:hover {
    background: linear-gradient(135deg, #2a73a3 0%, #184f75 100%);
}
#net_uid {
    display: flex;
    align-items: center;
    padding: 8px 12px;
    border-radius: 10px;
    background: #eef4f8;
    color: #355066;
    flex: 1 1 180px;
}
.net_div_son {
    background-color: #f9f9f9; /* 濞村懐浼嗛懝鑼跺剹閺咃拷 */
    border: 1px solid #ddd; /* 鏉炶浜曢惃鍕珶濡楋拷 */
    border-radius: 5px; /* 閸﹀棜顫楁潏瑙勵攱 */
    box-shadow: 0 2px 4px rgba(0,0,0,0.1); /* 鏉炶浜曢惃鍕Ь瑜版唻绱濇晶鐐插鐏炲倹顐奸幇锟?*/
    padding: 15px; /* 閸愬懓绔熺捄锟?*/
    margin-bottom: 10px; /* 娑撳簼绗呮稉鈧稉顏勫帗缁辩姷娈戦梻纾嬬獩 */
    transition: transform 0.3s ease, box-shadow 0.3s ease; /* 閸斻劍鈧焦鏅ラ弸锟?*/
}
.net_div_son:hover {
    transform: translateY(-3px); /* 姒х姵鐖ｉ幃顒€浠犻弮鎯颁氦瀵邦喕绗傜粔锟?*/
    box-shadow: 0 4px 8px rgba(0,0,0,0.2); /* 姒х姵鐖ｉ幃顒€浠犻弮鑸垫纯濞ｈ京娈戦梼鏉戝 */
}
.net_div_son strong {
    color: #333; /* 瀵缚鐨熼弬鍥х摟妫版粏澹?*/
    margin-right: 5px; /* 娑撳骸鍞寸€瑰湱娈戦梻纾嬬獩 */
}
.net_div_son hr {
    border: 0; /* 缁夊娅庢潏瑙勵攱 */
    height: 1px; /* 妤傛ê瀹?*/
    background-color: #eaeaea; /* 妫版粏澹?*/
    margin: 10px 0; /* 娑撳骸鍞寸€瑰湱娈戦梻纾嬬獩 */
}
.net_div_son button {
    margin-left: auto; /* 閹稿鎸抽棃鐘插礁 */
    min-height: 60%;
}
#have_ip {
    display: flex; /* 鐠佸墽鐤嗘稉绡簂ex鐢啫鐪?*/
    flex-wrap: wrap; /* 閸忎浇顔忕€涙劕鍘撶槐鐘哄殰閸斻劍宕茬悰锟?*/
    gap: 10px; /* 鐠佸墽鐤嗙€涙劕鍘撶槐鐘辩闂傚娈戦梻纾嬬獩 */
    margin-top: 10px; /* 娑撳酣鈧瀚ㄥ鍡欐畱闂傜绐?*/
    font-family: 'Arial', sans-serif; /* 鐠佸墽鐤嗙€涙ぞ缍?*/
    margin-left: 0;
}
#have_ip div {
    background-color: #f0f0f0; /* 濞村懐浼嗛懝鑼跺剹閺咃拷 */
    border: 1px solid #ddd; /* 鏉堣顢嬫０婊嗗 */
    border-radius: 4px; /* 閸﹀棜顫楁潏瑙勵攱 */
    padding: 5px 10px; /* 閸愬懓绔熺捄锟?*/
    display: inline-block; /* 閸愬懓浠堥崸妤冮獓閸忓啰绀?*/
}
#have_ip div:hover {
    background-color: #e0e0e0; /* 姒х姵鐖ｉ幃顒€浠犻弮鍓佹畱閼冲本娅欐０婊嗗 */
    cursor: pointer; /* 姒х姵鐖ｉ幃顒€浠犻弮鍓佹畱閸忓鐖ｉ弽宄扮础 */
}
@media (max-width: 768px) {
    #net {
        padding: 0 12px 16px;
    }
    .net_scan {
        flex-direction: column;
        align-items: stretch;
        gap: 12px;
        margin-bottom: 12px;
    }
    .net_scan select,
    .net_scan input,
    .net_scan button,
    #net_uid {
        width: 100%;
        flex: none;
    }
    .net_div {
        padding: 10px;
        border-radius: 12px;
    }
    #have_ip {
        gap: 8px;
    }
}
.file-dialog .file-history{
    width: 20%;
    min-width: 80px;
    max-width: 80vw;
    min-height: 0;
    height: 100%;
    overflow-y: auto;
    overflow-x: hidden;
    overscroll-behavior: contain;
    -webkit-overflow-scrolling: touch;
    font-size: 14px;
    color: #555;
    transition: width 0.1s;
}
.file-dialog #file-drag-bar {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 32px;
    cursor: move;
    background: rgba(0,0,0,0.05);
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    z-index: 10001;
}
.file-dialog .file-dialog-layout {
    display: flex;
    width: 100%;
    margin-top: 32px;
    position: relative;
    height: calc(90vh - 48px);
    overflow: hidden;
}
.file-dialog #file-history-resizer {
    min-width: 6px;
    cursor: col-resize;
    background: #e0e0e0;
    z-index: 10;
}
.file-dialog .file-dialog-toolbar-row {
    display: flex;
    align-items: center;
}
.file-dialog #file-dialog-hostname {
    margin-right: 25px;
}
.file-dialog .history-item {
    padding: 8px;
    border-bottom: 1px solid #eee;
    cursor: pointer;
    height: 45px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    transition: background-color 0.3s;
}
.file-dialog .history-item:hover {
    background-color: #f0f0f0;
}
.file-dialog .history-item-label {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}
.file-dialog .history-delete-btn {
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
.file-dialog .history-delete-btn:hover {
    background: rgba(204, 90, 90, 0.08);
    color: #a93f3f;
}
.file-dialog .filecontainer {
    width: 100%;
    margin: 0;
    padding: 15px;
    background-color: white;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    height: 92%;
    overflow-y: auto;
}
.file-dialog .file-manager {
    display: flex;
    flex-direction: column;
    flex-wrap: nowrap;
    justify-content: flex-start;
    align-items: stretch;
    gap: 6px;
    margin-top: 12px;
    width: 100%;
    min-height: 20px;
    overflow-x: hidden;
}
.file-dialog .directory,
.file-dialog .file {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 12px;
    width: 100%;
    max-width: 100%;
    line-height: 1.2;
    background: linear-gradient(180deg, #ffffff 0%, #f8fbfd 100%);
    border: 1px solid #d8e1e8;
    border-radius: 10px;
    cursor: pointer;
    text-decoration: none;
    color: inherit;
    box-sizing: border-box;
    transition: background-color 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
}
.file-dialog .directory > *,
.file-dialog .file > * {
    flex-shrink: 0;
}
.file-dialog .filename {
    flex: 1 1 auto;
    min-width: 0;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}
.file-dialog .filesize,
.file-dialog .fileperm,
.file-dialog .filetime {
    font-size: 12px;
    color: #666;
    white-space: nowrap;
}
.file-dialog .directory:hover,
.file-dialog .file:hover {
    background: linear-gradient(180deg, #ffffff 0%, #f2f7fb 100%);
    border-color: #bfd0dd;
    box-shadow: 0 6px 16px rgba(56, 82, 104, 0.08);
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
.file-dialog .icon {
    font-size: 1.1em;
    margin-right: 4px;
    color: #555;
}
.file-dialog .icon-download {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-size: 14px;
    line-height: 1;
}
.file-dialog .rename-btn,
.file-dialog .time-btn {
    margin-left: 0;
    padding: 2px 6px;
    font-size: 12px;
    line-height: 1;
    border: 1px solid #d6dbe1;
    background: #fff;
    border-radius: 6px;
    box-shadow: none;
}
.file-dialog .dir-btn {
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
.file-dialog .dir-btn:hover {
    background-color: #0056b3;
}
.file-dialog .dir-btn:active {
    background-color: #004085;
    transform: translateY(2px);
}
.file-dialog #cur_dir {
    background-color: #f9f9f9;
    border: 1px solid #e1e4e8;
    border-radius: 8px;
    padding: 15px 20px;
    margin: 20px 0;
    font-size: 16px;
}
.file-dialog #cur_dir_p{
    margin-right: 2%;
}
.file-dialog #uploadForm {
    margin-bottom: 20px;
    justify-content: center;
    align-items: center;
    display: flex;
    flex-direction: column;  /* 閸ㄥ倻娲块幒鎺戝灙 */
    gap: 10px;
}
.file-dialog .fileinput{
    padding: 10px;
    border: 1px solid #ccc;
    border-radius: 5px;
    cursor: pointer;
}
.file-dialog #uploadForm input[type="submit"] {
    padding: 10px 20px;
    font-size: 1em;
    color: #fff;
    background-color: #007bff;
    border: none;
    border-radius: 5px;
    cursor: pointer;
    transition: background-color 0.3s;
}
.file-dialog #uploadForm input[type="submit"]:hover {
    background-color: #0056b3;
}
.file-dialog #uploadForm input[type="submit"]:active {
    background-color: #004085;
    transform: translateY(2px);
}
.file-dialog .dir-controls {
    display: flex;       /* 娴ｈ法鏁lex鐢啫鐪?*/
    align-items: center; /* 閸ㄥ倻娲跨仦鍛厬鐎靛綊缍堢€涙劕鍘撶槐锟?*/
    margin-top: 20px;   /* 閺嶈宓侀棁鈧憰浣界殶閺佺繝绗傛潏纭呯獩 */
}
    /* 鏉堟挸鍙嗗鍡樼壉瀵拷 */
.file-dialog #directoryInput {
    padding: 10px;
    border: 1px solid #ccc;
    border-radius: 5px;
    font-size: 16px;
    margin-right: 10px; /* 娑撳孩瀵滈柦顔荤箽閹镐線妫跨捄锟?*/
    width: 200px; /* 鐠佸墽鐤嗘稉鈧稉顏勬値闁倻娈戠€硅棄瀹?*/
    transition: border-color 0.3s, box-shadow 0.3s;
}
.file-dialog #directoryInput:focus {
    border-color: #007bff;
    box-shadow: 0 0 8px rgba(0, 123, 255, 0.2);
    outline: none; /* 缁夊娅庢妯款吇閻ㄥ嫮鍔嶉悙纭呯枂瀵わ拷 */
}
/* 閹稿鎸抽弽宄扮础 */
.file-dialog #moveDirButton {
    padding: 10px 20px;
    font-size: 16px;
    color: #fff;
    background-color: #007bff;
    border: none;
    border-radius: 5px;
    cursor: pointer;
    transition: background-color 0.3s, transform 0.3s;
}
.file-dialog #moveDirButton:hover {
    background-color: #0056b3;
}
.file-dialog #moveDirButton:active {
    background-color: #004085;
    transform: translateY(2px);
}
/* 閸濆秴绨插蹇氼啎鐠侊拷 */
@media (max-width: 768px) {
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
    display: flex; /* 娴ｈ法鏁?flexbox 鐢啫鐪?*/
    align-items: center; /* 閸ㄥ倻娲跨仦鍛厬鐎靛綊缍?*/
    top: 0;
}
.msg-item {
    background: white;
    border: 1px solid #ccc;
    padding: 10px;
    margin-bottom: 8px;
    position: relative;
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 8px;
}
.msg-dialog #msg-drag-bar {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 32px;
    cursor: move;
    background: rgba(0,0,0,0.05);
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    z-index: 10001;
    touch-action: none;
}
.msg-dialog .msg-dialog-header {
    display: flex;
    align-items: center;
    margin-top: 32px;
}
.msg-dialog .msg-dialog-hostname {
    margin-left: 25px;
}
.msg-item-main {
    display: flex;
    align-items: center;
    gap: 8px;
    flex: 1;
    min-width: 0;
}
.msg-item-text {
    display: block;
    min-width: 0;
    flex: 1;
    word-break: break-word;
    overflow-wrap: anywhere;
}
.msg-item span {
    user-select: none;
}
.msg-item span[title] {
    color: blue;
    text-decoration: underline dotted;
}
.msg-item-dragging {
    opacity: 0.92;
    box-shadow: 0 14px 32px rgba(0,0,0,0.14);
    z-index: 10020;
}
.msg-drag-handle {
    margin-right: 6px;
    padding: 2px 6px;
    border: 1px solid #d7dde5;
    background: #f7f9fc;
    border-radius: 8px;
    cursor: grab;
    touch-action: none;
    color: #6b7b8b;
}
.msg-drag-handle:active {
    cursor: grabbing;
}
.msg-drop-placeholder {
    border: 1px dashed #9eb3c7;
    border-radius: 10px;
    margin-bottom: 8px;
    background: rgba(228,236,245,0.45);
}
.msg-item-actions {
    position: absolute;
    right: 10px;
    top: 10px;
    display: flex;
    gap: 4px;
}
.msg-action-btn {
    margin-left: 5px;
    padding: 4px 6px;
    font-size: 14px;
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
.chat {
    width: 100%;
    height: 100%;            /* 閸楃姵寮ч弫缈犻嚋閸欘垵顫嬫妯哄 */
    box-sizing: border-box;
}
.chat_container {
    margin: 0 auto;
    width: 65%;
    max-height: 80vh; /* 閻ｆ瑥鍤潏鎾冲弳濡楀棝鐝惔锟?闂傜绐?*/
    padding: 10px;
    box-sizing: border-box;
    display: flex;
    flex-direction: column;
    overflow-y: auto;  /* 閸愬懎顔愭径姘啊濠婃艾濮?*/
}
/* 鏉堟挸鍙嗗鍡楊啇閸ｏ拷 */
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

/* 鏉堟挸鍙嗗锟?*/
.chat_input {
    flex: 1;
    border: none;
    font-size: 14px;
    outline: none;
    margin: 0 5px;
}

/* 瀹革箑褰搁幐澶愭尦 */
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

/* 閸忣剙鍙″鏃€鍦洪弽宄扮础 */
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
    margin: 6px 0;             /* 娑撳﹣绗呴梻纾嬬獩 */
    align-self: flex-start;     /* 姒涙顓婚棃鐘蹭箯 */
}

/* 閼奉亜绻侀崣鎴︹偓浣烘畱濞戝牊浼呴棃鐘插礁 */
.chat_message.me {
    background: #DCF2FF;
    border-color: #c8e6ff;
    text-align: right;
    align-self: flex-end;       /* 闂堢姴褰?*/
}
/* 閻劍鍩涢崥锟?*/
.chat_message strong {
    display: block;
    margin-bottom: 4px;
    font-weight: 600;
    color: #333;
}
.chat_message.me strong {
    color: #2A7FD6;
}

/* 濞戝牊浼呴弬鍥ㄦ拱 */
.chat_message span,
.chat_message div,
.chat_message p {
    word-break: break-word;
    white-space: pre-wrap;
    margin: 0;
}

/* 閺冨爼妫块幋锟?*/
.chat_time {
    margin-top: 6px;
    color: #999;
    font-size: 12px;
    text-align: right;
}

/* 閺傚洣娆㈤柧鐐复 */
.chat_message a {
    color: #007BFF;
    text-decoration: none;
}

.chat_message a:hover {
    text-decoration: underline;
}

/* 姒х姵鐖ｉ幃顒佽癁閻ｃ儱浜曟妯瑰瘨 */
.chat_message:hover {
    box-shadow: 0 2px 6px rgba(0,0,0,0.12);
}

/* 闁鑵戦弬鍥ㄦ拱妤傛ü瀵?*/
.chat_message::selection {
    background: rgba(0, 120, 215, 0.3);
}
@media (max-width: 768px) {
    .chat {
        display: flex;
        flex-direction: column;
        gap: 10px;
        padding: 0 10px 12px;
        box-sizing: border-box;
    }

    .chat_container {
        width: 100%;
        max-width: none;
        max-height: calc(100vh - 220px);
        padding: 8px;
        gap: 8px;
    }

    .chat_input_wrapper {
        left: auto;
        bottom: auto;
        width: 100%;
        margin: 0;
        padding: 8px 10px;
        border-radius: 16px;
    }

    .chat_input {
        font-size: 16px;
        margin: 0 6px;
    }

    .chat_icon_left,
    .chat_icon_right {
        font-size: 14px;
        padding: 4px 8px;
    }

    .chat_message {
        max-width: 88%;
        min-width: 0;
        padding: 8px 10px;
        font-size: 13px;
        line-height: 1.35;
    }

    .chat_time {
        font-size: 11px;
    }

    .pending_file_preview {
        font-size: 13px;
        padding: 5px 8px;
    }
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

/* plugin dialog */

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
    .plugin-dialog-header h3 {
        font-size: 18px;
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

@media (max-width: 768px) {
    .floating-dialog {
        width: 94vw !important;
        max-width: 94vw !important;
        max-height: 92vh !important;
        border-radius: 22px !important;
        padding: 14px 12px 16px !important;
        box-sizing: border-box;
        overflow-x: hidden !important;
    }

    .terminal-dialog {
        min-height: 78vh;
    }

    .terminal-dialog-toolbar {
        flex-direction: column;
        align-items: stretch !important;
        gap: 10px !important;
        padding: 10px 2px 14px !important;
    }

    .terminal-dialog .terminal-shell-select {
        width: 100%;
        min-width: 0 !important;
    }

    .terminal-dialog .terminal-hostname {
        margin-left: 0 !important;
        width: 100%;
        text-align: left;
    }

    .terminal-dialog .terminal {
        min-height: 56vh !important;
        height: 60vh !important;
        padding: 12px !important;
        border-radius: 16px !important;
    }

    .file-dialog {
        height: 92vh !important;
        padding-bottom: 12px !important;
    }

    .file-dialog .file-dialog-layout {
        flex-direction: column;
        height: calc(92vh - 56px) !important;
        overflow: hidden;
    }

    .file-dialog #file-history-resizer {
        display: none;
    }

    .file-dialog .file-history {
        width: 100% !important;
        min-width: 0 !important;
        max-width: none !important;
        max-height: 132px;
        min-height: 0;
        overflow-y: auto;
        overflow-x: hidden;
        margin-right: 0;
        margin-bottom: 10px;
        padding-right: 0;
        border-right: none;
        border-bottom: 1px solid #e6edf3;
        background: linear-gradient(180deg, #fbfdff 0%, #f4f8fb 100%);
    }

    .file-dialog .filecontainer {
        width: 91% !important;
        height: auto;
        flex: 1 1 auto;
        border-radius: 18px 18px 0 0;
        box-shadow: none;
    }

    .file-dialog .file-dialog-toolbar-row {
        flex-direction: column;
        align-items: stretch !important;
        gap: 8px;
    }

    .file-dialog #file-dialog-hostname {
        margin-right: 0 !important;
    }

    .file-dialog #splitSize,
    .file-dialog #directoryInput,
    .file-dialog #moveDirButton,
    .file-dialog #uploadFile,
    .file-dialog .fileinput {
        width: 100%;
        box-sizing: border-box;
    }

    .file-dialog .dir-controls {
        flex-direction: column;
        align-items: stretch;
    }

    .file-dialog .file-manager {
        margin-top: 12px;
        gap: 8px;
        width: 100%;
    }

    .file-dialog .directory,
    .file-dialog .file {
        width: 100% !important;
        max-width: 100% !important;
        padding: 5px 8px !important;
        gap: 5px !important;
        align-items: flex-start;
        flex-wrap: wrap;
        line-height: 1.15;
        font-size: 11px;
    }

    .file-dialog .icon,
    .file-dialog .icon-file,
    .file-dialog .icon-download {
        font-size: 12px !important;
        margin-right: 0 !important;
    }

    .file-dialog .filename {
        flex: 1 1 calc(100% - 24px);
        min-width: 0;
        white-space: normal;
        word-break: break-all;
        overflow: hidden;
        text-overflow: unset;
        font-size: 11px;
    }

    .file-dialog .filesize,
    .file-dialog .fileperm,
    .file-dialog .filetime {
        font-size: 10px;
        line-height: 1.1;
        white-space: normal;
        word-break: break-all;
        color: #708090;
    }

    .file-dialog .rename-btn,
    .file-dialog .time-btn {
        padding: 1px 5px !important;
        font-size: 10px !important;
        line-height: 1 !important;
        min-height: 20px;
        border-radius: 5px;
    }

    .msg-dialog {
        width: 94vw !important;
        max-width: 680px !important;
        max-height: calc(100dvh - 20px) !important;
        padding: 14px 10px 18px !important;
        background: linear-gradient(180deg, #fbfdff 0%, #f4f7fb 100%) !important;
        border: 1px solid rgba(148, 168, 186, 0.24) !important;
        box-shadow: 0 18px 42px rgba(41, 61, 80, 0.18) !important;
        overflow-y: auto !important;
        -webkit-overflow-scrolling: touch;
        overscroll-behavior: contain;
    }

    .msg-dialog .msg-dialog-header {
        flex-direction: column;
        align-items: flex-start !important;
        gap: 6px;
        margin-top: 34px !important;
        padding: 0 6px 12px;
    }

    .msg-dialog .msg-dialog-title {
        margin: 0;
        font-size: 20px;
        line-height: 1.1;
        letter-spacing: 0.01em;
        color: #26384a;
    }

    .msg-dialog .msg-dialog-hostname {
        margin: 0 !important;
        font-size: 12px;
        line-height: 1.4;
        color: #708396;
        word-break: break-all;
    }

    .msg-dialog .msg-dialog-body {
        padding: 0 2px 8px;
    }

    .msg-dialog .msg-request-list,
    .msg-dialog .msg-result-list {
        display: flex;
        flex-direction: column;
        gap: 10px;
    }

    .msg-dialog .msg-result-title {
        margin: 16px 6px 10px;
        font-size: 13px;
        font-weight: 700;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        color: #6f8294;
    }

    .msg-dialog .msg-item {
        margin-bottom: 0 !important;
        padding: 12px 12px 48px !important;
        border: 1px solid rgba(160, 179, 194, 0.26) !important;
        border-radius: 18px;
        background: linear-gradient(180deg, rgba(255,255,255,0.98) 0%, rgba(247,250,253,0.96) 100%);
        box-shadow: 0 10px 24px rgba(67, 90, 111, 0.08);
        overflow: hidden;
    }

    .msg-dialog .msg-item-main {
        align-items: flex-start !important;
        gap: 8px !important;
        width: 100%;
        min-width: 0;
    }

    .msg-dialog .msg-index {
        flex-shrink: 0;
        padding-top: 2px;
        font-size: 12px;
        color: #8294a5;
    }

    .msg-dialog .msg-item-text {
        display: block;
        min-width: 0;
        line-height: 1.5;
        color: #233445;
        word-break: break-word;
        overflow-wrap: anywhere;
    }

    .msg-dialog .msg-item-actions {
        position: absolute;
        right: 10px;
        bottom: 10px;
        top: auto !important;
        gap: 8px !important;
    }

    .msg-dialog .msg-action-btn,
    .msg-dialog .msg-drag-handle {
        min-width: 34px;
        min-height: 34px;
        border-radius: 999px;
        border: 1px solid rgba(154, 173, 188, 0.34);
        background: rgba(255, 255, 255, 0.94);
        box-shadow: 0 4px 10px rgba(65, 86, 103, 0.08);
        margin-right: 2px;
        padding: 2px 10px;
        color: #607488;
    }
}

@media (max-width: 480px) {
    .floating-dialog {
        width: 96vw !important;
        max-width: 96vw !important;
        max-height: 94vh !important;
        border-radius: 20px !important;
        padding: 12px 8px 14px !important;
    }

    .terminal-dialog .terminal {
        min-height: 52vh !important;
        height: 58vh !important;
    }

    .file-dialog .file-history {
        max-height: 112px;
    }

    .msg-dialog .msg-dialog-title {
        font-size: 18px;
    }

    .msg-dialog .msg-item {
        padding: 11px 10px 46px !important;
        border-radius: 16px;
    }
}

.server-page {
    padding: 24px 24px 40px;
    min-height: 100%;
    box-sizing: border-box;
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
    min-height: 38px;
    padding: 9px 16px;
    background: linear-gradient(180deg, #ffffff 0%, #f4f8fb 100%);
    color: #2e536f;
    border-radius: 999px;
    font-size: 13px;
    font-weight: 600;
    line-height: 1;
    letter-spacing: 0.01em;
    cursor: pointer;
    box-shadow: 0 5px 14px rgba(63, 93, 116, 0.08);
    transition: background 0.2s ease, border-color 0.2s ease, color 0.2s ease, transform 0.2s ease, box-shadow 0.2s ease;
}

.online-teammates-action:hover {
    background: linear-gradient(180deg, #ffffff 0%, #eaf3f9 100%);
    border-color: #aac0d4;
    color: #183b56;
    transform: translateY(-1px);
    box-shadow: 0 8px 18px rgba(63, 93, 116, 0.13);
}

.online-teammates-action:active {
    transform: translateY(0);
    box-shadow: 0 4px 10px rgba(63, 93, 116, 0.08);
}

.online-teammates-action-strong {
    background: linear-gradient(180deg, #ffffff 0%, #eaf4ff 100%);
    border-color: #b8d3ea;
    color: #18486a;
}

.online-teammates-toolbar .online-teammates-action:nth-child(2),
.online-teammates-toolbar .online-teammates-action:nth-child(3) {
    background: linear-gradient(180deg, #f9fcff 0%, #edf5fa 100%);
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

    #modify-server-dialog .button-container button {
        flex: 1 1 calc(50% - 10px);
        text-align: center;
    }
}

.serverDialog {
    position: fixed;
    top: 50% !important;
    left: 50% !important;
    transform: translate(-50%, -50%) !important;
    margin: 0 !important;
    z-index: 9999;
    width: min(720px, calc(100vw - 40px));
    max-width: calc(100vw - 40px);
    max-height: min(80vh, 760px);
    box-sizing: border-box;
    overflow: auto;
    display: flex;
    flex-direction: column;
    align-items: stretch;
    background: linear-gradient(180deg, #ffffff 0%, #f7fbfd 100%) !important;
    border: 1px solid #cfdde7 !important;
    border-radius: 18px !important;
    padding: 22px 24px 28px !important;
    box-shadow: 0 18px 48px rgba(53, 83, 102, 0.22) !important;
}

.serverDialog input,
.serverDialog select,
.serverDialog textarea,
.serverDialog button {
    font-size: 14px;
}

.serverDialog .close-x,
#modify-server-dialog .close-x {
    position: absolute !important;
    top: 8px !important;
    right: 10px !important;
    width: 32px !important;
    height: 32px !important;
    padding: 0 !important;
    border: 1px solid transparent !important;
    border-radius: 999px !important;
    background: transparent !important;
    color: #667b8c !important;
    font-size: 22px !important;
    font-weight: 500 !important;
    line-height: 30px !important;
    text-align: center;
    cursor: pointer;
    transition: background-color 0.2s ease, border-color 0.2s ease, color 0.2s ease, transform 0.2s ease;
}

.serverDialog .close-x:hover,
#modify-server-dialog .close-x:hover {
    background: #e7f1f7 !important;
    border-color: #c9dce8 !important;
    color: #294b63 !important;
    transform: rotate(90deg);
}

.serverDialog .close-x:active,
#modify-server-dialog .close-x:active {
    background: #dbeaf2 !important;
    transform: rotate(90deg) scale(0.96);
}

#addUserDialog,
#whitelistDialog {
    width: min(440px, calc(100vw - 40px));
    max-width: calc(100vw - 40px);
}

#addUserDialog .server-dialog,
#whitelistDialog .server-dialog {
    width: 100%;
    box-sizing: border-box;
}

#addUserDialog .server-form,
#whitelistDialog .server-form {
    width: 100%;
    align-items: stretch;
    gap: 12px;
}

#addUserDialog .server-form input,
#addUserDialog .server-form button,
#whitelistDialog .server-form textarea,
#whitelistDialog .server-form button {
    width: 100%;
    min-height: 42px;
    box-sizing: border-box;
}

#addUserDialog .server-form input,
#whitelistDialog .server-form textarea {
    border: 1px solid #c7d7e2;
    border-radius: 12px;
    background: #f9fcfe;
    color: #26455c;
    padding: 11px 13px;
    outline: none;
    transition: border-color 0.2s ease, box-shadow 0.2s ease, background 0.2s ease;
}

#addUserDialog .server-form input:focus,
#whitelistDialog .server-form textarea:focus {
    border-color: #8fb8d6;
    background: #ffffff;
    box-shadow: 0 0 0 4px rgba(111, 170, 213, 0.14);
}

#addUserDialog .server-buttons,
#whitelistDialog .server-buttons {
    width: 100%;
    margin-top: 4px;
}

#addUserDialog .server-buttons button,
#whitelistDialog .server-buttons button {
    border: 1px solid #9fc0d7;
    border-radius: 999px;
    background: linear-gradient(135deg, #3a87b1 0%, #295f7b 100%);
    color: #ffffff;
    font-weight: 700;
    cursor: pointer;
    transition: background 0.2s ease, border-color 0.2s ease, transform 0.2s ease, box-shadow 0.2s ease;
}

#addUserDialog .server-buttons button:hover,
#whitelistDialog .server-buttons button:hover {
    background: linear-gradient(135deg, #34799f 0%, #244f66 100%);
    border-color: #244f66;
    transform: translateY(-1px);
    box-shadow: 0 8px 18px rgba(41, 95, 123, 0.2);
}

#addUserDialog .server-buttons button:active,
#whitelistDialog .server-buttons button:active {
    transform: translateY(0);
}

#whitelistDialog .server-form textarea {
    min-height: 220px;
    resize: vertical;
    line-height: 1.55;
    font-family: Consolas, Monaco, "Courier New", monospace;
}

@media (max-width: 768px) {
    .serverDialog {
        top: 50% !important;
        left: 50% !important;
        transform: translate(-50%, -50%) !important;
        width: calc(100vw - 24px);
        max-width: calc(100vw - 24px);
        max-height: 88vh;
        padding: 18px 16px 20px !important;
    }

    #addUserDialog,
    #whitelistDialog {
        width: calc(100vw - 24px);
        max-width: calc(100vw - 24px);
    }
}

/* unified floating dialog shell */
.floating-dialog,
.plugin-dialog {
    box-sizing: border-box;
    display: flex;
    flex-direction: column;
    gap: 0;
    overflow: hidden !important;
    border-radius: 20px !important;
    border: 1px solid rgba(138, 160, 178, 0.26) !important;
    box-shadow: 0 24px 60px rgba(44, 72, 98, 0.18) !important;
    background: linear-gradient(180deg, #fbfdff 0%, #f2f6fb 100%) !important;
    padding: 16px !important;
    overscroll-behavior: contain;
    -webkit-overflow-scrolling: touch;
}

.terminal-dialog,
.file-dialog,
.msg-dialog,
.plugin-dialog {
    width: min(92vw, 1100px) !important;
    max-width: min(92vw, 1100px) !important;
    max-height: 90vh !important;
}

.terminal-dialog {
    width: min(92vw, 980px) !important;
    max-width: min(92vw, 980px) !important;
}

.file-dialog {
    width: min(96vw, 1180px) !important;
    max-width: min(96vw, 1180px) !important;
}

.msg-dialog {
    width: min(92vw, 760px) !important;
    max-width: min(92vw, 760px) !important;
}

.plugin-dialog {
    width: min(92vw, 760px) !important;
    max-width: min(92vw, 760px) !important;
}

.terminal-dialog .terminal-drag-bar,
.file-dialog #file-drag-bar,
.msg-dialog #msg-drag-bar,
.plugin-dialog .plugin-drag-bar {
    position: sticky !important;
    top: -16px !important;
    left: 0;
    width: calc(100% + 32px) !important;
    height: 38px !important;
    min-height: 38px !important;
    max-height: 38px !important;
    flex: 0 0 38px !important;
    flex-shrink: 0 !important;
    margin: -16px -16px 12px -16px !important;
    cursor: move;
    background: linear-gradient(90deg, rgba(230, 236, 243, 0.96), rgba(243, 247, 251, 0.9)) !important;
    border-bottom: 1px solid rgba(138, 160, 178, 0.18) !important;
    border-top-left-radius: 20px !important;
    border-top-right-radius: 20px !important;
    z-index: 10001 !important;
    touch-action: none;
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
}

.terminal-dialog .terminal-dialog-toolbar {
    flex: 0 0 auto;
    margin-top: 0 !important;
    padding: 8px 4px 14px 4px;
}

.terminal-dialog .terminal {
    flex: 1 1 auto;
    min-height: 0;
    overflow: auto;
    border-radius: 16px;
}

.file-dialog .file-dialog-layout {
    flex: 1 1 auto;
    min-height: 0;
    margin-top: 0 !important;
    height: auto !important;
}

.file-dialog .file-history {
    background: linear-gradient(180deg, #fbfdff 0%, #f4f8fb 100%);
    border-right: 1px solid #e4ebf1;
    min-height: 0;
    overflow-y: auto;
    overflow-x: hidden;
    overscroll-behavior: contain;
    -webkit-overflow-scrolling: touch;
}

.file-dialog .filecontainer {
    flex: 1 1 auto;
    min-height: 0;
    overflow-y: auto;
    width: auto;
    height: auto;
    border-radius: 16px;
    box-shadow: inset 0 1px 0 rgba(255,255,255,0.72);
}

.msg-dialog {
    padding-bottom: 14px !important;
}

.msg-dialog .msg-dialog-header {
    flex: 0 0 auto;
    margin-top: 0 !important;
    padding: 8px 6px 12px;
}

.msg-dialog .msg-dialog-body {
    flex: 1 1 auto;
    min-height: 0;
    overflow-y: auto;
    padding: 0 2px 8px;
}

.plugin-dialog {
    position: fixed;
    top: 10%;
    left: 50%;
    width: min(92vw, 760px) !important;
    max-width: min(92vw, 760px) !important;
    overflow-y: auto !important;
    box-sizing: border-box;
}

.plugin-dialog .plugin-drag-bar {
    margin-bottom: 10px !important;
}

.dialog-close-btn {
    position: absolute;
    top: 3px;
    right: 12px;
    z-index: 10002;
    width: 34px;
    height: 34px;
    border: 1px solid rgba(130, 154, 170, 0.24);
    border-radius: 999px;
    background: rgba(255, 255, 255, 0.78);
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
    color: #5d7185;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 20px;
    line-height: 1;
    cursor: pointer;
    box-shadow: 0 8px 18px rgba(72, 94, 109, 0.12);
    transition: background-color 0.2s ease, border-color 0.2s ease, color 0.2s ease, transform 0.2s ease, box-shadow 0.2s ease;
}

.dialog-close-btn:hover {
    background: rgba(255, 255, 255, 0.95);
    border-color: rgba(111, 136, 153, 0.4);
    color: #314657;
    transform: translateY(-1px);
    box-shadow: 0 10px 22px rgba(72, 94, 109, 0.14);
}

.dialog-close-btn:active {
    transform: translateY(0);
    background: rgba(242, 247, 250, 0.96);
}

@media (max-width: 768px) {
    .floating-dialog,
    .plugin-dialog {
        width: min(92vw, 420px) !important;
        max-width: min(92vw, 420px) !important;
        max-height: calc(100dvh - 20px) !important;
        border-radius: 22px !important;
        padding: 12px 10px 14px !important;
    }

    .terminal-dialog,
    .file-dialog,
    .msg-dialog,
    .plugin-dialog {
        width: calc(100vw - 20px) !important;
        max-width: calc(100vw - 20px) !important;
    }

    .terminal-dialog .terminal-drag-bar,
    .file-dialog #file-drag-bar,
    .msg-dialog #msg-drag-bar,
    .plugin-dialog .plugin-drag-bar {
        top: -12px !important;
        width: calc(100% + 24px) !important;
        margin: -12px -12px 10px -12px !important;
        height: 36px !important;
        min-height: 36px !important;
        max-height: 36px !important;
        flex: 0 0 36px !important;
        border-top-left-radius: 22px !important;
        border-top-right-radius: 22px !important;
    }

    .dialog-close-btn {
        top: 0px;
        right: 8px;
        width: 34px;
        height: 34px;
        font-size: 22px;
    }
}

@media (max-width: 480px) {
    .floating-dialog,
    .plugin-dialog {
        width: min(94vw, 380px) !important;
        max-width: min(94vw, 380px) !important;
        max-height: calc(100dvh - 16px) !important;
        border-radius: 20px !important;
        padding: 10px 8px 12px !important;
    }

    .terminal-dialog,
    .file-dialog,
    .msg-dialog,
    .plugin-dialog {
        width: calc(100vw - 16px) !important;
        max-width: calc(100vw - 16px) !important;
    }

    .terminal-dialog .terminal-drag-bar,
    .file-dialog #file-drag-bar,
    .msg-dialog #msg-drag-bar,
    .plugin-dialog .plugin-drag-bar {
        top: -10px !important;
        width: calc(100% + 20px) !important;
        margin: -10px -10px 8px -10px !important;
        height: 34px !important;
        min-height: 34px !important;
        max-height: 34px !important;
        flex: 0 0 34px !important;
    }

    .dialog-close-btn {
        top: 0px;
        right: 8px;
        width: 32px;
        height: 32px;
        font-size: 20px;
    }
}
`
        }
        w.Header().Set("Content-Type", "text/css")
        fmt.Fprint(w, cssContent)
        }
    }
}
