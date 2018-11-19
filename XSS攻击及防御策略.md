/*
* @Author: Zhang Guohua
* @Date:   2018-11-19 19:55:06
* @Last Modified by:   zgh
* @Last Modified time: 2018-11-19 19:55:16
* @Description: create by zgh
* @GitHub: Savour Humor
*/
# XSS 攻击
## 介绍

1. XSS 攻击，从最初 netscap 推出 javascript 时，就已经察觉到了危险。 我们常常需要面临跨域的解决方案，其实同源策略是保护我们的网站。糟糕的跨域会带来危险，虽然我们做了访问控制，但是网站仍然面临着严峻的 XSS 攻击考验。
2. 攻击定义： Cross-Site Scripting（跨站脚本攻击）简称 XSS，是一种代码注入攻击。攻击者通过在目标网站上注入恶意脚本，利用信任执行代码。利用这些恶意脚本，攻击者可获取用户的敏感信息，危害网站。
3. 在部分情况下，由于输入的限制，注入的恶意脚本比较短。但可以通过引入外部的脚本，并由浏览器执行，来完成比较复杂的攻击策略。
4. 这些恶意网页程序通常是JavaScript，但实际上也可以包括Java，VBScript，ActiveX，Flash或者甚至是普通的HTML。

## 攻击来源
1. 用户的 UGC 信息
2. 来自第三方的链接
3. URL参数
4. POST参数
5. Referer(可能来自不可信的来源)
6. Cookie(可能来自其他子域注入)

## 攻击结果
1. 盗用cookie，获取敏感信息。
1. 利用植入Flash，通过crossdomain权限设置进一步获取更高权限；或者利用Java等得到类似的操作。
1. 利用iframe、frame、XMLHttpRequest或上述Flash等方式，以（被攻击）用户的身份执行一些管理动作，或执行一些一般的如发微博、加好友、发私信等操作。
1. 利用可被攻击的域受到其他域信任的特点，以受信任来源的身份请求一些平时不允许的操作，如进行不当的投票活动。
1. 在访问量极大的一些页面上的XSS可以攻击一些小型网站，实现DDoS攻击的效果。 

## 攻击分类 (见详细总结)
1. 存储型 XSS:
    1. 你的应用或者API将未净化的用户输入存储下来了，并在后期在其他用户或者管理员的页面展示出来。 存储型XSS一般被认为是高危或严重的风险。
    2. 攻击过程：
        1. Bob拥有一个Web站点，该站点允许用户发布信息/浏览已发布的信息。
        1. Charly注意到Bob的站点具有类型C的XSS漏洞。
        1. Charly发布一个热点信息，吸引其它用户纷纷阅读。
        1. Bob或者是任何的其他人如Alice浏览该信息，其会话cookies或者其它信息将被Charly盗走。

2. 反射型 XSS：
    1. 你的应用中包含未验证的或未编码的用户输入，并作为HTML或者其他未启用CSP头的一部分输出。成功的攻击将在受害者的浏览器上执行任意HTML或JS代码。 一般而言，用户需要点击链接或与其他攻击者控制页面做交互，例如：水坑攻击、恶意行为或其它。
    2. 攻击过程：
        1. Alice经常浏览某个网站，此网站为Bob所拥有。Bob的站点运行Alice使用用户名/密码进行登录，并存储敏感信息(比如银行帐户信息)。
        2. Charly发现Bob的站点包含反射性的XSS漏洞。
        3. Charly编写一个利用漏洞的URL，并将其冒充为来自Bob的邮件发送给Alice。
        4. Alice在登录到Bob的站点后，浏览Charly提供的URL。
        5. 嵌入到URL中的恶意脚本在Alice的浏览器中执行，就像它直接来自Bob的服务器一样。此脚本盗窃敏感信息(授权、信用卡、帐号信息等然后在Alice完全不知情的情况下将这些信息发送到Charly的Web站点。
        
3. DOM 型 XSS
    1. 会动态的将攻击者可控的内容加入页面的JavaScript框架、单页面程序或API存在这种类型的漏洞。理想的来说，你应该避免将攻击者可控的数据发送给不安全的JavaScriptAPI。
    2. 攻击过程:
        1. 攻击者构造出特殊的 URL，其中包含恶意代码。
        2. 用户打开带有恶意代码的 URL。
        3. 用户浏览器接收到响应后解析执行，前端 JavaScript 取出 URL 中的恶意代码并执行。
        4. 恶意代码窃取用户数据并发送到攻击者的网站，或者冒充用户的行为，调用目标网站接口执行攻击者指定的操作。

## 攻击预防
1. 渲染前处理： 在渲染前对服务端返回的数据，进行明确的数据类型处理。像文本（.innerText），还是属性（.setAttribute），还是样式（.style）等等
2. 对 HTML 各个内容做相应的语义转换规则。详情可以查看 [XSS (Cross Site Scripting) Prevention Cheat Sheet](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet)。
3. 为了避免客户端XSS，最好的选择是避免传递不受信任的数据到JavaScript和可以生成活动内容的其他浏览器A PI。如 location、onclick、onerror、onload、onmouseover 等，a 标签的 href 属性，JavaScript 的 eval()、setTimeout()、setInterval() 等，都能把字符串作为代码运行。如果不可信的数据拼接到字符串中传递给这些 API，很容易产生安全隐患，请务必避免。
4.  HTTP-only Cookie: 禁止 JavaScript 读取某些敏感 Cookie，攻击者完成 XSS 注入后也无法窃取此 Cookie。
5.  使用CSP是对抗XSS的深度防御策略。具体可查看[内容安全策略](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/CSP)

## 防御检测
1. 使用通用 XSS 攻击字符串手动检测 XSS 漏洞。jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
    
2. 使用扫描工具自动检测 XSS 漏洞。
    1.  Arachni、Mozilla HTTP Observatory、w3af 

## 攻击案例总结
1. 新浪微博
2. 百度贴吧
