/*
* @Author: Zhang Guohua
* @Date:   2018-11-23 16:26:17
* @Last Modified by:   zgh
* @Last Modified time: 2018-11-23 16:36:27
* @Description: create by zgh
* @GitHub: Savour Humor
*/
## 介绍
1. 是一种挟制用户在当前已登录的Web应用程序上执行非本意的操作的攻击方法。
    1. 释义： 跨站请求攻击，简单地说，是攻击者通过一些技术手段欺骗用户的浏览器去访问一个自己曾经认证过的网站并运行一些操作（如发邮件，发消息，甚至财产操作如转账和购买商品）。由于浏览器曾经认证过，所以被访问的网站会认为是真正的用户操作而去运行。这利用了web中用户身份验证的一个漏洞：简单的身份验证只能保证请求发自某个用户的浏览器，却不能保证请求本身是用户自愿发出的。
    
2. 特点： 跟跨网站脚本（XSS）相比，XSS 利用的是用户对指定网站的信任，CSRF 利用的是网站对用户网页浏览器的信任。
    1. 释义： 不获取用户的信息，不获取用户的账户控制权，欺骗用户浏览器，以用户的名义运行操作。
    2. 打开莫名的网站，加载莫名的内容。
3. 区别： 跟跨网站脚本（XSS）相比，XSS 利用的是用户对指定网站的信任，CSRF 利用的是网站对用户网页浏览器的信任。


## 攻击特点
1. 发送请求。
    1. get
    2. post
    3. 常常跨域，或本域则更危险
        1. CSRF 攻击通常是由其他域发起的请求，所以可以通过限制 发起域 来防范大多数的 CSRF 攻击。
        2. 本域下有容易被利用的功能，比如可以发图和链接的论坛和评论区，攻击可以直接在本域下进行，而且这种攻击更加危险。
2. 考虑对象：
    1. 将内容载入你用户的浏览器并迫使他们向你的网站提交请求的任何人。你的用户所访问的任何网站或者HTML 源（feed）都可以这样做。
    2. 攻击者创建伪造HTTP请求并通过图片标签、跨站脚本或许多其他技术诱使受害用户提交这些请求。如果该受害用户已经经过身份认证，那么攻击就能成功。
3. 方式
    1. 图片
    2. 链接
    3. 表单提交

## 攻击结果
1. 攻击者能欺骗受害用户完成该受害者所允许的任意状态改变的操作，比如：更新帐号细节，完成购物，注销甚至登录等操作 。

## 案例
1. 2007 年的Gmail 曾被黑客利用 CSRF 攻击。

## 攻击预防
1. 将持久化的授权方法（例如cookie或者HTTP授权）切换为瞬时的授权方法（在每个form中提供隐藏field），这将帮助网站防止这些攻击。一种类似的方式是在form中包含秘密信息、用户指定的代号作为cookie之外的验证。
2. 双提交”cookie。此方法只工作于Ajax请求，但它能够作为无需改变大量form的全局修正方法。如果某个授权的cookie在form post之前正被JavaScript代码读取，那么限制跨域规则将被应用。如果服务器需要在Post请求体或者URL中包含授权cookie的请求，那么这个请求必须来自于受信任的域，因为其它域是不能从信任域读取cookie的。
3. 检查Referer字段：HTTP头中有一个Referer字段，这个字段用以标明请求来源于哪个地址。在处理敏感数据请求时，通常来说，Referer字段应和请求的地址位于同一域名下。
4. 检查 Origin Header 字段值。
3. 添加校验token：由于CSRF的本质在于攻击者欺骗用户去访问自己设置的地址，所以如果要求在访问敏感数据请求时，要求用户浏览器提供不保存在cookie中，并且攻击者无法伪造的数据作为校验，那么攻击者就无法再运行CSRF攻击。这种数据通常是窗体中的一个数据项。服务器将其生成并附加在窗体中，其内容是一个伪随机数。当客户端通过窗体提交请求时，这个伪随机数也一并提交上去以供校验。正常的访问时，客户端浏览器能够正确得到并传回这个伪随机数，而通过CSRF传来的欺骗性攻击中，攻击者无从事先得知这个伪随机数的值，服务端就会因为校验token的值为空或者错误，拒绝这个可疑请求。
4. 防止CSRF攻击的办法已经有上面的预防措施。为了从源头上解决这个问题，Google起草了一份草案来改进HTTP协议，那就是为Set-Cookie响应头新增Samesite属性，它用来标明这个 Cookie是个“同站 Cookie”，同站Cookie只能作为第一方Cookie，不能作为第三方Cookie。

## 攻击检测
1. 通过渗透测试或代码分析检测到。
2. 通过 CSRFTester 进行检测。

## CSRF 监控
1. 通过请求IP， 以及Token 验证，当Token 不符合我们的要求时，便可以将 IP 通过日志记录下来，作为可能的 CSRF 攻击进行处理。。


