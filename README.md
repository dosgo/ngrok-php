##ngrok-php

一个php的ngrok客户端,不需要依赖啥扩展。。php5.2以上都可以跑，支持cgi模式，跟cli模式，意味着你在nginx/apache里面跑,特方便，代码很简单只有500行，比较讽刺的是，貌似性能比C语言版本还好，可见我的C语言有多烂。。

还有个hauntek大神写的python版本，https://github.com/hauntek/python-ngrok

#运行方法。。
直接运行就行了。。

#温馨提示
鉴于长时间跑cgi程序，可能php不怎么稳定，所以里面有个自杀函数。。1个小时会自动退出，最好跟任务计划配合。。这样就可以随时。。连接了。。
，也可以去掉那函数。


以下来自hauntek大神的分支。
#适配平台

***
1.ngrok.cc[sunny.php]

2.natapp.cn[natapp.php]

适配平台运行方法，文件内有说明

***

#更新日记 v1.38(2016/03/13)

***

1.支持ngrok.cc https协议头

2.优化隧道查询信息判断

***

#更新日记 v1.36(2016/8/8)

***

1.删除无用的函数

2.优化渠道注册成功判断

3.去除没必要清理的循环变量

4.去除建立本地渠道的解析判断

5.修复本地渠道建立失败无需覆盖

6.添加是否允许自签名证书上下文

***

#更新日记 v1.33(2016/08/02)

***

1.修复首次运行处于断网状态，渠道反复注册

2.修复退出时close错误

***

#更新日记 v1.32(2016/07/31)

***

1.添加域名解析ip后再进行连接操作,避免链接不上循环问题导致cpu过高

2.添加屏蔽警告错误

3.修复断线重连判断优化，优先判断dns

4.修复close不是资源变量删除并跳出当前循环

5.修复输出日记乱码修复

6.修复隧道已注册后无限循环注册的问题，并且等待60秒后继续注册

7.添加本地映射地址无效转向定制的html页面

8.添加连接状态日记提醒

***
