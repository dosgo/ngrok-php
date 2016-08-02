<?php
/**
 * ngrok.cc 内网穿透服务 PHP 版
 *
 * 本程序仅适用于ngrok.cc 使用前请先在 http://ngrok.cc 注册账号.
 * 机器只要装有php(无须web服务)即可运行本程序,可用于路由器等OpenWRT操作系统
 * 命令行模式执行 php sunny.php即可运行
 *
 * 感谢 dosgo 提供的 ngrok-php 原版程序
 *
 */

ConsoleOut("欢迎使用内网穿透 sunny-php v1.33\r\nCtrl+C 退出");
set_time_limit(0); //设置执行时间
ignore_user_abort(true);
error_reporting(E_ALL ^ E_NOTICE ^ E_WARNING);

//检测大小端
define('BIG_ENDIAN', pack('L', 1) === pack('N', 1));

$seraddr = 'server.ngrok.cc'; //ngrok服务器地址
$port = 4443; //端口
$is_verify_peer = false; //是否校验证书

$isDebug = false;//调试开关

//设置映射隧道,支持多渠道[客户端id]
$Tunnels = array();
ngrok_yunnel($Tunnels, ngrok_auth('02473e9ad443252a'));//添加单个渠道到队列[客户端id]
//ngrok_yunnel($Tunnels, ngrok_auth('02473e9ad443252a,02473e9ad443252b'));//添加多个渠道到队列[客户端id,客户端id] 以此类推直接用逗号分隔就行了

//定义变量
$readfds = array();
$writefds = array();

$e = null;
$t = 1;

$socklist = array();

$ClientId = '';
$recvflag = true;
$starttime = time();//启动时间
$pingtime = 0;

//建立隧道协议
$mainsocket = connectremote($seraddr, $port);
if($mainsocket) {
    $socklist[] = array('sock' => $mainsocket, 'linkstate' => 0, 'type' => 1);
}

//注册退出执行函数
register_shutdown_function('shutdown');
while ($recvflag) {

    //重排
    array_filter($socklist);
    sort($socklist);

    //检测控制连接是否连接.
    if ($mainsocket == false) {
        $ip = dnsopen($seraddr, $port);//解析dns, port
        if (!$ip) {
            ConsoleOut('连接服务器失败.');
            sleep(1);
            continue;
        }
        $mainsocket = connectremote($ip, $port);
        if(!$mainsocket) {
            ConsoleOut('连接服务器失败.');
            sleep(10);
            continue;
        }
        $socklist[] = array('sock' => $mainsocket, 'linkstate' => 0, 'type' => 1);
    }

    //如果非cli超过1小时自杀
    if (is_cli() == false) {
        if ($starttime + 3600 < time()) {
            fclose($mainsocket);
            $recvflag = false;
            break;
        }
    }

    //发送心跳
    if ($pingtime + 25 < time() && $pingtime != 0) {
        sendpack($mainsocket, Ping());
        $pingtime = time();
    }

    //重新赋值
    $readfds = array();
    $writefds = array();
    foreach ($socklist as $k => $z) {
        if (is_resource($z['sock'])) {
            $readfds[] = $z['sock'];
            if ($z['linkstate'] == 0) {
                $writefds[] = $z['sock'];
            }
        } else {
            //close的时候不是资源。。移除
            if ($z['type'] == 1) {
                $mainsocket = false;
            }
            unset($z['type']);
            unset($z['sock']);
            unset($z['tosock']);
            unset($z['recvbuf']);
            array_splice($socklist, $k, 1);
        }
    }

    //查询
    $res = stream_select($readfds, $writefds, $e, $t);
    if ($res === false) {
        ConsoleOut('sockerr', 'debug');
    }

    //有事件
    if ($res > 0) {
        foreach ($socklist as $k => $sockinfo) {
            $sock = $sockinfo['sock'];
            //可读
            if (in_array($sock, $readfds)) {

                $recvbut = fread($sock, 1024);

                if ($recvbut == false || strlen($recvbut) == 0) {
                    //主连接关闭，关闭所有
                    if ($sockinfo['type'] == 1) {
                        $mainsocket = false;
                    }
                    if ($sockinfo['type'] == 3) {
                        fclose($sockinfo['tosock']);
                    }
                    unset($sockinfo['type']);
                    unset($sockinfo['sock']);
                    unset($sockinfo['tosock']);
                    unset($sockinfo['recvbuf']);
                    unset($socklist[$k]);
                    continue;
                }

                if (strlen($recvbut) > 0) {
                    if (!isset($sockinfo['recvbuf'])) {
                        $sockinfo['recvbuf'] = $recvbut;
                    } else {
                        $sockinfo['recvbuf'] = $sockinfo['recvbuf'] . $recvbut;
                    }
                    $socklist[$k] = $sockinfo;
                }

                //控制连接，或者远程未连接本地连接
                if ($sockinfo['type'] == 1 || ($sockinfo['type'] == 2 && $sockinfo['linkstate'] == 1)) {
                    $allrecvbut = $sockinfo['recvbuf'];
                    //处理
                    $lenbuf = substr($allrecvbut, 0, 8);
                    $len = tolen1($lenbuf);
                    if (strlen($allrecvbut) >= (8 + $len)) {
                        $json = substr($allrecvbut, 8, $len);
                        ConsoleOut($json, 'debug');
                        $js = json_decode($json, true);

                        //远程主连接
                        if ($sockinfo['type'] == 1) {
                            if ($js['Type'] == 'ReqProxy') {
                                $newsock = connectremote($seraddr, $port);
                                if ($newsock) {
                                    $socklist[] = array('sock' => $newsock, 'linkstate' => 0, 'type' => 2);
                                }
                            }
                            if ($js['Type'] == 'AuthResp') {
                                $ClientId = $js['Payload']['ClientId'];
                                $pingtime = time();
                                sendpack($sock, Ping());
                                foreach ($Tunnels as $tunnelinfo) {
                                    //注册端口
                                    sendpack($sock, ReqTunnel($tunnelinfo['protocol'], $tunnelinfo['hostname'], $tunnelinfo['subdomain'], $tunnelinfo['httpauth'], $tunnelinfo['rport']));
                                }
                            }
                            if ($js['Type'] == 'NewTunnel') {
                                if ($js['Payload']['Error'] != null) {//判断NewTunnel是否有错误
                                    ConsoleOut('隧道建立失败:,'.$js['Payload']['Error']);//注册失败
                                    sleep(60);//延迟60后继续注册
                                    continue;
                                }
                                ConsoleOut('隧道建立成功:' . $js['Payload']['Url']);//注册成功
                            }
                        }

                        //远程代理连接
                        if ($sockinfo['type'] == 2) {
                            //未连接本地
                            if ($sockinfo['linkstate'] == 1) {
                                if ($js['Type'] == 'StartProxy') {
                                    $loacladdr = getloacladdr($Tunnels, $js['Payload']['Url']);

                                    $ip = dnsopen($loacladdr['lhost'], $loacladdr['lport']);//解析dns, port
                                    if (!$ip) {//本地地址无效转向指定html页面
                                        $body = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Web服务错误</title><meta name="viewport" content="initial-scale=1,maximum-scale=1,user-scalable=no"><meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1"><style>html,body{height:100%%}body{margin:0;padding:0;width:100%%;display:table;font-weight:100;font-family:"Microsoft YaHei",Arial,Helvetica,sans-serif}.container{text-align:center;display:table-cell;vertical-align:middle}.content{border:1px solid #ebccd1;text-align:center;display:inline-block;background-color:#f2dede;color:#a94442;padding:30px}.title{font-size:18px}.copyright{margin-top:30px;text-align:right;color:#000}</style></head><body><div class="container"><div class="content"><div class="title">隧道 %s 无效<br>无法连接到<strong>%s</strong>. 此端口尚未提供Web服务</div><div class="copyright">Powered By ngrok.cc</div></div></div></body></html>';
                                        $html = sprintf($body, $js['Payload']['Url'], $loacladdr['lhost'] .':' . $loacladdr['lport']);
                                        $header = "HTTP/1.0 502 Bad Gateway"."\r\n";
                                        $header .= "Server: ngrok-php"."\r\n";
                                        $header .= "Content-Type: text/html"."\r\n";
                                        $header .= "Content-Length: %d"."\r\n";
                                        $header .= "\r\n"."%s";
                                        $buf = sprintf($header, strlen($html), $html);
                                        sendbuf($sock, $buf);
                                    } else {
                                        $newsock = connectlocal($ip, $loacladdr['lport']);
                                        if ($newsock) {
                                            $socklist[] = array('sock' => $newsock, 'linkstate' => 0, 'type' => 3, 'tosock' => $sock);
                                        }
                                        //把本地连接覆盖上去
                                        $sockinfo['tosock'] = $newsock;
                                        $sockinfo['linkstate'] = 2;
                                    }
                                }
                            }
                        }
                        //edit buffer
                        if (strlen($allrecvbut) == (8 + $len)) {
                            $sockinfo['recvbuf'] = '';
                        } else {
                            $sockinfo['recvbuf'] = substr($allrecvbut, 8 + $len);
                        }
                        $socklist[$k] = $sockinfo;
                    }
                }

                //远程连接已连接本地跟本地连接，纯转发
                if ($sockinfo['type'] == 3 || ($sockinfo['type'] == 2 && $sockinfo['linkstate'] == 2)) {
                    sendbuf($sockinfo['tosock'], $sockinfo['recvbuf']);
                    $sockinfo['recvbuf'] = '';
                    $socklist[$k] = $sockinfo;
                }
            }

            //可写
            if (in_array($sock, $writefds)) {
                if ($sockinfo['linkstate'] == 0) {

                    if ($sockinfo['type'] == 1) {
                        sendpack($sock, NgrokAuth(), false);
                        $sockinfo['linkstate'] = 1;
                        $socklist[$k] = $sockinfo;
                    }
                    if ($sockinfo['type'] == 2) {
                        sendpack($sock, RegProxy($ClientId), false);
                        $sockinfo['linkstate'] = 1;
                        $socklist[$k] = $sockinfo;
                    }
                    if ($sockinfo['type'] == 3) {
                        $sockinfo['linkstate'] = 1;
                        $socklist[$k] = $sockinfo;
                    }
                }
            }
        }
    }
}

/* 域名解析-端口 */
function dnsopen($seraddr, $port) {
    $ip = gethostbyname($seraddr);//解析dns
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return false;
    }

    $fsock = @fsockopen($ip, $port, $errno, $errstr, 3);//检测端口
    if (!$fsock) {
        return false;
    }
    return $ip;
}

/* 连接到远程 */
function connectremote($seraddr, $port) {
    global $is_verify_peer;
    $socket = stream_socket_client('tcp://' . $seraddr . ':' . $port, $errno, $errstr, 30);
    if (!$socket) {
        return false;
    }
    //设置加密连接，默认是ssl，如果需要tls连接，可以查看php手册stream_socket_enable_crypto函数的解释
    if ($is_verify_peer == false) {
        stream_context_set_option($socket, 'ssl', 'verify_host', false);
        stream_context_set_option($socket, 'ssl', 'verify_peer_name', false);
        stream_context_set_option($socket, 'ssl', 'verify_peer', false);
    }
    stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_SSLv23_CLIENT);
    stream_set_blocking($socket, 0); //设置为非阻塞模式
    return $socket;
}

/* 连接到本地 */
function connectlocal($localaddr, $localport) {
    $socket = stream_socket_client('tcp://' . $localaddr . ':' . $localport, $errno, $errstr, 30);
    if (!$socket) {
        return false;
    }
    stream_set_blocking($socket, 0); //设置为非阻塞模式
    return $socket;
}

function getloacladdr($Tunnels, $url) {
    $protocol = substr($url, 0, strpos($url, ':'));
    $hostname = substr($url, strpos($url, '//') + 2);
    $subdomain = trim(substr($hostname, 0, strpos($hostname, '.')));
    $rport = substr($url, strrpos($url, ':') + 1);
    


    //   echo 'protocol:'.$protocol."\r\n";
    //   echo '$subdomain:'.$subdomain."\r\n";
    //      echo '$hostname:'.$hostname."\r\n";
    //    echo '$rport:'.$rport."\r\n";

    foreach ($Tunnels as $k => $z) {
        //
        if ($protocol == $z['protocol']) {
            if ($hostname == $z['hostname']) {
                return $z;
            }
            if ($subdomain == $z['subdomain']) {
                return $z;
            }
            
            if ($protocol == 'tcp') {
                if ($rport == $z['rport']) {
                    return $z;
                }
            }
        }
    }

    //  array('protocol'=>$protocol,'hostname'=>'','subdomain'=>'','rport'=>0,'lhost'=>'','lport'=>80),
}

function NgrokAuth() {
    $Payload = array(
        'ClientId' => '',
        'OS' => 'darwin',
        'Arch' => 'amd64',
        'Version' => '2',
        'MmVersion' => '1.7',
        'User' => 'user',
        'Password' => '',
    );
    $json = array(
        'Type' => 'Auth',
        'Payload' => $Payload,
    );
    return json_encode($json);
}

function ReqTunnel($protocol, $HostName, $Subdomain, $HttpAuth, $RemotePort) {
    $Payload = array(
        'ReqId' => getRandChar(8),
        'Protocol' => $protocol,
        'Hostname' => $HostName,
        'Subdomain' => $Subdomain,
        'HttpAuth' => $HttpAuth,
        'RemotePort' => $RemotePort,
    );
    $json = array(
        'Type' => 'ReqTunnel',
        'Payload' => $Payload,
    );
    return json_encode($json);
}

function RegProxy($ClientId) {
    $Payload = array('ClientId' => $ClientId);
    $json = array(
        'Type' => 'RegProxy',
        'Payload' => $Payload,
    );
    return json_encode($json);
}

function Pong() {
    $Payload = (object) array();
    $json = array(
        'Type' => 'Pong',
        'Payload' => $Payload,
    );
    return json_encode($json);
}

function Ping() {
    $Payload = (object) array();
    $json = array(
        'Type' => 'Ping',
        'Payload' => $Payload,
    );
    return json_encode($json);
}

/* 网络字节序 （只支持整型范围） */
function lentobyte($len) {
    $xx = pack("N", $len);
    $xx1 = pack("C4", 0, 0, 0, 0);
    return $xx1 . $xx;
}

/* 机器字节序 （小端 只支持整型范围） */
function lentobyte1($len) {
    $xx = pack("L", $len);
    $xx1 = pack("C4", 0, 0, 0, 0);
    return $xx . $xx1;
}

function sendpack($sock, $msg, $isblock = true) {
    if ($isblock) {
        stream_set_blocking($sock, 1); //设置为非阻塞模式
    }
    fwrite($sock, lentobyte1(strlen($msg)) . $msg);
    if ($isblock) {
        stream_set_blocking($sock, 0); //设置为非阻塞模式
    }
}

function sendbuf($sock, $buf, $isblock = true) {
    if ($isblock) {
        stream_set_blocking($sock, 1); //设置为非阻塞模式
    }
    fwrite($sock, $buf);
    if ($isblock) {
        stream_set_blocking($sock, 0); //设置为非阻塞模式
    }
}

/* 网络字节序 （只支持整型范围） */
function tolen($v) {
    $array = unpack("N", $v);
    return $array[1];
}

/* 机器字节序 （小端） 只支持整型范围 */
function tolen1($v) {
    $array = unpack("L", $v);
    return $array[1];
}

//随机生成字符串
function getRandChar($length) {
    $str = null;
    $strPol = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
    $max = strlen($strPol) - 1;

    for ($i = 0; $i < $length; $i++) {
        $str .= $strPol[rand(0, $max)];
    }

    return $str;
}

//输出日记到命令行
function ConsoleOut($log, $level = 'info') {
    global $isDebug;
    if ($level == 'debug' and $isDebug == false) {
        return;
    }
    //cli
    if (is_cli()) {
        if (DIRECTORY_SEPARATOR == "\\") {
            $log = iconv('UTF-8', 'GB2312', $log);
        }
        echo $log . "\r\n";
    }
    //web
    else {
        echo $log . "<br/>";
        ob_flush();
        flush();
        // file_put_contents("ngrok.log", date("Y-m-d H:i:s:::") . $log . "\r\n", FILE_APPEND);
    }
}

//判断是否命令行运行
function is_cli() {
    return (php_sapi_name() === 'cli') ? true : false;
}

//ngrok.cc 获取服务器设置
function ngrok_auth($clientid) {
    $host = 'www.ngrok.cc';
    $port = 80;

    $fp = @fsockopen($host, $port, $errno, $errstr, 10);
    if (!$fp) {
        ConsoleOut('连接认证服务器: http://www.ngrok.cc 错误.' . $errno . $errstr);
        sleep(10);
        exit();
    }

    $header = "GET "."/api/clientid/clientid/%s"." HTTP/1.1"."\r\n";
    $header .= "Host: %s"."\r\n";
    $header .= "\r\n";

    $buf = sprintf($header, $clientid, $host);
    $write = fputs($fp, $buf);

    $body = null;
    while (!feof($fp)) {
        $line = fgets($fp,1024); //去除请求包的头只显示页面的返回数据
        if ($line == "\n" || $line == "\r\n") {
            $body = fread($fp, 1024);
            break;
        }
    }

    fclose($fp);
    $authData = json_decode($body, true);

    if ($authData['status'] != 200) {
        ConsoleOut('认证错误:' . $authData['status'] . ' ErrorCode:' . $authData['msg']);
        sleep(10);
        exit();
    }
    ConsoleOut('认证成功,正在连接服务器...');
    return $authData['data'];
}

//ngrok.cc 添加到渠道队列
function ngrok_yunnel($Tunnels, $Tunnel) {
    global $Tunnels;
    foreach ($Tunnel as $tunnelinfo) {
        if (isset($tunnelinfo['proto']['http'])) {
            $t = 'http';
        }
        if (isset($tunnelinfo['proto']['https'])) {
            $t = 'https';
        }
        if (isset($tunnelinfo['proto']['tcp'])) {
            $t = 'tcp';
        }

        $proto = explode(':', $tunnelinfo['proto'][$t]);//127.0.0.1:80 拆分成数组
        if ($proto[0] == '') {
            $proto[0] = '127.0.0.1';
        }
        if ($proto[1] == '' || $proto[1] == 0) {
            $proto[1] = 80;
        }

        $Tunnels[] = array(
            'protocol' => $t,
            'hostname' => $tunnelinfo['hostname'],
            'subdomain' => $tunnelinfo['subdomain'],
            'httpauth' => $tunnelinfo['httpauth'],
            'rport' => $tunnelinfo['remoteport'],
            'lhost' => $proto[0],
            'lport' => $proto[1]
        );
    }
}

//注册退出执行函数
function shutdown() {
    global $mainsocket;
    sendpack($mainsocket, 'close');
    fclose($mainsocket);
}

?>
