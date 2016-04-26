<?php
ConsoleOut("ngrok-php v1.3");
set_time_limit(0); //设置执行时间
ignore_user_abort(true);

//检测大小端
define('BIG_ENDIAN', pack('L', 1) === pack('N', 1));

$seraddr = 'tunnel.qydev.com';  //ngrok服务器地址
$port = 4443;    //端口
$is_verify_peer=false;//是否校验证书

//你要映射到通道
$Tunnels = array(

     array('protocol' => 'http', 'hostname' => '', 'subdomain' => 'yyy', 'rport' => 0, 'lhost' => '127.0.0.1', 'lport' => 80),
       array('protocol' => 'http', 'hostname' => '', 'subdomain' => 'xxx', 'rport' => 0, 'lhost' => '127.0.0.1', 'lport' => 80),
    array('protocol' => 'tcp', 'hostname' => '', 'subdomain' => '', 'rport' => 57715, 'lhost' => '127.0.0.1', 'lport' => 80),

);



$mainsocket=0;
//发送数据



$readfds = array();
$writefds = array();

$e = null;
$t = 1;

$socklist = array();

$ClientId = '';
$runflag = true;
$pingtime = 0;
$starttime = time(); //启动时间
$connecttime=0;
//注册退出执行函数
register_shutdown_function('shutdown',$mainsocket);
while ($runflag) {
     
	 //重排
	 array_filter($socklist);
	 sort($socklist);

	 //检测控制连接是否连接
	 if($mainsocket==0&&$connecttime+60<time()){
	 	 $mainsocket = connectremote($seraddr, $port);
         $connecttime=time();
	     if ($mainsocket) {
	          $socklist[] = array('sock' => $mainsocket, 'linkstate' => 0, 'type' => 1);
	     }else{
            $mainsocket=0;
         }
	 }



    //如果非cli超过1小时自杀
	if(is_cli()==false){
		if ($starttime + 3600 < time()) {
			fclose($mainsocket);
			$runflag = false;
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
               	$mainsocket=0;
                array_splice($socklist, $k, 1);
            } else {
                array_splice($socklist, $k, 1);
            }
        }
    }
    $t = 1;

    //查询
    if(count($readfds)>0||count($writefds)>0){
        $res = stream_select($readfds, $writefds, $e, $t);
    }else{
        sleep(1);
        continue;
    }

    if ($res === false) {
        ConsoleOut('sockerr');
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
                    	$mainsocket=0;
                        unset($sockinfo['type']);
                        unset($sockinfo['sock']);
                        unset($sockinfo['tosock']);
                        unset($sockinfo['recvbuf']);
                        unset($socklist[$k]);
                    } else {
                        if ($sockinfo['type'] == 3) {
                            fclose($sockinfo['tosock']);
                        }
                        //array_splice($socklist, $k, 1);
                        unset($sockinfo['type']);
                        unset($sockinfo['sock']);
                        unset($sockinfo['tosock']);
                        unset($sockinfo['recvbuf']);
						unset($socklist[$k]);
                        continue;
                    }
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
                        ConsoleOut($json);
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
                                    sendpack($sock, ReqTunnel($tunnelinfo['protocol'], $tunnelinfo['hostname'], $tunnelinfo['subdomain'], $tunnelinfo['rport']));
                                }
                            }
                            if ($js['Type'] == 'NewTunnel') {
                                ConsoleOut($js['Payload']['Url']);
                            }
                        }

                        //远程代理连接
                        if ($sockinfo['type'] == 2) {
                            //未连接本地
                            if ($sockinfo['linkstate'] == 1) {
                                if ($js['Type'] == 'StartProxy') {
                                    $loacladdr = getloacladdr($Tunnels, $js['Payload']['Url']);

                                    $newsock = connectlocal($loacladdr['lhost'], $loacladdr['lport']);
                                    if ($newsock) {
                                        $socklist[] = array('sock' => $newsock, 'linkstate' => 0, 'type' => 3, 'tosock' => $sock);
                                    }
                                    //把本地连接覆盖上去
                                    $sockinfo['tosock'] = $newsock;
                                    $sockinfo['linkstate'] = 2;
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
                if (($sockinfo['type'] == 2 && $sockinfo['linkstate'] == 2) || $sockinfo['type'] == 3) {
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

function NgrokAuth() {
    $Payload = array('Version' => '2',
        'MmVersion' => '1.7',
        'User' => 'user',
        'Password' => '',
        'OS' => 'darwin',
        'Arch' => 'amd64',
        'ClientId' => '');
    $json = array(
        'Type' => 'Auth',
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

/* 连接到远程 */

function connectremote($seraddr, $port) {
    global $is_verify_peer;
    global $errno;
    global $errstr;
    $socket = stream_socket_client("tcp://" . $seraddr . ":" . $port, $errno, $errstr, 30);
    if (!$socket) {
        return false;
    }
    //设置加密连接，默认是ssl，如果需要tls连接，可以查看php手册stream_socket_enable_crypto函数的解释
	if($is_verify_peer==false){
		stream_context_set_option($socket, 'ssl', 'verify_host', FALSE);
		stream_context_set_option($socket, 'ssl', 'verify_peer_name', FALSE);
		stream_context_set_option($socket, 'ssl', 'verify_peer', FALSE);
	}
    stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_SSLv23_CLIENT);
    stream_set_blocking($socket, 0); //设置为非阻塞模式
    return $socket;
}

function getloacladdr($Tunnels, $url) {
    $protocol = substr($url, 0, strpos($url, ':'));
    $hostname = substr($url, strpos($url, '//') + 2);
    $subdomain = trim(substr($hostname,0,strpos($hostname, '.')));
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
            
            if($protocol=='tcp'){
                if ($rport == $z['rport']) {
                    return $z;
                }
            }
        }
    }

    //  array('protocol'=>$protocol,'hostname'=>'','subdomain'=>'','rport'=>0,'lhost'=>'','lport'=>80),
}

/* 连接到本地 */

function connectlocal($localaddr, $localport) {
    global $errno;
    global $errstr;
    $socket = stream_socket_client("tcp://" . $localaddr . ":" . $localport, $errno, $errstr, 30);
    if (!$socket) {
        return false;
    }
    stream_set_blocking($socket, 0); //设置为非阻塞模式
    return $socket;
}

function RegProxy($ClientId) {
    $Payload = array('ClientId' => $ClientId);
    $json = array(
        'Type' => 'RegProxy',
        'Payload' => $Payload,
    );
    return json_encode($json);
}

function ReqTunnel($protocol, $HostName, $Subdomain, $RemotePort) {
    $Payload = array(
        'Protocol' => $protocol,
        'ReqId' => getRandChar(8),
        'Hostname' => $HostName,
        'Subdomain' => $Subdomain,
        'HttpAuth' => '',
        'RemotePort' => $RemotePort,
    );
    $json = array(
        'Type' => 'ReqTunnel',
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

/*
  网络字节序 只支持整型范围
 */

function tolen($v) {
    $array = unpack("N", $v);
    return $array[1];
}

/* 机器字节序 （小端） 只支持整型范围 */

function tolen1($v) {
    $array = unpack("L", $v);
    return $array[1];
}

function hex_dump($data, $newline = "n") {
    static $from = '';
    static $to = '';

    static $width = 16; # number of bytes per line 

    static $pad = '.'; # padding for non-visible characters 

    if ($from === '') {
        for ($i = 0; $i <= 0xFF; $i++) {
            $from .= chr($i);
            $to .= ($i >= 0x20 && $i <= 0x7E) ? chr($i) : $pad;
        }
    }

    $hex = str_split(bin2hex($data), $width * 2);
    $chars = str_split(strtr($data, $from, $to), $width);

    $offset = 0;
    foreach ($hex as $i => $line) {
        echo sprintf('%6X', $offset) . ' : ' . implode(' ', str_split($line, 2)) . ' [' . $chars[$i] . ']' . $newline;
        $offset += $width;
    }
}

function getRandChar($length) {
    $str = null;
    $strPol = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
    $max = strlen($strPol) - 1;

    for ($i = 0; $i < $length; $i++) {
        $str.=$strPol[rand(0, $max)]; //rand($min,$max)生成介于min和max两个数之间的一个随机整数
    }

    return $str;
}

function ConsoleOut($log) {
    //cli
    if (is_cli()) {
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

function is_cli() {
    return (php_sapi_name() === 'cli') ? true : false;
}

//注册退出执行函数
function shutdown(&$mainsocket) {
    sendpack($mainsocket, 'close');
    fclose($mainsocket);
}

?>