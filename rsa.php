<?php

declare(strict_types=1);
/**
 * 第二版实现，使用二进制字符串直接转数字的方式
 */


/**
 * 扩展欧几里得算法，用来求模的逆元
 * 计算 ax + by = gcd(a,b) = 1中x，y的整数解（a与b互质）.
 */
function extGcd(string $a, string $b): array
{
    if ($b === '0') {
        // 返回[x,y]
        return ['1', '0'];
    }
    [$x1, $y1] = extGcd($b, bcmod($a, $b));
    $x = $y1;
    $y = bcsub($x1, bcmul(bcdiv($a, $b), $y1));
    return [$x, $y];
}

/**
 * 获取秘钥对，（n, e, d).
 */
function getKey(string $p, string $q): array
{
    // 公钥，实际生产环境中常用65537（费马数）
    $e = '65537';
    $n = bcmul($p, $q);
    // n的欧拉函数，φ(n) = 小于等于n的正整数中与n互质的数的个数；可以由下式得出
    $z = bcmul(bcsub($p, '1'), bcsub($q, '1'));
    [$x, $y] = extGcd($e, $z);
    // $x为负，则需要加上$x
    $d = (substr($x, 0, 1) === '-') ? bcadd($x, $z) : $x;
    return [$n, $e, $d];
}

/**
 * RSA加密解密；当指数为公钥时定义为加密，私钥时定义为解密
 * 因此可以采用快速求幂算法，bcmath中已经实现有相关的函数.
 */
function RSA(string $m, string $n, string $exponent): string
{
    return bcpowmod($m, $exponent, $n);
}

/**
 * 字符串的二进制转数值
 */
function stringToBinitNumber(string $str): string
{
    $binStr = '';
    $num = '';
    // 获取二进制字符串
    foreach (str_split($str) as $char) {
        $bin = decbin(ord($char));
        // 小于128时，需补全8bit，左填0
        if (strlen($bin) < 8) {
            $bin = str_repeat('0', 8 - strlen($bin)) . $bin;
        }
        $binStr .= $bin;
    }

    // 理论上需要反转字符串才能够得到实际对应的十进制值，但我在解密时用除2取余法从十进制转二进制，得到的是逆序的二进制字符串，刚好抵消
    foreach (str_split($binStr) as $index => $binChar) {
        $num = bcadd($num, bcmul($binChar, bcpow('2', (string) $index)));
    }
    return $num;
}

/**
 * 将长数字字符串转为原始数据.
 */
function numberToBinitString(string $num): string
{
    $binStr = '';
    $hexStr = '';
    // 除2取余法转十进制
    while (bccomp($num, '0') > 0) {
        $binStr .= bcmod($num, '2');
        $num = bcdiv($num, '2');
    }
    // 解密时，需要从二进制字符串得到16进制的字符串（防止int型溢出正数范围，以16bit分割）
    foreach (str_split($binStr, 16) as $bin4Char) {
        $hexStr .= dechex(bindec($bin4Char));
    }
    return hex2bin($hexStr);
}

/**
 * 对字符串进行RSA加密运算，获取密文.
 */
function getEncryptedString(string $message, string $n, string $exponent): string
{
    return RSA(stringToBinitNumber($message), $n, $exponent);
}

/**
 * 对字符串进行RSA解密运算，获取明文.
 */
function getDecryptedString(string $encryptedString, string $n, string $exponent): string
{
    return numberToBinitString(RSA($encryptedString, $n, $exponent));
}

// RSA算法的参数，两个大质数p和q
$p = '106697219132480173106064317148705638676529121742557567770857687729397446898790451577487723991083173010242416863238099716044775658681981821407922722052778958942891831033512463262741053961681512908218003840408526915629689432111480588966800949428079015682624591636010678691927285321708935076221951173426894836169';
$q = '144819424465842307806353672547344125290716753535239658417883828941232509622838692761917211806963011168822281666033695157426515864265527046213326145174398018859056439431422867957079149967592078894410082695714160599647180947207504108618794637872261572262805565517756922288320779308895819726074229154002310375209';

// 要加密的明文数据
$message = 'Hello World!';
$Chinese = '你好，世界！';

[$n, $e, $d] = getKey($p, $q);
print_r([$n, $e, $d]);

// 使用私钥钥加密
$encryptedString = getEncryptedString("{$Chinese} {$message}", $n, $d);

print_r([$encryptedString, getDecryptedString($encryptedString, $n, $e)]);
