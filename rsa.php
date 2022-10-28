<?php

declare(strict_types=1);
/**
 * 可用版RSA加密
 */
const OFFSET = 10;

// base64码值与字符的对应关系
const BASE64_CODE_VALUE = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'];

// base64码值与字符的对应关系(flip)
const BASE64_VALUE_CODE = ['A' => 0, 'Q' => 16, 'g' => 32, 'w' => 48, 'B' => 1, 'R' => 17, 'h' => 33, 'x' => 49, 'C' => 2, 'S' => 18, 'i' => 34, 'y' => 50, 'D' => 3, 'T' => 19, 'j' => 35, 'z' => 51, 'E' => 4, 'U' => 20, 'k' => 36, '0' => 52, 'F' => 5, 'V' => 21, 'l' => 37, '1' => 53, 'G' => 6, 'W' => 22, 'm' => 38, '2' => 54, 'H' => 7, 'X' => 23, 'n' => 39, '3' => 55, 'I' => 8, 'Y' => 24, 'o' => 40, '4' => 56, 'J' => 9, 'Z' => 25, 'p' => 41, '5' => 57, 'K' => 10, 'a' => 26, 'q' => 42, '6' => 58, 'L' => 11, 'b' => 27, 'r' => 43, '7' => 59, 'M' => 12, 'c' => 28, 's' => 44, '8' => 60, 'N' => 13, 'd' => 29, 't' => 45, '9' => 61, 'O' => 14, 'e' => 30, 'u' => 46, '+' => 62, 'P' => 15, 'f' => 31, 'v' => 47, '/' => 63];

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
 * 求私钥D，满足两个条件：1 < D < Z， (E * D) mod Z = 1
 * 简单实现可以用遍历来求，实际使用扩展欧几里得算法求
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
 * 可以采用快速求幂算法，bcMath中已经实现有相关的函数.
 */
function RSA(string $m, string $n, string $exponent): string
{
    return bcpowmod($m, $exponent, $n);
}

/**
 * 中文——》base64编码——》字母转数字（+10）——》加密
 * 对字符串进行RSA加密运算，获取密文.
 */
function getEncryptedString(string $message, string $n, string $exponent): string
{
    // 1、原文转base64
    $base64String = base64_encode($message);

    // 2、base64转数字(逐字母)
    $base64Letters = str_split($base64String);
    $integerString = '';
    foreach ($base64Letters as $base64Letter) {
        $integerString .= BASE64_VALUE_CODE[$base64Letter] + OFFSET;
    }

    // 3、加密
    return RSA($integerString, $n, $exponent);
}

/**
 * 解密——》十进制（2位切割）——》数字转base64字母（-10）——》base64解密
 * 对字符串进行RSA解密运算，获取明文.
 */
function getDecryptedString(string $encryptedString, string $n, string $exponent): string
{
    // 1、解密（得到数字）
    $decryptedString = RSA($encryptedString, $n, $exponent);

    // 2、切割转Base64字符串
    $base64Integers = str_split($decryptedString, 2);
    $base64String = '';
    foreach ($base64Integers as $integer) {
        $base64String .= BASE64_CODE_VALUE[$integer - OFFSET];
    }

    // 3、base64解码
    return base64_decode($base64String);
}

// RSA算法的参数，两个大质数p和q
$p = '106697219132480173106064317148705638676529121742557567770857687729397446898790451577487723991083173010242416863238099716044775658681981821407922722052778958942891831033512463262741053961681512908218003840408526915629689432111480588966800949428079015682624591636010678691927285321708935076221951173426894836169';
$q = '144819424465842307806353672547344125290716753535239658417883828941232509622838692761917211806963011168822281666033695157426515864265527046213326145174398018859056439431422867957079149967592078894410082695714160599647180947207504108618794637872261572262805565517756922288320779308895819726074229154002310375209';

// 要加密的明文数据
$message = 'Hello World!';
$Chinese = '你好，世界！';

// 密钥参数
[$n, $e, $d] = getKey($p, $q);
print_r([$n, $e, $d]);

// 使用公钥加密
$encryptedString = getEncryptedString("{$Chinese} {$message}", $n, $e);

print_r([$encryptedString, getDecryptedString($encryptedString, $n, $d)]);
