<?php

namespace Chuanglan\Shanyan;

use Chuanglan\Shanyan\Exceptions\ServerErrorException;
use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\RequestOptions;


class ShanyanService
{
    const MOBILE_QUERY_URL = 'https://api.253.com/open/flashsdk/mobile-query';

    const MOBILE_VALIDATE_URL = 'https://api.253.com/open/flashsdk/mobile-validate';

    const RESPONSE_PHRASES = [
        '200000' => '请求成功',
        '400001' => '参数校验异常',
        '403000' => '用户校验失败',
        '415000' => '请求数据转换异常',
        '500000' => '系统异常',
        '500002' => '数据处理异常',
        '500003' => '业务操作失败',
        '500004' => '远程调用失败',
        '500005' => '账户余额异常',
        '500006' => '请求外部系统失败',
        '504000' => '系统超时',
        '400101' => '在下游系统中的商户信息不存在',
        '403101' => '账户被下游系统禁用',
        '403102' => '账户在下游系统中没有被激活',
        '510101' => '在下游系统中的用户产品可用数量不足',
        '400102' => '商户IP地址在下游系统中不合法',
        '400200' => '黑名单列表',
        '400201' => '手机号码不能为空',
        '400901' => '账户信息不存在',
        '400902' => '应用类型信息不存在',
        '500901' => '邮箱未设置',
        '500902' => '账户信息已存在',
        '500903' => '账户相关能力已激活'
    ];

    /**
     * http client
     * @var \GuzzleHttp\ClientInterface
     */
    private $client;

    private $appid;

    private $appkey;

    private $encryptType = "aes";

    private $privateKey;

    private $publicKey;

    /**
     * ShanyanService constructor.
     *
     * $config = [
     *      "appid" => 'xxxxxxxxx',
     *      "appkey" => 'xxxxxxxx'
     * ]
     *
     * @param array $config accept an array of constructor parameters. 接受一个数据作为初始化参数.
     * @param ClientInterface|null $client accepts an HTTP client that conforms to the guzzleClient interface specification  第二个参数接收一个实现了\GuzzleHttp\ClientInterface接口的客户端，非必填
     */
    public function __construct($config, ClientInterface $client = null){
        if (!isset($config['appid'])){
            throw new ServerErrorException("appid is required");
        }
        $this->appid = $config['appid'];
        if (!isset($config['appkey'])){
            throw new ServerErrorException("appkey is required");
        }
        $this->appkey = $config['appkey'];

        if (isset($config['encrypt_type'])){
            $this->encryptType = $config['encrypt_type'];
        }

        if($this->encryptType == "rsa"){
            if (!isset($config['rsa_private_key'])){
                throw new ServerErrorException("encrypt_type is rsa, rsa_private_key is required");
            }

            $this->privateKey = $config['rsa_private_key'];
        }

        $this->client = $client ?: $this->createDefaultHttpCLient();
    }

    /**
     * get mobile num from token
     * @param $token
     * @param array $param = [
     *      "out_id" => '123456',
     *      "client_ip" => '127.0.0.1'
     * ]
     * @return $data = [
     *      "mobile" => "133xxxx3333" // 手机号
     *      "trade_no" => "110110110110" // 流水号
     *      "charge_status" => "1" // 是否收费
     * ]
     * @throws ServerErrorException
     */
    public function getMobile($token, $param = []){

        $responseArray = $this->doGetMobile($token, $param);

        $encryptMobile = $responseArray["data"]["mobileName"];
        $tradeNo = $responseArray["data"]["tradeNo"];
        $chargeStatus = $responseArray["chargeStatus"];

        $data = [
            "mobile" => $this->decryMobile($encryptMobile),
            "trade_no" => $tradeNo,
            "charge_status" => $chargeStatus
        ];

        return $data;
    }

    // decry the moble
    public function decryMobile($encryptMobile){
        if ($this->encryptType === 'aes'){
            $key=md5($this->appkey);
            $mobile=openssl_decrypt(hex2bin($encryptMobile),  'AES-128-CBC', substr($key,0,16), OPENSSL_RAW_DATA,  substr($key,16));
        }elseif($this->encryptType === 'rsa'){
            $pi_key =  openssl_pkey_get_private($this->privateKey);
            openssl_private_decrypt(hex2bin($encryptMobile),$mobile,$pi_key);//私钥解密
        }

        return $mobile;
    }

    /**
     * send Request for query mobile
     *
     * @param $token
     * @param array $param
     * @return \Psr\Http\Message\ResponseInterface
     * @throws ServerErrorException
     */
    private function doGetMobile($token, $param = []){
        $response = $this->client->request('POST', $this->getQueryModebileUrl(), [
            RequestOptions::FORM_PARAMS => $this->buildRequestForQueryMobile($token, $param)
        ]);

        if ($response) {
            $this->parseResponse($response);
        } else {
            throw new ServerErrorException('服务异常');
        }

        $body = (string) $response->getBody();
        $responseArray = json_decode($body, true);

        return $responseArray;
    }

    // parse the response
    private function parseResponse(Response $response){
        if ($response->getStatusCode() != 200){
            throw new ServerErrorException('服务异常');
        }

        $responseBody = (string) $response->getBody();
        $responseArray = json_decode($responseBody, true);
        if (!$responseArray){
            throw new ServerErrorException('服务异常');
        }

        if ($responseArray["code"] != '200000') {
            throw new ServerErrorException(array_get(self::RESPONSE_PHRASES, $responseArray['code'],
                sprintf('服务异常(%s)', $responseArray['code'])));
        }

    }

    // build the request param for query mobile
    private function buildRequestForQueryMobile($token, $param){
        $outId = array_get($param, "out_id", "");
        $clientIp = array_get($param, "client_ip", "");

        $data = [
            "appId" => $this->appid,
            "token" => $token,
            "outId" => $outId,
            'clientIp' => $clientIp,
            'encryptType' => $this->encryptType === "rsa" ? '1' : '0',
        ];

        $sign = $this->calculateSign($data);

        $data["sign"] = $sign;

        return $data;
    }

    // get the requrest url for query mobile
    private function getQueryModebileUrl(){
        return self::MOBILE_QUERY_URL;
    }

    /**
     * create default http client
     *
     * @param array $config Client configuration settings. see \GuzzleHttp\Client::__construct()
     * @return Client
     */
    private function createDefaultHttpClient(array $config = []){
        return new Client($config);
    }

    /**
     * calculate the sign for query fields sign
     *
     * @param $param
     * @return string
     */
    private function calculateSign($param){

        ksort($param);

        $string = "";
        foreach($param as $key => $value){
            $string .= $key.$value;
        }

        return bin2hex(hash_hmac('sha256',$string, $this->appkey, true));
    }

}