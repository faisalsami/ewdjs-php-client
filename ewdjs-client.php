<?php
class EwdjsClient
{
    private $obj = array(
        "host" => "192.168.1.1", //host server url
        "port" => "8080", //ewdjs port
        "ssl" => false, //enable or disable ssl
        "appName" => "demo", //ewdjs application name
        "serviceName" => "",
        "secretKey" => "admin", //Secret Key
        "returnUrl" => false,
        "params" => array(
            "accessId" => "admin"
        )
    );

    private function _uniord($c)
    {
    if (ord($c{0}) >=0 && ord($c{0}) <= 127)
            return ord($c{0});
        if (ord($c{0}) >= 192 && ord($c{0}) <= 223)
            return (ord($c{0})-192)*64 + (ord($c{1})-128);
        if (ord($c{0}) >= 224 && ord($c{0}) <= 239)
            return (ord($c{0})-224)*4096 + (ord($c{1})-128)*64 + (ord($c{2})-128);
        if (ord($c{0}) >= 240 && ord($c{0}) <= 247)
            return (ord($c{0})-240)*262144 + (ord($c{1})-128)*4096 + (ord($c{2})-128)*64 + (ord($c{3})-128);
        if (ord($c{0}) >= 248 && ord($c{0}) <= 251)
            return (ord($c{0})-248)*16777216 + (ord($c{1})-128)*262144 + (ord($c{2})-128)*4096 + (ord($c{3})-128)*64 + (ord($c{4})-128);
        if (ord($c{0}) >= 252 && ord($c{0}) <= 253)
            return (ord($c{0})-252)*1073741824 + (ord($c{1})-128)*16777216 + (ord($c{2})-128)*262144 + (ord($c{3})-128)*4096 + (ord($c{4})-128)*64 + (ord($c{5})-128);
        if (ord($c{0}) >= 254 && ord($c{0}) <= 255)    //  error
            return FALSE;
        return 0;
    }

    private function encodeURIComponent($str)
    {
        $revert = array('%21'=>'!', '%2A'=>'*', '%27'=>"'", '%28'=>'(', '%29'=>')');
        return strtr(rawurlencode($str), $revert);
    }

    private function escape($string, $encode) {
        if ($encode === "escape") {
            $unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~";
            $escString = "";
            $c = "";
            $hex = "";
            for ($i = 0; $i <= strlen($string); $i++) {
                $c = substr( $string, $i, 1 );
                if (strpos($unreserved,$c)) {
                    $escString = $escString . $c;
                }
                else {
                    $hex = strtoupper((string)_uniord($c));
                    if (strlen($hex) == 1) $hex = "0" . $hex;
                    $escString = $escString . "%" . $hex;
                }
            }
            return $escString;
        }
        else {
            $enc = $this->encodeURIComponent($string);
            $enc = str_replace("*","%2A",$enc);
            $enc = str_replace("'","%27",$enc);
            $enc = str_replace("!","%21",$enc);
            $enc = str_replace("(","%28",$enc);
            $enc = str_replace(")","%29",$enc);
            return $enc;
        }
    }

    private function createStringToSign($action, $includePort, $encodeType) {
        $stringToSign = "";
        $name = "";
        $amp = "";
        $value = "";
        $keys = array();
        $index = 0;
        $pieces = "";
        $host = $action["host"];
        if ($includePort) {
            if (strpos($host,":")) {
                $pieces = explode(":", $host);
                $host = $pieces[0];
            }
        }
        $url = $action["uri"];
        $method = "GET"; // should be $action["method"]
        $stringToSign = $method . "\n" . $host . "\n" . $url . "\n";
        reset($action["query"]);
        while (list($key, $val) = each($action["query"])) {
            if ($key !== "signature") {
                $keys[$index] = $key;
                $index++;
            }
        }
        sort($keys);
	    foreach ($keys as $val) {
            $name = $val;
            $value = $action["query"][$name];
            $stringToSign = $stringToSign . $amp . $this->escape($name, $encodeType) . '=' . $this->escape($value, $encodeType);
            $amp = '&';
	    }
        return $stringToSign;
    }

    private function digest($string, $key, $type) {
        $s = hash_hmac('sha256', $string, $key, true);
        return base64_encode($s);
    }

    public function callEwdService($inserviceName,$inParams){
        $obj = $this->obj;
        $obj["serviceName"] = $inserviceName;
        foreach ($inParams as $ikey => $ivalue) {
            $obj["params"][$ikey] = $ivalue;
        }
        $params = $obj["params"];
        $secretKey = $obj["secretKey"];
        $appName = $obj["appName"];
        $serviceName = $obj["serviceName"];
        $method = "GET";
        if (array_key_exists('method', $obj)) {
            $method = $obj["method"];
        }
        $post_data = "";
        $amp = "";
        $name = "";
        $timeout = "120000";
        if (array_key_exists('timeout', $obj)) {
            $timeout = $obj["timeout"];
        }
        if ($method == 'POST' || $method == 'PUT') {
            $post_data = $obj["post_data"];
        }
        $path = '/' . $appName . '/' . $serviceName;
        if (!array_key_exists('ewdjs', $obj)) {
            $obj["ewdjs"] = true;
        }
        if ($obj["ewdjs"]) {
            $path = '/json/' . $appName . '/' . $serviceName;
        }
        else {
            $path = '/' . $obj["params"]["rest_path"];
            $amp = '?';
            while (list($key, $val) = $obj["params"]) {
                if ($key !== 'accessId' && strrpos($key, "rest_")) {
                    $path = $path . $amp . $name . '=' . $obj["params"][$key];
                    $amp = '&';
                }
            }
        }
        $options = array(
            "hostname" => $obj["host"],
            "port" => $obj["port"],
            "method" => $method,
            "path" => $path,
            "agent" => false,
            "data" => $post_data,
            "rejectUnauthorized" => false
        );
        if ($obj["ewdjs"] && $secretKey !== '') {
            $uri = $options["path"];
            $params["timestamp"] = gmdate('D, d M Y H:i:s T', time());
            $amp = '?';
	        foreach ($params as $key => $value) {
                $options["path"] = $options["path"] . $amp . $this->escape($key, 'uri') . '=' . $this->escape($value, 'uri');
                $amp = '&';
	        }
            $action = array(
                "host" => $options["hostname"],
                "query" => $params,
                "uri" => $uri,
                "method" => $options["method"]
            );
            $stringToSign = $this->createStringToSign($action, false, "uri");
	        $hash = $this->digest($stringToSign, $secretKey, 'sha256');
	        $options["path"] = $options["path"] . '&signature=' . $this->escape($hash, 'uri');
        }
        $req = 'http';
        if ($obj["ssl"]) {
            $req = 'https';
        }
        $requestUrl = $req . '://' . $options["hostname"] . ':' . $options["port"] . $options["path"];
	    if (array_key_exists('returnUrl', $obj)) {
            if ($obj["returnUrl"]){
                return $requestUrl;
            }
        }
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $requestUrl);

        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        $response = curl_exec($ch);
        $rtrnarr = array();
        if($response === false)
        {
            $rtrnarr["error"] = true;
            $rtrnarr["response"] = curl_error($ch);
        }else {
            $rtrnarr["error"] = false;
            $rtrnarr["response"] = $response;
        }

        curl_close($ch);

        return $rtrnarr;
    }
}
?>