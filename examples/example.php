<?php
    $ewdjs = new EwdjsClient();

    $params = array(
        "sessid" => 1
    );

    $result = $ewdjs->callEwdService("webServiceExample",$params);
    if($result["error"]){
        echo '{error: "' . $result["response"] . '"}';
    }
    else {
        echo $result["response"];
    }
?>