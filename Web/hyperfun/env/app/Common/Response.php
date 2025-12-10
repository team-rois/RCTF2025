<?php
declare(strict_types=1);

namespace App\Common{
    abstract class Response
    {
        public static function json_ok($arr): array
        {
            $res = array(
                "status" => "success",
                "code" => 200
            );

//            var_dump(array_merge($res, $arr));

            return array_merge($res, $arr);
        }

        public static function json_err($code, $message): array
        {
            return array(
                "status" => "fail",
                "code" => $code,
                "message" => $message
            );
        }
    }

}
