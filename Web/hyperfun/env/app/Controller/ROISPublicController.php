<?php

declare(strict_types=1);
/**
 * This file is part of Hyperf.
 *
 * @link     https://www.hyperf.io
 * @document https://hyperf.wiki
 * @contact  group@hyperf.io
 * @license  https://github.com/hyperf/hyperf/blob/master/LICENSE
 */

namespace App\Controller;

use App\Common\Response;
use function Hyperf\Support\env;

class ROISPublicController extends AbstractController
{
    public function aes_key()
    {
        $key = env('AES_KEY','');
        if (empty($key)){
            return $this->response->json(Response::json_err(500,"no aes key set!"))->withStatus(500);
        }

        return $this->response->json(Response::json_ok([
            "key" => $key
        ]));
    }
}
