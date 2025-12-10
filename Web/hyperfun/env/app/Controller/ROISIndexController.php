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

class ROISIndexController extends AbstractController
{
    public function index()
    {
        return $this->response->html(file_get_contents(BASE_PATH."/storage/view/index.blade.php"));
    }
}
