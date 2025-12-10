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
use function Hyperf\Support\env;

return [
    'default'=>[
        'driver' => env('DB_DRIVER', 'sqlite'),
        'host' => env('DB_HOST', 'localhost'),
        // :memory: 为内存数据库 也可以指定文件绝对路径
        'database' => env('DB_DATABASE', BASE_PATH.'/storage/database.db'),
        // other sqlite config
    ]
];
