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
use Hyperf\HttpServer\Router\Router;

Router::addRoute(['GET', 'POST', 'HEAD'], '/', 'App\Controller\ROISIndexController@index');

Router::addRoute(['GET', 'POST'], '/api/debug', 'App\Controller\ROISDebugController@debug');

Router::addRoute(['POST'], '/api/register', 'App\Controller\ROISLoginController@register');

Router::addRoute(['POST'], '/api/login', 'App\Controller\ROISLoginController@login');

Router::addRoute(['GET'], '/api/get_aes_key', 'App\Controller\ROISPublicController@aes_key');

Router::get('/favicon.ico', function () {
    return '';
});
