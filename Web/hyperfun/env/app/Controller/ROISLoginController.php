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

use Hyperf\DbConnection\Db;
use HyperfExt\Encryption\Crypt;
use  App\Common\Response;
use Hyperf\Di\Annotation\Inject;
use Hyperf\Contract\SessionInterface;
class ROISLoginController extends AbstractController
{

    #[Inject]
    private SessionInterface $session;

    public function login()
    {
//        posix_getpwnam()
        $data = $this->request->input('data');
        if (empty($data)){
            return $this->response->json(Response::json_err(500,"empty data!"))->withStatus(500);
        }

        try {
            $data = Crypt::decrypt($data,false);
            $data = json_decode($data, true, 512, JSON_THROW_ON_ERROR);
        } catch (\Exception $e) {
                return $this->response->json(Response::json_err(500,$e->getMessage()))->withStatus(500);
        }


        $username = trim($data['username']);
        $password = trim($data['password']);

        if (empty($username) || empty($password)){
            return $this->response->json(Response::json_err(400,"username or password cannot be empty!"))->withStatus(400);
        }

        $user = Db::select('SELECT * FROM user where username = ? and password = ?',[$username, $password]);

        if (empty($user)){
            return $this->response->json(Response::json_err(400,"username or password was incorrect!"))->withStatus(400);
        }

        $this->session->set('user',$username);

        return $this->response->json(Response::json_ok(
            [
                'message' => 'login success!',
                'username' => $username
            ]
        ));
    }

    public function register()
    {
        $data = $this->request->input('data');
        if (empty($data)){
            return $this->response->json(Response::json_err(500,"empty data!"))->withStatus(500);
        }


        try {
            $data = Crypt::decrypt($data, false);
            $data = json_decode($data, true, 512, JSON_THROW_ON_ERROR);
        } catch (\Exception $e) {
            return $this->response->json(Response::json_err(500,$e->getMessage()))->withStatus(500);
        }


        $username = trim($data['username']);
        $password = trim($data['password']);

        if (empty($username) || empty($password)){
            return $this->response->json(Response::json_err(400,"username or password cannot be empty!"))->withStatus(400);
        }

        $user = Db::select('SELECT * FROM user where username = ?',[$username]);

        if (!empty($user)){
            return $this->response->json(Response::json_err(400,"username has been registered"))->withStatus(400);
        }

        $insert = Db::insert("INSERT INTO user (username, password) values (? , ?)",[$username, $password]);

        if (! $insert){
            return $this->response->json(Response::json_err(500,"register failed!"))->withStatus(500);
        }

        return $this->response->json(Response::json_ok([
            'message' => 'register success!',
            'username' => $username
        ]));
    }
}
