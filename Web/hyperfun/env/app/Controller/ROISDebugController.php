<?php

declare(strict_types=1);


namespace App\Controller;

use App\Common\Response;
use HyperfExt\Encryption\Crypt;
use Hyperf\Di\Annotation\Inject;
use Hyperf\Contract\SessionInterface;
class ROISDebugController extends AbstractController
{

    #[Inject]
    private SessionInterface $session;
    public function debug()
    {
        $username = $this->session->get('user');
        if ($username !== 'admin'){
            return $this->response->json(Response::json_err(401, "only admin can debug"))->withStatus(401);
        }

        $option = $this->request->input('option');

        switch ($option){
            case 'read_file':{

                $filename = $this->request->input('filename','');

                try {
                    return $this->response->download(BASE_PATH. '/'. $filename, $filename);
                }catch (\Exception $e){
                    return $this->response->json(Response::json_err(500,$e->getMessage()))->withStatus(500);
                }
            }
            case 'aes_encrypt':{
                $data = $this->request->input('data','');
                if (empty($data)){
                    return $this->response->json(Response::json_err(500,"data is needed"))->withStatus(500);
                }
                $crypt = Crypt::encrypt($data);
                return $this->response->json(
                    Response::json_ok([
                        'data' => $data,
                        'encrypted' => $crypt
                    ])
                );
            }
            case 'aes_decrypt':{
                $data = $this->request->input('data','');
                if (empty($data)){
                    return $this->response->json(Response::json_err(500,"data is needed"))->withStatus(500);
                }

                $decrypt = Crypt::decrypt($data);
                return $this->response->json(
                    Response::json_ok([
                        'data' => $data,
                        'decrypted' => $decrypt
                    ])
                );
            }
            default :{
                return $this->response->json(
                    Response::json_ok([
                        'option_list' => [
                            'aes_encrypt' => 'encrypt data, eg: {"username":"admin", "password": "123321"}',
                            'aes_decrypt' => 'decrypt data',
                            'read_file' => 'debug to read files in the web directory',
                        ]
                    ])
                );
            }
        }


    }

}
