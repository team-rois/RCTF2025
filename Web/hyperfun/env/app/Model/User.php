<?php

declare(strict_types=1);
/**
 * This file is part of Hyperf.
 *
 * @link     https://www.hyperf.io
 * @document https://doc.hyperf.io
 * @contact  group@hyperf.io
 * @license  https://github.com/hyperf/hyperf/blob/master/LICENSE
 */

namespace App\Model;

/**
 * @property int $id
 * @property string $mobile
 * @property string $realname
 */
class User extends Model
{
    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected ?string $table = 'user';

    /**
     * The connection name for the model.
     *
     * @var string
     */
    protected ?string $connection = 'default';

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected array $fillable = ['id', 'username', 'password'];

    /**
     * The attributes that should be cast to native types.
     *
     * @var array
     */
//    protected array $casts = ['id' => 'integer'];
}
