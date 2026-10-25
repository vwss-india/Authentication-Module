<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class CentralAdmin extends Model
{
    protected $fillable = [
        'user_id',
        'granted_by_user_id',
        'revoked_by_user_id',
        'grant_reason',
        'permissions',
        'revoked_at',
    ];

    protected function casts(): array
    {
        return [
            'revoked_at' => 'datetime',
            'permissions' => 'array',
        ];
    }
}
