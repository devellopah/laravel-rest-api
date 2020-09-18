<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    protected $fillable = [
        'title',
        'slug',
        'likes',
        'content',
    ];

    protected $casts = [
        'likes' => 'integer',
    ];
}
