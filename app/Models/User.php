<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;
use Illuminate\Database\Eloquent\SoftDeletes;
use Tymon\JWTAuth\Contracts\JWTSubject;
use Ramsey\Uuid\Uuid;

class User extends Authenticatable implements JWTSubject
{
    use HasApiTokens, HasFactory, Notifiable, SoftDeletes;

    /**
     * Indicates if the model's ID is auto-incrementing.
     *
     * @var bool
     */
    public $incrementing = false;

    /**
     * The data type of the auto-incrementing ID.
     *
     * @var string
     */
    protected $keyType = 'string';

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'id',
        'fname',
        'lname',
        'type',
        'email',
        'email_verified_at',
        'password',
        'phone',
        'gender',
        'birthday',
        'auth_provider',
        'photo',
        'role_id', // Add this line
        'refresh_token_hash',
        'refresh_token_expires_at'
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var list<string>
     */
    protected $hidden = [
        'password',
        'remember_token',
        'refresh_token_hash',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'birthday' => 'date',
            'refresh_token_expires_at' => 'datetime',
            'password' => 'hashed',
        ];
    }

    /**
     * The "booting" method of the model.
     *
     * @return void
     */
    protected static function boot()
    {
        parent::boot();

        static::creating(function ($model) {
            if (!$model->id) {
                $model->id = static::generateUuid();
            }
        });
    }

    /**
     * Generate a UUID.
     *
     * @return string
     */
    protected static function generateUuid()
    {
        return Uuid::uuid4()->toString();
    }

    /**
     * Get the role that owns the user.
     */
    public function role()
    {
        return $this->belongsTo(\Modules\User\Models\Role::class);
    }

    /**
     * Check if the user has a specific role.
     *
     * @param string $role
     * @return bool
     */
    public function hasRole($role)
    {
        return $this->role->name === $role;
    }

    /**
     * Check if the user has any of the given roles.
     *
     * @param array $roles
     * @return bool
     */
    public function hasAnyRole($roles)
    {
        if (is_array($roles)) {
            return $this->roles()->whereIn('name', $roles)->exists();
        }
        
        return $this->hasRole($roles);
    }

    /**
     * Check if the user has a permission through their roles.
     *
     * @param string $permission
     * @return bool
     */
    public function hasPermission($permission)
    {
        return $this->roles()->whereHas('permissions', function ($query) use ($permission) {
            $query->where('name', $permission);
        })->exists();
    }

    /**
     * Get the identifier that will be stored in the subject claim of the JWT.
     *
     * @return mixed
     */
    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    /**
     * Return a key value array, containing any custom claims to be added to the JWT.
     *
     * @return array
     */
    public function getJWTCustomClaims()
    {
        return [];
    }
}
