<?php

// database/seeders/RbacSeeder.php
namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use Spatie\Permission\Models\Role;
use Spatie\Permission\Models\Permission;

class RbacSeeder extends Seeder
{
    public function run(): void
    {
        $resources = ['users', 'roles', 'permissions'];
        $actions = ['view', 'create', 'update', 'delete'];

        foreach ($resources as $res) {
            foreach ($actions as $act) {
                Permission::firstOrCreate([
                    'name' => "{$act} {$res}",
                    'guard_name' => 'web',
                ]);
            }
        }

        $admin = Role::firstOrCreate(['name' => 'Admin', 'guard_name' => 'web']);
        $admin->givePermissionTo(Permission::all());

        $adminUser = User::firstOrCreate(
            ['email' => 'admin@example.com'],
            ['name' => 'Admin', 'password' => Hash::make('password')]
        );

        $adminUser->assignRole('Admin');
    }
}
