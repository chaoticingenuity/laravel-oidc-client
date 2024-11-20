<?php /** @noinspection UnusedFunctionResultInspection */

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

class AddOidcFieldsToUsers extends Migration
{

    final public function up(): void
    {

        if (strtolower(config('oidc.users_entity_name')) !== 'users') {
            Schema::create(
                config('oidc.users_entity_name'),

                function (Blueprint $table) {
                    $table->id();
                    $table->timestamps();

                    $table->string(config('oidc.users-key-field'), 50)->unique();
                }
            );
        }

        Schema::table(
            config('oidc.users_entity_name'),

            function (Blueprint $table) {
                $column = $table->uuid('uuid')->unique();
                if (Schema::hasColumn(config('oidc.users_entity_name'), 'id')) {
                    $column->after('id');
                }
                $table->text('id_token')->nullable();
            }
        );
    }

    final public function down(): void
    {

        Schema::table(
            config('oidc.users_entity_name'),

            function (Blueprint $table) {
                $table->dropColumn('uuid');
            }
        );

        if (strtolower(config('oidc.users_entity_name')) !== 'users') {
            Schema::drop(config('oidc.users_entity_name'));
        }
    }
}