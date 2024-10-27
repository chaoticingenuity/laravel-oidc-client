<?php /** @noinspection UnusedFunctionResultInspection */

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

class AddOidcFieldsToUsers extends Migration
{
    final public function up(): void
    {
        Schema::table(config('oidc.users_entity_name'), function (Blueprint $table) {
            $column = $table->uuid('uuid')->unique();
            if (Schema::hasColumn('users', 'id')) {
                $column->after('id');
            }
            $table->string('id_token')->nullable();
        });
    }

    final public function down(): void
    {
        Schema::table(config('oidc.users_entity_name'), function (Blueprint $table) {
            $table->dropColumn('uuid');
        });
    }
}
