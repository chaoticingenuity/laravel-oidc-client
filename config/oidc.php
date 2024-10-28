<?php

use Maicol07\OpenIDConnect\JwtSigningAlgorithm;

/** @noinspection LaravelFunctionsInspection */
/** @noinspection JsonEncodingApiUsageInspection */
return [
    'client_id' => env('OIDC_CLIENT_ID'),
    'client_secret' => env('OIDC_CLIENT_SECRET'),
    'client_name' => env('OIDC_CLIENT_NAME', 'oidc'),
    'provider_url' => env('OIDC_PROVIDER_URL'),
    'provider_name' => env('OIDC_PROVIDER_NAME', 'oidc'),
    'issuer' => env('OIDC_ISSUER'),
    'http_proxy' => env('OIDC_HTTP_PROXY'),
    'cert_path' => env('OIDC_CERT_PATH'),
    'verify' => env('OIDC_VERIFY'),
    'scopes' => explode(',', env('OIDC_SCOPES', 'openid')),
    'enable_pkce' => env('OIDC_ENABLE_PKCE', false),
    'enable_nonce' => env('OIDC_ENABLE_NONCE', false),
    'allow_implicit_flow' => env('OIDC_ALLOW_IMPLICIT_FLOW', false),
    'code_challenge_method' => env('OIDC_CODE_CHALLENGE_METHOD', 'S256'),
    'timeout' => env('OIDC_TIMEOUT', 0),
    'time_drift' => env('OIDC_TIME_DRIFT', 300),
    'redirect_uri' => env('OIDC_PROVIDER_NAME', 'oidc') . '/' . env('OIDC_CALLBACK_ROUTE_PATH', 'callback'),
    'response_types' => env('OIDC_RESPONSE_TYPES') ? explode(',', env('OIDC_RESPONSE_TYPES')) : [],
    'authorization_endpoint' => env('OIDC_AUTHORIZATION_ENDPOINT'),
    'authorization_endpoint_query_params' => json_decode(env('OIDC_AUTHORIZATION_ENDPOINT_QUERY_PARAMS', 'null'), true),
    'authorization_response_iss_parameter_supported' => env('OIDC_AUTHORIZATION_RESPONSE_ISS_PARAMETER_SUPPORTED', false),
    'id_token_signing_alg_values_supported' => array_map(fn($algorithm) => JwtSigningAlgorithm::tryFromName($algorithm), explode(',', env('OIDC_ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED', ''))),
    'token_endpoint' => env('OIDC_TOKEN_ENDPOINT'),
    'token_endpoint_auth_methods_supported' => env('OIDC_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED') ? explode(',', env('OIDC_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED')) : [],
    'userinfo_endpoint' => env('OIDC_USERINFO_ENDPOINT'),
    'jwt_signing_method' => env('OIDC_JWT_SIGNING_METHOD', 'sha256'),
    'jwt_key' => env('OIDC_JWT_KEY'),
    'jwt_signing_key' => env('OIDC_JWT_SIGNING_KEY'),
    'jwt_plain_key' => env('OIDC_JWT_PLAIN_KEY'),

    'callback_route_path' => env('OIDC_CALLBACK_ROUTE_PATH', 'callback'),
    'redirect_path_after_login' => env('OIDC_REDIRECT_PATH_AFTER_LOGIN', '/'),
    'redirect_path_after_logout' => env('OIDC_REDIRECT_PATH_AFTER_LOGOUT', '/'),
    'disable_state_middleware_for_post_callback' => env('OIDC_DISABLE_STATE_MIDDLEWARE_FOR_POST_CALLBACK', false),
    'jwks' => null,

    'auth-guard' => env('OIDC_AUTH_GUARD', 'web'),
    'auth-provider' => env('OIDC_AUTH_PROVIDER', 'users'),
    'users_entity_name' => env('OIDC_USERS_ENTITY_NAME', 'users') /** Table/collection name for Users model -- this will be created if necessary */ ,

    'create_new_users' => env('OIDC_CREATE_NEW_USERS', false) /** perist users not found in DB ? */ ,
    'claims_to_persist_on_new_user' => env('OIDC_CLAIMS_TO_PERSIST_ON_NEW_USER', 'all') /** Comma delimited list of claims to set when creating/updating user */ ,
    'users_key_field' => env('OIDC_USERS_KEY_FIELD') /** Necessary for secondary lookup via key field ... initial lookup utilizes uuid from IDP */ ,
];