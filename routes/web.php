<?php

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::get('/', function () {
    return view('welcome');
});

Auth::routes();

Route::get('/home', 'HomeController@index')->name('home');

Route::get('login/{facebook}', 'Auth\LoginController@redirectToProvider');
Route::get('login/{facebook}/callback', 'Auth\LoginController@handleProviderCallback');

Route::get('login/{twitter}', 'Auth\LoginController@redirectToProvider');
Route::get('login/{twitter}/callback', 'Auth\LoginController@handleProviderCallback');

Route::get('login/{linkedin}', 'Auth\LoginController@redirectToProvider');
Route::get('login/{linkedin}/callback', 'Auth\LoginController@handleProviderCallback');

Route::get('login/{google}', 'Auth\LoginController@redirectToProvider');
Route::get('login/{google}/callback', 'Auth\LoginController@handleProviderCallback');

Route::get('login/{github}', 'Auth\LoginController@redirectToProvider');
Route::get('login/{github}/callback', 'Auth\LoginController@handleProviderCallback');

Route::get('login/{gitlab}', 'Auth\LoginController@redirectToProvider');
Route::get('login/{gitlab}/callback', 'Auth\LoginController@handleProviderCallback');

Route::get('login/{bitbucket}', 'Auth\LoginController@redirectToProvider');
Route::get('login/{bitbucket}/callback', 'Auth\LoginController@handleProviderCallback');
