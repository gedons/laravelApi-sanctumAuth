<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\ProductController;
use App\Http\Controllers\UserController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/


//Route::resource('products',  ProductController::class);

//public routes
Route::post('/register',  [UserController::class, 'register']);
Route::post('/login',  [UserController::class, 'login']);
Route::get('/products',  [ProductController::class, 'index']);
Route::get('/products/{id}',  [ProductController::class, 'show']);
Route::get('/products/search/{name}',  [ProductController::class, 'search']);



//protected routes using sanctum
Route::group(['middleware' => ['auth:sanctum']], function() {

   Route::post('/products',  [ProductController::class, 'store']);
   Route::put('/products/{id}',  [ProductController::class, 'update']);
   Route::delete('/products/{id}',  [ProductController::class, 'destroy']);
   Route::post('/logout',  [UserController::class, 'logout']);

});






Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});
