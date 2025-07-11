<?php

namespace Modules\Verification\Http\Controllers;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\DB;
use App\Mail\VerificationCodeMail;

class VerificationController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        return view('verification::index');
    }

    /**
     * Show the form for creating a new resource.
     */
    public function create()
    {
        return view('verification::create');
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request) {}

    /**
     * Show the specified resource.
     */
    public function show($id)
    {
        return view('verification::show');
    }

    /**
     * Show the form for editing the specified resource.
     */
    public function edit($id)
    {
        return view('verification::edit');
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, $id) {}

    /**
     * Remove the specified resource from storage.
     */
    public function destroy($id) {}

    /**
     * Send a verification code to the user's email.
     */
    public function sendCode(Request $request)
    {
        $request->validate([
            'fname' => 'required|string',
            'lname' => 'required|string',
            'email' => 'required|email',
        ]);

        $code = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);

        DB::table('verification_codes')->updateOrInsert(
            ['email' => $request->email, 'type' => 'registration'],
            [
                'fname' => $request->fname,
                'lname' => $request->lname,
                'code' => $code,
                'type' => 'registration',
                'expires_at' => now()->addMinutes(10),
                'verified' => false,
                'updated_at' => now(),
                'created_at' => now(),
            ]
        );

        // Send verification code email
        Mail::to($request->email)->send(new VerificationCodeMail([
            'name' => $request->fname,
            'code' => $code,
            'type' => 'registration'
        ]));

        return response()->json(['message' => 'Verification code sent.']);
    }

    /**
     * Verify the code sent to the user's email.
     */
    public function verifyCode(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'code' => 'required|digits:6',
        ]);

        $verification = DB::table('verification_codes')
            ->where('email', $request->email)
            ->where('code', $request->code)
            ->where('type', 'registration')
            ->where('expires_at', '>', now())
            ->first();

        if (!$verification) {
            return response()->json(['message' => 'Invalid or expired code.'], 422);
        }

        DB::table('verification_codes')
            ->where('email', $request->email)
            ->where('type', 'registration')
            ->update(['verified' => true]);

        return response()->json(['message' => 'Email verified.']);
    }
}
