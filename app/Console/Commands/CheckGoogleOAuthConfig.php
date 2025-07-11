<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;

class CheckGoogleOAuthConfig extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'oauth:check-google';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Check Google OAuth configuration';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $this->info('Checking Google OAuth Configuration...');
        
        $clientId = config('services.google.client_id');
        $clientSecret = config('services.google.client_secret');
        $redirectUri = config('services.google.redirect');
        
        $this->info('Client ID: ' . ($clientId ? $clientId : 'Not set'));
        $this->info('Client Secret: ' . ($clientSecret ? 'Set (hidden)' : 'Not set'));
        $this->info('Redirect URI: ' . ($redirectUri ? $redirectUri : 'Not set'));
        
        if (!$clientId || !$clientSecret || !$redirectUri) {
            $this->error('Google OAuth is not properly configured. Please check your .env file.');
            $this->line('Add the following to your .env file:');
            $this->line('GOOGLE_CLIENT_ID=your-google-client-id');
            $this->line('GOOGLE_CLIENT_SECRET=your-google-client-secret');
            $this->line('GOOGLE_REDIRECT_URI=http://localhost:8000/api/v1/auth/google/callback');
        } else {
            $this->info('Google OAuth configuration looks good!');
            $this->line('Make sure the redirect URI matches exactly what you have in Google Cloud Console.');
        }
    }
} 