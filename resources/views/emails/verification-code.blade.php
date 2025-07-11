<x-mail::message>
# Hello {{ $name }}!

@if($type === 'password_reset')
You requested to reset your password for your wejha account.
@else
Thank you for registering with wejha.
@endif

Here is your verification code:

<h2 style="font-size: 36px; text-align: center; padding: 10px; background-color:rgb(214, 50, 50); letter-spacing: 5px;">{{ $code }}</h2>

@if($type === 'password_reset')
This code will expire in 15 minutes. If you did not request a password reset, please ignore this email.
@else
This code will expire in 10 minutes.
@endif

Thanks,<br>
{{ config('app.name') }}
</x-mail::message>
