<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Tests\TestCase;

class PortalTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        $this->withoutVite();
    }

    public function test_public_homepage_uses_the_central_auth_landing_page(): void
    {
        $this->get('/')
            ->assertOk()
            ->assertSee('One secure sign-in');
    }

    public function test_authentication_pages_use_the_shared_visionweb_layout_and_reset_is_private(): void
    {
        foreach (['/login', '/register', '/verify-email', '/forgot-password'] as $path) {
            $this->get($path)
                ->assertOk()
                ->assertSee('class="vwss-app"', false)
                ->assertSee('name="csrf-token"', false);
        }

        $this->get('/reset-password?token=example-token&email=user%40example.test')
            ->assertOk()
            ->assertSee('class="vwss-app"', false)
            ->assertSee('Reset your password')
            ->assertHeader('Referrer-Policy', 'no-referrer')
            ->assertHeader('Cache-Control', 'no-store, private');
    }

    public function test_passport_authorization_and_device_views_use_the_shared_layout_and_real_actions(): void
    {
        $user = User::factory()->create(['status' => 'active']);
        $client = (object) ['id' => (string) Str::uuid(), 'name' => 'VisionWeb Test Client'];

        $this->withViewErrors([])->actingAs($user)->view('auth.oauth.authorize', [
            'client' => $client,
            'user' => $user,
            'scopes' => collect(),
            'authToken' => 'test-authorization-form-token',
        ])
            ->assertSee('class="vwss-app"', false)
            ->assertSee('Approve access')
            ->assertSee('Deny')
            ->assertSee(route('passport.authorizations.approve'), false)
            ->assertSee(route('passport.authorizations.deny'), false);

        $this->withViewErrors([])->view('auth.oauth.device.user-code')
            ->assertSee('class="vwss-app"', false)
            ->assertSee('name="user_code"', false)
            ->assertSee(route('passport.device.authorizations.authorize'), false);

        $request = Request::create('/oauth/device/authorize');
        $request->setLaravelSession($this->app['session.store']);

        $this->actingAs($user)->view('auth.oauth.device.authorize', [
            'client' => $client,
            'user' => $user,
            'scopes' => collect(),
            'authToken' => 'test-device-form-token',
            'request' => $request,
        ])
            ->assertSee('class="vwss-app"', false)
            ->assertSee('Approve device')
            ->assertSee('Deny')
            ->assertSee(route('passport.device.authorizations.approve'), false)
            ->assertSee(route('passport.device.authorizations.deny'), false);
    }

    public function test_account_and_security_pages_require_a_web_session(): void
    {
        $this->get('/account')->assertRedirect('/login');
        $this->get('/account/security')->assertRedirect('/login');
    }

    public function test_account_page_displays_only_the_authenticated_users_identity(): void
    {
        $user = User::factory()->create(['name' => 'Visible Account', 'status' => 'active']);
        User::factory()->create(['name' => 'Private Other Account', 'email' => 'other@example.test', 'status' => 'active']);

        $this->actingAs($user)->get('/account')
            ->assertOk()
            ->assertSee('Visible Account')
            ->assertDontSee('Private Other Account');
    }

    public function test_security_page_is_scoped_to_the_authenticated_users_events(): void
    {
        $user = User::factory()->create(['status' => 'active']);
        $other = User::factory()->create(['status' => 'active']);

        foreach ([[$user, 'auth.login', 'success'], [$other, 'private.other.event', 'success']] as [$owner, $type, $result]) {
            DB::table('security_events')->insert([
                'event_id' => (string) Str::uuid(),
                'user_id' => $owner->id,
                'event_type' => $type,
                'result' => $result,
                'context' => json_encode([]),
                'occurred_at' => now(),
            ]);
        }

        $this->actingAs($user)->get('/account/security')
            ->assertOk()
            ->assertSee('Auth.login')
            ->assertDontSee('Private Other Event');
    }
}
