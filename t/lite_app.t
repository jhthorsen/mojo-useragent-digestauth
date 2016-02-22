use Mojo::Base -strict;

use Test::More;
use Test::Mojo;

use Mojolicious::Lite;
use Mojo::UserAgent::DigestAuth;

plan skip_all => 'TEST_ONLINE=1' unless $ENV{TEST_ONLINE};

get '/' => sub {
  my $c = shift;
  my $tx = $c->ua->$_request_with_digest_auth(get => 'http://user:passwd@httpbin.org/digest-auth/auth/user/passwd');
  $c->render(json => $tx->res->json);
};

my $t = Test::Mojo->new;

$t->get_ok('/')->status_is(200)->json_is('/user', 'user');

done_testing;
