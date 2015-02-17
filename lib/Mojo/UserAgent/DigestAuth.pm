package Mojo::UserAgent::DigestAuth;

=head1 NAME

Mojo::UserAgent::DigestAuth - Allow Mojo::UserAgent to execute digest auth requests

=head1 VERSION

0.01

=head1 DESCRIPTION

L<Mojo::UserAgent::DigestAuth> is a L<Mojo::UserAgent> "plugin" which can
handle 401 digest auth responses from the server.

Currently, this module only support async requests.

=head1 SYNOPSIS

  use Mojo::UserAgent::DigestAuth;
  my $ua = Mojo::UserAgent->new;

  $ua->$_request_with_digest_auth($method, $url, $headers, $cb);
  $ua->$_request_with_digest_auth($method, $url, $cb);

  $ua->$_request_with_digest_auth(
    get => "http://example.com", sub {
      my ($ua, $tx) = @_;
    }
  );

=cut

use Mojo::Base 'Exporter';
use Mojo::UserAgent;
use Mojo::Util 'md5_sum';
use constant DEBUG => $ENV{MOJO_USERAGENT_DIGEST_AUTH_DEBUG} || 0;

our $VERSION = '0.01';

our @EXPORT = qw( $_request_with_digest_auth );
my $NC = 0;

our $_request_with_digest_auth = sub {
  my $cb = pop;
  my $ua = shift;
  my @args = @_;
  my $tx = $ua->build_tx(@args);
  my @userinfo = split ':', $tx->req->url->userinfo || '';

  $tx->req->url->userinfo(undef);

  return $ua->start($tx, sub {
    my ($ua, $tx) = @_;
    my $code = $tx->res->code || '';
    return $ua->$cb($tx) unless @userinfo == 2 and !$tx->res->headers->header('WWW-Authenticate');
    my $next_tx = $ua->build_tx(@args);
    $next_tx->req->headers->authorization(sprintf 'Digest %s', join ', ', _digest_kv($tx, @userinfo));
    $next_tx->req->headers->accept('*/*');
    $ua->start($next_tx, $cb);
  });
};

sub _digest_kv {
  my ($tx, @userinfo) = @_;
  my %auth_param = $tx->res->headers->header('WWW-Authenticate') =~ /(\w+)="?([^",]+)"?/g;
  my $nc         = sprintf '%08X', ++$NC;
  my ($ha1, $ha2, $response);

  $auth_param{client_nonce} = 'MTx0NzAz'; # TODO
  $auth_param{nonce} //= '__UNDEF__';
  $auth_param{realm} //= '';

  $ha1 = _ha1(\%auth_param, @userinfo);
  $ha2 = _ha2(\%auth_param, $tx->req);

  if ($auth_param{qop} and $auth_param{qop} =~ /^auth/) {
    $response = md5_sum join ':', $ha1, $auth_param{nonce}, $nc, $auth_param{client_nonce}, $auth_param{qop}, $ha2;
    warn "RESPONSE: MD5($ha1:$auth_param{nonce}:$nc:$auth_param{client_nonce}:$auth_param{qop}:$ha2) = $response\n" if DEBUG;
  }
  else {
    $response = md5_sum join ':', $ha1, $auth_param{nonce}, $ha2;
    warn "RESPONSE: MD5($ha1:$auth_param{nonce}:$ha2) = $response\n" if DEBUG;
  }

  return (
    qq(username="$userinfo[0]"),
    qq(realm="$auth_param{realm}"),
    qq(nonce="$auth_param{nonce}"),
    qq(uri="@{[$tx->req->url->path]}"),
    qq(cnonce="$auth_param{client_nonce}"),
    "nc=$nc",
    $auth_param{qop} ? (qq(qop="$auth_param{qop}")) : (),
    qq(response="$response"),
    $auth_param{opaque} ? (qq(opaque="$auth_param{opaque}")) : (),
    qq(algorithm="MD5"),
  );
}

sub _ha1 {
  my ($auth_param, $username, $password) = @_;
  my $res;

  if (!$auth_param->{algorithm} or $auth_param->{algorithm} eq 'MD5') {
    $res = md5_sum join ':', $username, $auth_param->{realm}, $password;
    warn "HA1: MD5($username:$auth_param->{realm}:$password) = $res\n" if DEBUG;
  }
  else {
    $res = md5_sum md5_sum(join ':', $username, $auth_param->{realm}, $password), $auth_param->{nonce}, $auth_param->{client_nonce};
    warn "HA1: MD5(MD5($username:$auth_param->{realm}:$password), $auth_param->{nonce}, $auth_param->{client_nonce}) = $res\n" if DEBUG;
  }

  return $res;
}

sub _ha2 {
  my ($auth_param, $req) = @_;
  my $method     = uc $req->method;
  my $res;

  if (!$auth_param->{qop} or $auth_param->{qop} eq 'auth') {
    $res = md5_sum join ':', $method, $req->url->path;
    warn "HA2: MD5($method:@{[$req->url->path]}) = $res\n" if DEBUG;
  }
  else {
    $res = md5_sum join ':', $method, $req->url->path, md5_sum('entityBody'); #  TODO: entityBody
    warn "HA2: MD5(TODO) = $res\n" if DEBUG;
  }

  return $res;
}

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2014, Jan Henning Thorsen

This program is free software, you can redistribute it and/or modify it under
the terms of the Artistic License version 2.0.

=head1 AUTHOR

Jan Henning Thorsen - C<jhthorsen@cpan.org>

=cut

1;
