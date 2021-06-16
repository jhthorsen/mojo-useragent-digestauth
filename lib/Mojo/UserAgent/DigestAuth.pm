package Mojo::UserAgent::DigestAuth;
use Mojo::Base 'Exporter';
use Mojo::UserAgent;
use Mojo::Util 'md5_sum';
use constant DEBUG => $ENV{MOJO_USERAGENT_DIGEST_AUTH_DEBUG} || 0;

our $VERSION = '0.04';
our @EXPORT  = qw( $_request_with_digest_auth );
my $NC = 0;

our $_request_with_digest_auth = sub {
  my $cb   = ref $_[-1] eq 'CODE' ? pop : undef;
  my $ua   = shift;
  my @args = @_;
  my $tx   = $ua->build_tx(@args);
  my $auth = {};

  @$auth{qw(username password)} = split ':', $tx->req->url->userinfo || '';

  if (my $client_nonce = $tx->req->headers->header('D-Client-Nonce')) {
    $auth->{client_nonce} = $client_nonce;
    _clean_tx($tx);
  }

  $tx->req->url($tx->req->url->clone)->url->userinfo(undef);
  warn "[DigestAuth] url=@{[$tx->req->url]}\n" if DEBUG;

  my $build_next = sub {
    my $tx   = shift;
    my $code = $tx->res->code || '';
    warn "[DigestAuth] code=$code\n" if DEBUG;
    return $tx
      unless 3 == grep { defined $_ } @$auth{qw(username password)}, $tx->res->headers->header('WWW-Authenticate');
    warn "[DigestAuth] Digest authorization...\n" if DEBUG;
    my $next_tx = _clean_tx($ua->build_tx(@args));
    $next_tx->req->headers->authorization(sprintf 'Digest %s', join ', ', _digest_kv($tx, $auth));
    $next_tx->req->headers->accept('*/*');
    $next_tx;
  };

  # non-blocking
  if ($cb) {
    Mojo::IOLoop->delay(
      sub { $ua->start($tx, shift->begin) },
      sub {
        my ($delay, $tx) = @_;
        my $next_tx = $build_next->($tx);
        return $ua->$cb($tx) if $next_tx eq $tx;
        return $ua->start($next_tx, $delay->begin);
      },
      sub { $ua->$cb($_[1]) },
    );
    return $ua;
  }

  # blocking
  my $next_tx = $build_next->($ua->start($tx));
  return $tx if $next_tx eq $tx;
  return $ua->start($next_tx);
};

sub _clean_tx {
  my $tx = shift;
  $tx->req->headers->remove('D-Client-Nonce');
  $tx;
}

sub _digest_kv {
  my ($tx, $args) = @_;
  my %auth_param = $tx->res->headers->header('WWW-Authenticate') =~ /(\w+)="?([^",]+)"?/g;
  my $nc = sprintf '%08X', ++$NC;
  my ($ha1, $ha2, $response);

  $auth_param{client_nonce} = $args->{client_nonce} // _generate_nonce(time);
  $auth_param{nonce} //= '__UNDEF__';
  $auth_param{realm} //= '';

  $ha1 = _ha1(\%auth_param, @$args{qw( username password )});
  $ha2 = _ha2(\%auth_param, $tx->req);

  if ($auth_param{qop} and $auth_param{qop} =~ /^auth/) {
    $response = md5_sum join ':', $ha1, $auth_param{nonce}, $nc, $auth_param{client_nonce}, $auth_param{qop}, $ha2;
    warn "RESPONSE: MD5($ha1:$auth_param{nonce}:$nc:$auth_param{client_nonce}:$auth_param{qop}:$ha2) = $response\n"
      if DEBUG;
  }
  else {
    $response = md5_sum join ':', $ha1, $auth_param{nonce}, $ha2;
    warn "RESPONSE: MD5($ha1:$auth_param{nonce}:$ha2) = $response\n" if DEBUG;
  }

  return (
    qq(username="$args->{username}"),                              qq(realm="$auth_param{realm}"),
    qq(nonce="$auth_param{nonce}"),                                qq(uri="@{[$tx->req->url->path]}"),
    $auth_param{qop} ? ("qop=$auth_param{qop}") : (),              "nc=$nc",
    qq(cnonce="$auth_param{client_nonce}"),                        qq(response="$response"),
    $auth_param{opaque} ? (qq(opaque="$auth_param{opaque}")) : (), qq(algorithm="MD5"),
  );
}

sub _generate_nonce {
  my $time  = shift;
  my $nonce = Mojo::Util::b64_encode(join ' ', $time, Mojo::Util::hmac_sha1_sum($time), '');
  chomp $nonce;
  $nonce =~ s!=+$!!;
  return $nonce;
}

sub _ha1 {
  my ($auth_param, $username, $password) = @_;
  my $res;

  if (!$auth_param->{algorithm} or $auth_param->{algorithm} eq 'MD5') {
    $res = md5_sum join ':', $username, $auth_param->{realm}, $password;
    warn "HA1: MD5($username:$auth_param->{realm}:$password) = $res\n" if DEBUG;
  }
  else {
    $res = md5_sum md5_sum(join ':', $username, $auth_param->{realm}, $password), $auth_param->{nonce},
      $auth_param->{client_nonce};
    warn
      "HA1: MD5(MD5($username:$auth_param->{realm}:$password), $auth_param->{nonce}, $auth_param->{client_nonce}) = $res\n"
      if DEBUG;
  }

  return $res;
}

sub _ha2 {
  my ($auth_param, $req) = @_;
  my $method = uc $req->method;
  my $res;

  if (!$auth_param->{qop} or $auth_param->{qop} eq 'auth') {
    $res = md5_sum join ':', $method, $req->url->path;
    warn "HA2: MD5($method:@{[$req->url->path]}) = $res\n" if DEBUG;
  }
  else {
    $res = md5_sum join ':', $method, $req->url->path, md5_sum('entityBody');    #  TODO: entityBody
    warn "HA2: MD5(TODO) = $res\n" if DEBUG;
  }

  return $res;
}

1;

=encoding utf8

=head1 NAME

Mojo::UserAgent::DigestAuth - Allow Mojo::UserAgent to execute digest auth requests

=head1 VERSION

0.04

=head1 DESCRIPTION

L<Mojo::UserAgent::DigestAuth> is a L<Mojo::UserAgent> "plugin" which can
handle 401 digest auth responses from the server.

See L<http://en.wikipedia.org/wiki/Digest_access_authentication>.

=head1 SYNOPSIS

  use Mojo::UserAgent::DigestAuth;
  my $ua = Mojo::UserAgent->new;

  # blocking
  $tx = $ua->$_request_with_digest_auth($method, $url, $headers);

  # non-blocking
  $ua = $ua->$_request_with_digest_auth($method, $url, $headers, $cb);
  $ua = $ua->$_request_with_digest_auth($method, $url, $cb);

  $ua = $ua->$_request_with_digest_auth(
    get => "http://example.com", sub {
      my ($ua, $tx) = @_;
    }
  );

A custom client nonce can be specified by using a special "D-Client-Nonce"
header. This is a hack to work around servers which does not understand the
nonce generated by this module.

Note that this feature is EXPERIMENTAL and might be removed once I figure
out why the random nonce L<does not work|https://github.com/jhthorsen/mojo-useragent-digestauth/issues/1>
for all servers.

  $ua = $ua->$_request_with_digest_auth(
    get => { "D-Client-Nonce" => "0e163838ccd62299" },
    "http://example.com", sub {
      my ($ua, $tx) = @_;
    }
  );

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2014, Jan Henning Thorsen

This program is free software, you can redistribute it and/or modify it under
the terms of the Artistic License version 2.0.

=head1 AUTHOR

Jan Henning Thorsen - C<jhthorsen@cpan.org>

=cut
