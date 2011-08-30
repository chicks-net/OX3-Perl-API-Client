package OX::OAuth;

# pragma
use warnings;
use strict;

# requirements
use Data::Dumper;
use LWP::UserAgent;
use Net::OAuth;
$Net::OAuth::PROTOCOL_VERSION = Net::OAuth::PROTOCOL_VERSION_1_0A; # requires callbacks
use HTTP::Request::Common;
use JSON -support_by_pp;
use Sub::Override;

=head1 NAME

OX::OAuth - use OpenX's OAuth login mechanism

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';


=head1 SYNOPSIS

This encapsulates the ugly OAuth process so you can pass in paramaters and get out the token of your dreams.

For example:

    use OX::OAuth;

    my $oauth = OX::OAuth->new();
    if ($oauth->login) {
       my $token = $oauth->token;
       # do something with $token
    }

=head1 EXPORT

A list of functions that can be exported.  You can delete this section
if you don't export anything, such as for a purely object-oriented module.

=head1 FUNCTIONS

=head2 new

Create an authentication object.

=cut

sub new {
}

=head2 login

Attempts to login.

Returns true if you successfully logged.  Returns false if you failed to login for some reason.

=cut

sub login {
	# config
	my $sso_host = 'sso.openx.com';
	$sso_host = 'test-sso.openx.org';

	my $callback = 'oob';

	my $config = {
		requestTokenUrl => "https://$sso_host/api/index/initiate",
		accessTokenUrl => "https://$sso_host/api/index/token",
		authorizeUrl => "https://$sso_host/index/authorize",
		loginUrl => "https://$sso_host/login/process",
		path => '/ox/3.0/a/',
		apiKey => '115269f76921a7293e5e6f93abb3ce5f1898c390',
		apiSecret => 'f9e052a1049b8aa03ad72fd1df1ac3c451a5ee63',
		username => '',
		password => '',
		domain => '',
		realm => 'test_ad_server_2',
	};

	my $ua = LWP::UserAgent->new;
	$ua->agent('ox3-get-timezones/0.8');
	$ua->cookie_jar( {} ); # ephemeral cookies

	#
	# request token
	#
	my $request = Net::OAuth->request("request token")->new(
		consumer_key => $config->{apiKey},
		consumer_secret => $config->{apiSecret},
		request_url => $config->{requestTokenUrl},
		request_method => 'POST',
		signature_method => 'HMAC-SHA1',
		#signature_method => 'PLAINTEXT',
		#signature_method => 'RSA-SHA1',
		timestamp => time(),
		nonce => nonce(),
		callback => $callback,
		extra_params => {
			realm => $config->{realm},
		},
	);

	$request->sign;

	die unless $request->verify;

	my $res = $ua->request(POST $request->to_url); # Post message to the Service Provider

	my ($request_token,$request_token_secret);
	if ($res->is_success) {
		my $response = Net::OAuth->response('request token')->from_post_body($res->content);
		$request_token = $response->token;
		$request_token_secret = $response->token_secret;
		print "Got Request Token:        $request_token\n";
		print "Got Request Token Secret: $request_token_secret\n";
	} else {
		print "signature_base_string=", $request->signature_base_string, "\n";
		#print Dumper($request->to_hash), "\n";
		die $request->to_url . " failed: " . $res->status_line . "\n" . $res->content . "\n";
	}

	#
	# login
	#

	my $login_post_params = {
		oauth_token => $request_token,
		email => 'chicks@openx.org',
		password => '0p3nxFoo',
	};

	$ua->requests_redirectable( [ 'POST', $ua->requests_redirectable ] );
	$res = $ua->post( $config->{loginUrl}, $login_post_params);

	my $oauth_verifier;
	if ($res->is_success) {
		print "user auth'd\n";
		my $out = $res->content;
		$out =~ s/^oob.*\?//;
		my %results = split(/[&=]/,$out);
		$oauth_verifier = $results{oauth_verifier};
		print "OAuth Verifier:   $oauth_verifier\n";
		die "no oauth verifier found in '$out'" unless defined $oauth_verifier;
	} else {
		print $res->as_string;
		die $res->request->uri() . " failed: " . $res->status_line . "\n" . $res->content . "\n";
	}

	#
	# get access token
	#

	#package Net::OAuth::AccessTokenRequest;
	#sub allow_extra_params {1}
	#1;

	my $access_request = Net::OAuth->request('access token')->new(
		consumer_key => $config->{apiKey},
		consumer_secret => $config->{apiSecret},
		token => $request_token,
		token_secret => $request_token_secret,
		verifier => $oauth_verifier,
		request_url => $config->{accessTokenUrl},
		request_method => 'POST',
		signature_method => 'HMAC-SHA1',
		timestamp => time,
		nonce => nonce(),
		realm => $config->{realm},
		extra_params => {
			realm => $config->{realm},
		},
	);

	#$access_request->allow_extra_params(1);
	my $override = Sub::Override->new('Net::OAuth::AccessTokenRequest::allow_extra_params',sub {1});
	die "bad module" unless $access_request->allow_extra_params;

	$access_request->sign;

	die unless $access_request->verify; # double check

	$res = $ua->request(POST $access_request->to_url); # Post message to the Service Provider

	my($oauth_access_token, $oauth_access_token_secret);
	if ($res->is_success) {
		print "got access token\n";
		my $out = $res->content;
		my %results = split(/[&=]/,$out);
		$oauth_access_token = $results{oauth_token};
		$oauth_access_token_secret = $results{oauth_token_secret};
		print "OAuth Token:        $oauth_access_token\n";
		print "OAuth Token Secret: $oauth_access_token_secret\n";
	} else {
		print Dumper($access_request->to_hash), "\n";
		die $access_request->to_url . " failed: " . $res->status_line . "\n" . $res->content . "\n";
	}

	#
	# test
	#
	my ($search) = @ARGV;

	$ua->default_header('Cookie' => "openx3_access_token=$oauth_access_token");

	my $base_url='http://qa-ox3-ui-xv-03.xv.dc.openx.org/ox/3.0';
	my $tzresponse = $ua->get("$base_url/a/account/timezoneOptions");

	if ($tzresponse->is_success) {
		my $content = $tzresponse->content;

		my $json = new JSON;

		my $json_text = $json->allow_nonref->utf8->relaxed->escape_slash->loose->allow_singlequote->allow_barekey->decode($content);

		foreach my $entry (@$json_text) {
			if (defined $search and $entry->{name} !~ /$search/) {
				next;
			}
			print join("\t",$entry->{id},$entry->{name},$entry->{code}), "\n";
		}
	} else {
		die "timezoneOptions failed:" . $tzresponse->status_line;
	}
}

=head2 nonce

This calculates a random base62 string 32 characters long.

=cut

sub nonce {
	my @a = ('A'..'Z', 'a'..'z', 0..9);
	my $nonce = '';
	for ( 0 .. 31 ) {
		$nonce .= $a[rand(scalar(@a))];
	}

	$nonce;
}


=head1 AUTHOR

Christopher Hicks, C<< <chris.hicks at openx.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-ox-oauth at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=OX-OAuth>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc OX::OAuth


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=OX-OAuth>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/OX-OAuth>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/OX-OAuth>

=item * Search CPAN

L<http://search.cpan.org/dist/OX-OAuth/>

=item * RFC 5849 - The OAuth 1.0 Protocol

L<http://tools.ietf.org/html/rfc5849>

=back


=head1 ACKNOWLEDGEMENTS

=over 4

=item * Keith Miller C<< <keith.miller at openx.com> >>, our OAuth implementor

=back


=head1 COPYRIGHT & LICENSE

Copyright 2011 Christopher Hicks.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

1; # End of OX::OAuth

__END__
#!/usr/bin/perl


