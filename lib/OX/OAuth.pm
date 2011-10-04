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
use File::Slurp;

=head1 NAME

OX::OAuth - use OpenX's OAuth login mechanism

=head1 VERSION

Version 0.66

=cut

our $VERSION = '0.66';


=head1 SYNOPSIS

This encapsulates the ugly OAuth process so you can pass in paramaters and get out the token of your dreams.

For example:

    use OX::OAuth;

    $config = {
	api_url => 'https://prod-console.openx.com/ox/3.0',
	sso_url => 'https://sso.openx.com/'
	realm => 'blah_ad_server',
	email => 'you@your.dom',
	password => 'secret',
    };

    my $oauth = OX::OAuth->new($config);
    if ($oauth->login) {
       my $token = $oauth->token;
       # do something with $token
    } else {
       die $oauth->error;
    }

    my $response = $oauth->rest({
	relative_url => '/some/stuff/id',
    });

=head1 EXPORT

We don't export anything.  Fear not.

=head1 FUNCTIONS

=head2 new

Create an authentication object.

Arguments are passed as a hashref with these keys:

=over 4

=item * api_url

Required.  Should probably be L<https://prod-console.openx.com/ox/3.0>

=item * sso_url

Required.  Should probably be L<https://sso.openx.com/>

=item * realm

Required.  Provided as part of your Enterprise setup.

=item * email

Required.  The email address of the API user.  All ox3 logins can use the API.

=item * password

Required.  The password of the API user.

=item * api_key

Required.  Provided as part of your Enterprise setup.

=item * api_secret

Required.  Provided as part of your Enterprise setup.

=item * request_token_url

Optional.  This can be inferred from the sso_url.

=item * access_token_url

Optional.  This can be inferred from the sso_url.

=item * authorize_url

Optional.  This can be inferred from the sso_url.

=item * login_url

Optional.  This can be inferred from the sso_url.

=back

Returns an object.

=cut

sub new {
	my $type = shift;
	my $self = {};
	#my %params = @_;
	my $config = shift;
	my ($config_errors,@config_errors);
	if (ref $config eq 'HASH') {
		# required
		foreach my $key (qw(api_url sso_url realm email password api_key api_secret)) {
			if (defined $config->{$key}) {
				$self->{$key} = $config->{$key};
			} else {
				push(@config_errors,"required field $key is not in config");
				$config_errors++;
			}
		}

		# optional
		foreach my $key (qw(request_token_url access_token_url authorize_url login_url)) {
			$self->{$key} = $config->{$key};
		}

		my $sso_url = $self->{sso_url};
		$self->{request_token_url} = $sso_url . '/api/index/initiate' unless defined $self->{request_token_url};
		$self->{access_token_url} = $sso_url . '/api/index/token' unless defined $self->{access_token_url};
		$self->{authorize_url} = $sso_url . '/index/authorize' unless defined $self->{authorize_url};
		$self->{login_url} = $sso_url . '/login/process' unless defined $self->{login_url};

		# validate url's
		foreach my $key (qw(api_url sso_url request_token_url access_token_url authorize_url login_url)) {
			my $url = $self->{$key};
			unless ($url =~ /https?:\/\//) {
				push(@config_errors,"url '$url' doesn't taste url'y");
				$config_errors++;
			}
		}
	} else {
		die "unsupported argument: expecting a hash ref";
	}

	if ($config_errors) {
		warn "there were $config_errors configuration errors:\n";
		my $x = 0;
		foreach my $error (@config_errors) {
			$x++;
			warn "$x: $error\n";
		}
		die "not enough config";
	}

	bless $self, $type; # and return it
}

=head2 login

Attempts to login.

Returns true if you successfully logged.  Returns false if you failed to login for some reason.

The only argument is optional and is a boolean for whether you want it to be verbose during the numerous steps oauth requires.

=cut

sub login {
	my $self = shift;
	my $verbose = shift || 0;

	my $callback		= 'oob';
	my $api_url		= $self->{api_url};
	my $sso_url		= $self->{sso_url};

	my $api_key		= $self->{api_key};
	my $api_secret		= $self->{api_secret};
	my $realm		= $self->{realm};
	my $email		= $self->{email};
	my $password		= $self->{password};

	my $request_token_url	= $self->{request_token_url};
	my $access_token_url	= $self->{access_token_url};
	my $authorize_url	= $self->{authorize_url};
	my $login_url		= $self->{login_url};

	my $ua = LWP::UserAgent->new;
	$ua->agent("ox-oauth-perl/$VERSION");
	$ua->cookie_jar( {} );	# ephemeral cookies
	$self->{_ua} = $ua;	# reused user agent

	#
	# request token
	#
	my $request = Net::OAuth->request("request token")->new(
		consumer_key => $api_key,
		consumer_secret => $api_secret,
		request_url => $request_token_url,
		request_method => 'POST',
		signature_method => 'HMAC-SHA1',
		#signature_method => 'PLAINTEXT',
		#signature_method => 'RSA-SHA1',
		timestamp => time(),
		nonce => nonce(),
		callback => $callback,
		extra_params => {
			realm => $realm,
		},
	);

	$request->sign;

	die unless $request->verify; # double check

	my $res = $ua->request(POST $request->to_url); # Post message to the Service Provider

	my ($request_token,$request_token_secret);
	if ($res->is_success) {
		my $response = Net::OAuth->response('request token')->from_post_body($res->content);
		$request_token = $response->token;
		$request_token_secret = $response->token_secret;
		print "Got Request Token:        $request_token\n" if $verbose;
		print "Got Request Token Secret: $request_token_secret\n" if $verbose;
	} else {
		print "signature_base_string=", $request->signature_base_string, "\n" if $verbose;
		die $request->to_url . " failed: " . $res->status_line . "\n" . $res->content . "\n";
	}

	#
	# login
	#

	my $login_post_params = {
		oauth_token => $request_token,
		email => $email,
		password => $password,
	};

	$ua->requests_redirectable( [ 'POST', $ua->requests_redirectable ] );
	$res = $ua->post( $login_url, $login_post_params);

	my $oauth_verifier;
	if ($res->is_success) {
		my $out = $res->content;
		if ($out =~ /oob/) {
			print "user auth'd at $login_url\n" if $verbose;
		} else {
			die "probably user authentication failure";
		}
		$out =~ s/^oob.*\?//;
		my %results = split(/[&=]/,$out);
		$oauth_verifier = $results{oauth_verifier};
		print "OAuth Verifier:   $oauth_verifier\n" if $verbose;
		die "no oauth verifier found in '$out'" unless defined $oauth_verifier;
	} else {
		print $res->as_string;
		die $res->request->uri() . " failed: " . $res->status_line . "\n" . $res->content . "\n";
	}

	#
	# get access token
	#

	my $access_request = Net::OAuth->request('access token')->new(
		consumer_key => $api_key,
		consumer_secret => $api_secret,
		token => $request_token,
		token_secret => $request_token_secret,
		verifier => $oauth_verifier,
		request_url => $access_token_url,
		request_method => 'POST',
		signature_method => 'HMAC-SHA1',
		timestamp => time,
		nonce => nonce(),
		realm => $realm, # TODO: try it again with realm in only one place
		extra_params => {
			realm => $realm,
		},
	);

	#$access_request->allow_extra_params(1);
	my $override = Sub::Override->new('Net::OAuth::AccessTokenRequest::allow_extra_params',sub {1}); # bru-hahahaha
	die "bad module" unless $access_request->allow_extra_params; # verify magic

	$access_request->sign;

	die unless $access_request->verify; # double check

	$res = $ua->request(POST $access_request->to_url); # Post message to the Service Provider

	my($oauth_access_token, $oauth_access_token_secret);
	if ($res->is_success) {
		print "got access token\n" if $verbose;
		my $out = $res->content;
		my %results = split(/[&=]/,$out);
		$oauth_access_token = $results{oauth_token};
		$oauth_access_token_secret = $results{oauth_token_secret};
		print "OAuth Token:        $oauth_access_token\n" if $verbose;
		print "OAuth Token Secret: $oauth_access_token_secret\n" if $verbose;
	} else {
		print Dumper($access_request->to_hash), "\n";
		die $access_request->to_url . " failed: " . $res->status_line . "\n" . $res->content . "\n";
	}

	$self->{token} = $oauth_access_token;
	$ua->default_header('Cookie' => "openx3_access_token=$oauth_access_token"); # the normal cookie jar uses a format that breaks something

	#
	# validate with ox3 api, almost done
	#

	$self->rest({
		relative_url => '/a/session/validate',
		success => 'login validated...',
		decode_json => 0,
		method => 'PUT',
		quiet => 1-$verbose,
	});

	return 1; # woo hoo, success!
}

=head2 nonce

This calculates and returns a random base62 string 32 characters long.

=cut

sub nonce {
#	my $self = shift;
	my @a = ('A'..'Z', 'a'..'z', 0..9);
	my $nonce = '';
	for ( 0 .. 31 ) {
		$nonce .= $a[rand(scalar(@a))];
	}

	$nonce;
}

=head2 find_config

This will retrieve a config file for you.  The config file format is json and the json is decoded and a reference returned.  It looks for a config in:

=over 4

=item * the file specified by the environment variable OX3AUTH

=item * a file in /etc/ox/oauth/${env}.json

=item * the file $HOME/~.ox3auth

=back

The only argument is the environment which is optional.  "qa" is the default environment.

=cut

sub find_config {
	my $self = shift;
	my $env = shift || 'qa';

	my $canonical_filename = "/etc/ox/oauth/${env}.json";
	my $config_filename;
	if (defined $ENV{OX3AUTH}) {
		$config_filename = $ENV{OX3AUTH};
	} elsif ( -e $canonical_filename )  {
		$config_filename = $canonical_filename;
	} elsif ( -e ($ENV{HOME} . '/.ox3auth') ) {
		$config_filename = $ENV{HOME} . '/.ox3auth';
	} else {
		die "no potential config files found, so giving up";
	}

	unless (-r $config_filename) {
		die "cannot read $config_filename";
	}

	return $self->jsondecode(read_file($config_filename));
}

=head2 token

Get back the token if you want to use it yourself.  This is read-only naturally.

=cut

sub token {
	my $self = shift;
	return $self->{token};
}

=head2 jsondecode

decode JSON into perl structure

=cut

sub jsondecode {
	my $self = shift;
	my $content = join('',@_); # merge all the lines
	my $json = new JSON;
#	print "### $content\n###\n";
	my $json_text = $json->allow_nonref->utf8->relaxed->escape_slash->loose->allow_singlequote->allow_barekey->decode($content);
	return $json_text;
}

=head2 jsondump

turn JSON into human readable output and print it out

=cut

sub jsondump {
	my $self = shift;
	my $content = join('',@_); # merge all the lines
	my $json_text = $self->jsondecode($content);
	print Dumper($json_text);
}

=head2 rest

Make a call to the REST API.  You can do this for yourself with the token, but then you miss out on all the DWIM syrup this method provides.

Arguments are passed as a hashref with these keys:

=over 4

=item * relative_url

Required.  This is the API call you're trying to make.

=item * url

If you want to provide the entire URL use this instead of relative_url.  That's usually not a good idea.

=item * success

Optional.  A message to print upon success.  If the return value includes an id field, it will be printed also.

=item * post_args

Optional.  If you want to make a POST then you need something to post.  Pass in a hashref here.

=item * method

Optional.  Do you want DELETE or PUT?  You'll need to say so since we can't infer that.  Otherwise you get POST if there stuff in post_args or finally GET.

=item * quiet

Optional.  Off by default so the success message prints.  Do you want the success message to print?

=item * debug

Optional.  Off by default.  Do you want to see the guts of what is happening?

=item * decode_json

Optional.  The default is on: it will decode the json into a Perl structure.  Otherwise you get back a hashref with content and status_line to play with.

=item * upload_file

Optional.  If you're uploading a file, which file?

=item * upload_file_field

Optional.  The name of the field to put the uploaded file in.

=item * retry

Optional.  The number of times to retry an operation.  The default is 0 retries.  Each retry will exponentially back off starting at 2 seconds, then 4, 8, 16, etc.

=back

=cut

sub rest {
	my $self = shift;
	my $args = shift;

	# reflect on self
	my $ua = $self->{_ua} || die "no ua";
#	my $token = $self->{token};

	# read arguments
	my $url;
	if ($args->{url}) {
		# go with the explicit url
		$url = $args->{url};
	} elsif ($args->{relative_url}) {
		$url = $self->{api_url} . $args->{relative_url};
	} else {
		die "rest() needs some url to rest with";
	}
	die "bad url: $url" unless $url =~ qr{^https?://};

	my $success = $args->{success} || "$url succeeded";
	my $post_args = $args->{post_args};
	my $method = $args->{method};
	my $debug = $args->{debug} || 0;
	my $quiet = $args->{quiet} || 0;
	my $retry = $args->{retry} || 0;
	$retry++; # try at least once

	my $decode_json = 1;
	$decode_json = $args->{decode_json} if defined $args->{decode_json};

	my $upload_file = $args->{upload_file};
	my $upload_file_field = $args->{upload_file_field};

	# web hit
	my $retry_delay = 2;
	my $response;
	while ($retry) {
		if (defined $upload_file) {
			die "no field name" unless length $upload_file_field;
			die "no file name" unless length $upload_file;
			die "file '$upload_file' does not exist" unless -f $upload_file;
			$response = $ua->post($url,
				Content_Type => 'form-data',
				Content => [
					%$post_args,
					$upload_file_field => [ $upload_file ],
				]
			);
		} elsif (defined $method) {
			if ($method eq 'PUT') {
				$response = $ua->request(PUT $url);
			} elsif ($method eq 'DELETE') {
				$response = $ua->request(DELETE $url);
			} # TODO: more options?
		} elsif (defined $post_args) {
			$response = $ua->post($url,$post_args);
		} else {
			$response = $ua->get($url);
		}

		# we tried
		$retry--;

		# how did it go?
		if ($response->is_success) { # TODO: log this as well
			my $content = $response->content;

			if ($debug) {
				print "$success\n";
				print "sent: " . Dumper($post_args) . "\n";
				$self->jsondump($content);
				die "debug";
			}
			my $href;
			if ($decode_json) {
				$href = $self->jsondecode($content);
			} else {
				$href = {
					content => $content,
					status_line => $response->status_line,
				}
			}
			unless ($quiet) {
				if ( ref($href) eq 'HASH' and defined $href->{id} ) {
					print "$success id " . $href->{id} . "\n";
				} else {
					print "$success\n";
				}
			}
			return $href;
		} else {
			my $fail_message = "$url failed: " . $response->status_line . "\n" . $response->content;
			if (defined $post_args) {
				$fail_message .= "\nsent:" . Dumper($post_args);
			} else {
				$fail_message .= "\nsent _NO_ POST parameters\n";
			}

			if ($retry) {
				warn $fail_message;
				warn "sleeping $retry_delay seconds before trying again ($retry retries left)...\n\n";
				sleep($retry_delay);
				$retry_delay = $retry_delay * $retry_delay; # exponential back off
			} else {
				# no more retries
				die $fail_message;
			}
		}
	}
}

=head1 FUTURE

=over 4

=item * caching of token and other cookies across script invocations

=item * tweaking UserAgent header

=back

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

=item * Net::OAuth module

L<Net::OAuth> which L<OX::OAuth> is mostly a wrapper for.

=item * Sub::Override module

L<Sub::Override> which made dealing with Net::OAuth I<much> easier.  This module saved me a lot of trouble.

=item * JSON module

L<JSON>

=back


=head1 ACKNOWLEDGEMENTS

=over 4

=item * Keith Miller, OpenX's OAuth implementor

=item * Michael Todd, OpenX Operations Manager

=back


=head1 COPYRIGHT & LICENSE

Copyright 2011 Christopher Hicks.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License 2.0 as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

1; # End of OX::OAuth

__END__
