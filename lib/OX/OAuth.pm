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

Version 0.50

=cut

our $VERSION = '0.50';


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

A list of functions that can be exported.  You can delete this section
if you don't export anything, such as for a purely object-oriented module.

=head1 FUNCTIONS

=head2 new

Create an authentication object.

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

	return 1; # woo hoo, success!
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
	my ($content) = @_;
#	print "### $content\n";
	my $json = new JSON;
	my $json_text = $json->allow_nonref->utf8->relaxed->escape_slash->loose->allow_singlequote->allow_barekey->decode($content);
	return $json_text;
}

=head2 jsondump

turn JSON into human readable output

=cut

sub jsondump {
	my($content) = @_;
	my $json_text = jsondecode($content);
	print Dumper($json_text);
}

=head2 rest

Make a call to the REST API.

=cut

sub rest {
	my $self = shift;
	my $args = shift;

	# reflect on self
	my $ua = $self->{_ua};

	# read arguments
	my $url;
	if ($args->{url}) {
		# go with the explicit url
		$url = $self->{url};
	} elsif ($args->{relative_url}) {
		$url = $self->{api_url} . $args->{relative_url};
	} else {
		die "rest() needs some url to rest with";
	}
	die "bad url: $url" unless $url =~ qr{^https?://};

	my $success = $args->{success} || "$url succeeded";
	my $post_args = $args->{post_args};
	my $debug = $args->{debug} || 0;

	my $decode_json = 1;
	$decode_json = $args->{decode_json} if defined $args->{decode_json};

	my $upload_file = $args->{upload_file};
	my $upload_file_field = $args->{upload_file_field};

	# web hit
	my $response;
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
	} elsif (defined $post_args) {
		$response = $ua->post($url,$post_args);
	} else {
		$response = $ua->get($url);
	}

	# how did it go?
	if ($response->is_success) { # TODO: log this as well
		my $content = $response->content;

		if ($debug) {
			print "$success\n";
			print "sent: " . Dumper($post_args) . "\n";
			jsondump($content);
			die "debug";
		}
		my $href;
		if ($decode_json) {
			$href = jsondecode($content);
		} else {
			$href = {
				content => $content,
				status_line => $response->status_line,
			}
		}
		if ( ref($href) eq 'HASH' and defined $href->{id} ) {
			print "$success id " . $href->{id} . "\n";
		} else {
			print "$success\n";
		}
		return $href;
	} else {
		die "$url failed: " . $response->status_line . "\n" . $response->content . "\nsent:" . Dumper($post_args);
	}
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

use warnings;
use strict;

use LWP::UserAgent;
use Data::Dumper;
use JSON -support_by_pp;
use File::Slurp;
use Digest::SHA1 qw(sha1_hex sha1_base64);

# config
my $base_url='http://prod-ox3-ui-xv-06.xv.dc.openx.org/ox/3.0';
my $base_url_secure='https://prod-console.openx.com/ox/3.0'; # can't use it for now anyway
my $auth = {
	email => 'root@openx.org',
	password => '279b62d07f117bf50e12a84d9d4e7063',
};
my $sso_auth = {
	email => 'openx-api@openx.org',
	pass => 'ajN58Y0Gux2',
};
my $environment = 'production';
my $iab486x60 = 8;
my $creative_path = '/home/chicks/Downloads/openx-468x60.png';
my $ua_timeout = 10; # seconds

# setup UA
my $ua = LWP::UserAgent->new;
$ua->timeout($ua_timeout); # configured above
$ua->env_proxy;
$ua->cookie_jar( { file => "$ENV{HOME}/.ox3.cookies.txt" } );
$ua->agent('ox3-customer-creator/0.3');

# load paramaters from file
my ($shortname) = @ARGV;
die "provide shortname or shortname.json as argument please" unless defined $shortname and length $shortname;

my $configfile;

if ($shortname =~ /\.json$/) {
	$configfile = $shortname;
	$shortname =~ s/\.json$//;
} else {
	$configfile = "$shortname.json";
}

unless (-f $configfile) {
	die "no config file $configfile";
}

my $config = jsondecode(read_file($configfile));
#jsondump($config); die;
my $masternetworkid = $config->{masternetworkid};
my $timezone = $config->{timezone};
my $uihostname = $config->{ui};
my $deliveryhostname = $config->{delivery};
my $imagehostname = $config->{image};
my $deliverysslhostname = $config->{deliveryssl};
my $content_topic_origin = $config->{content_topic_origin} || 'Custom'; # we never use Master anymore
my $country = $config->{country} || 'us';
my $currency = $config->{currency} || 1; # default = USD
my $ssorealm = "${shortname}_ad_server";
my $apihostname = "$shortname-ui3.openxenterprise.com";

# get a session
rest({
	url => "$base_url/a/session/",
	success => 'logged in...',
	post_args => $auth,
});

#goto upload_creative;
#goto create_ad;

# create master network
unless (defined $masternetworkid) {
	my $mna_args = {
		name => "$shortname Instance",
		status => "Active",
		account_id => "1",
		account_type_id => "1",
		currency_id => $currency,
		timezone_id => $timezone,
		country_of_business_id => $country,
	};
	#print Dumper($instanceargs); die;

	my $mna = rest({
		url => "$base_url/a/account",
		success => 'created master network account',
		post_args => $mna_args,
	});
	$masternetworkid = $mna->{id};
}

# get master network
my $masternetwork = rest({
	url => "$base_url/a/account/$masternetworkid",
	success => "got master network",
});

my $instanceid;
unless ($masternetwork->{instance_id} and $masternetwork->{instance_id} != 1) {
	#my $secret = 'Zombies!!!';
	my $secret = sha1_hex(rand(100_000_000_000_000));
	my $consumer_key = sha1_hex(rand(100_000_000_000_000));
	my $consumer_secret = sha1_hex($secret);

	# create instance
	my $instanceargs = {
		name => $shortname,
		timezone_id => $timezone,
		sso_realm => $ssorealm,
		sso_domain => 'https://sso.openx.com',
		environment => $environment,
		delivery_hostname => $deliveryhostname,
		admin_hostname => $uihostname,
		api_hostname => $apihostname,
		cdn_hostname => $imagehostname,
		cdn_ssl_hostname => 'ssl-i.cdn.openx.com',
		content_topic_origin => $content_topic_origin,
		active => 1,
		account_id => $masternetworkid,
		consumer_key => $consumer_key,
		consumer_secret => $consumer_secret,
		theme => 'oxtongue',
		market_operator_id => 'OX',
	};
	#print Dumper($instanceargs); die;

	my $ci = rest({
		url => "$base_url/a/instance",
		success => 'created instance',
		post_args => $instanceargs,
	});
	$instanceid = $ci->{id};

#	# update master network
#	my $masterupdate = {
#		instance_id => $instanceid,
#		name => $masternetwork->{name}, # unchanged but required
#		status => $masternetwork->{status}, # unchanged but required
#		timezone_id => $masternetwork->{timezone_id}, # unchanged but required
#	};
#
#	my $mu = rest ({
#		url => "$base_url/a/account/$masternetworkid",
#		success => 'updated master instance',
#		post_args => $masterupdate,
#	});

	# create sso realm
	my $sso_realm_args = {
		%$sso_auth,
		realm		=>	$ssorealm,		# realm - unique realm identifier.
								# Needs to match against ^[a-zA-Z0-9_]+$

		name		=>	$shortname,		# name - name of the SSO Realm.

		# secret - shared secret for the SSO realm. Needs to match against /^[a-zA-Z0-9_!@#]+$/
		# and must match the existing API shared secret if the realm is for the API. Check
		# config.php in the API to get this information.
	#	secret		=>	'test', # qa
		secret		=>	$secret, # prod
		consumer_key	=>	$consumer_key,

		domain		=>	'sso.openx.com',	# domain - base domain for the realm. This is
								# used for skinning, which we haven't started
								# using yet. Needs to match against
								# ^[a-zA-Z0-9.-]+$ . In production this is
								# 'sso.openx.com'. 
	};
	my $sso_realm = rest({
		url => "https://sso.openx.com/api/supervisor/createrealm",
		success => "created sso realm",
		post_args => $sso_realm_args,
		decode_json => 0,
	});

	if ($content_topic_origin eq 'Custom') {
		my $ct_args = {
			id => "9999",
			name => "Unclassified",
			instance_id => $instanceid,
			parent_id => "0",
		};
		#print Dumper($instanceargs); die;

		my $ct = rest({
			url => "$base_url/a/contenttopic",
			success => 'created content topic "Unclassified"',
			post_args => $ct_args,
		});
	}

} else { # unless ($masternetwork->{instance_id}) 
	print "master network account $masternetworkid already has instance id " . $masternetwork->{instance_id} . "\n";
}

#die "skip the rest because of random funkiness";

# create publisher account
#
# POST /a/account/
#
# required fields:
# 	name			= Monitoring Publisher (don't use)
# 	status			= Active
# 	account_id		= ???
# 	account_type_id		= 2 (Publisher: Exclusive)
# 	currency_id		= 1 (USD)
# 	timezone_id		= 8 (PST)
# 	country_of_business_id	= 'us'

my $publisher_args = {
	name		=> "Monitoring Publisher (don't use)",
	status		=> "Active",
	account_id	=> $masternetwork->{id},
	account_type_id => 2, # Publisher: Exclusive
	currency_id	=> 1, # USD
	timezone_id	=> 8, # PST
	country_of_business_id => 'us',
};

my $publisher = rest({
	url => "$base_url/a/account/",
	success => "created Monitoring publisher account",
	post_args => $publisher_args,
});

# create "Default" publisher account
my $default_publisher_args = {
	name		=> "Default Publisher",
	status		=> "Active",
	account_id	=> $masternetwork->{id},
	account_type_id => 2, # Publisher: Exclusive
	currency_id	=> $currency,
	timezone_id	=> $timezone, # their timezone
	country_of_business_id => $country,
};

my $default_publisher = rest({
	url => "$base_url/a/account/",
	success => "created Default publisher account",
	post_args => $default_publisher_args,
});

# create advertiser account
#
# POST /a/account/
#
# required fields:
# 	name			= Monitoring Advertiser (don't use)
# 	status			= Active
# 	account_id		= ???
# 	account_type_id		= 4 (Advertiser: Managed)
# 	currency_id		= 1 (USD)
# 	timezone_id		= 8 (PST)
# 	country_of_business_id	= 'us'

my $advertiser_args = {
	name		=> "Monitoring Advertiser (don't use)",
	status		=> "Active",
	account_id	=> $masternetwork->{id},
	account_type_id => 4, # Advertiser: Managed
	currency_id	=> 1, # USD
	timezone_id	=> 8, # PST
	country_of_business_id => 'us',
};

my $advertiser = rest({
	url => "$base_url/a/account/",
	success => "created advertiser account",
	post_args => $advertiser_args,
});

# create site
#
# POST /a/site/
#
# required fields:
# 	name			= Monitoring Site (don't use)
# 	status			= Active
# 	url			= http://www.openx.org
# 	content_topic_id	= 9999 (Unclassified)
# 	content_type_id		= 99 (Unclassified)
# 	account_id		= $ (publisher account id)

my $site_args = {
 	name			=> "Monitoring Site (don't use)",
 	status			=> "Active",
 	url			=> "http://www.openx.org",
 	content_topic_id	=> 9999, # (Unclassified)
 	content_type_id		=> 99, # (Unclassified)
 	account_id		=> $publisher->{id} #publisher account id
};
my $site = rest({
	url => "$base_url/a/site/",
	success => "created site",
	post_args => $site_args,
});

# create adunit
#
# POST /a/adunit/
#
# required fields:
# 	name			= Monitoring Ad Unit (don't use)
# 	status			= Active
# 	site_id			= $ (site just created)
# 	delivery_medium_id	= 2 (web)
#	size_id			= 8
#	tag_type_id		= 1

my $adunit_args = {
 	name			=> "Monitoring Ad Unit (don't use)",
 	status			=> "Active",
 	site_id			=> $site->{id},
 	delivery_medium_id	=> 2, # web
 	size_id			=> $iab486x60, # IAB Full Banner 468x60
	tag_type_id		=> 1 # javascript synchronous,
};
my $adunit = rest({
	url => "$base_url/a/adunit/",
	success => "created adunit",
	post_args => $adunit_args,
});

# associate content topic with ad unit
#
# GET /a/adunit/${ad_unit_id}/associateContentTopic/9999 	
my $adunit_id = $adunit->{id};
rest({
	url => "$base_url/a/adunit/$adunit_id/associateContentTopic/9999",
	success => "associated content topic 9999 with adunit $adunit_id",
});

# create order
#
# POST /a/order/
#
# required fields:
# 	name			= Monitoring Order (don't use)
# 	status			= Pending (??)
# 	start_date		= now in yyyy-mm-dd
# 	end_date		= null
#	account_id		= $ (advertiser account id)

my $order_args = {
 	name			=> "Monitoring Order (don't use)",
 	status			=> "Pending",
	start_date		=> now(),
	end_date		=> 'null', # TODO: null properly?
 	account_id		=> $advertiser->{id} # advertiser account id
};
my $order = rest({
	url => "$base_url/a/order/",
	success => "created order",
	post_args => $order_args,
});

# create lineitem
#
# POST /a/lineitem/
#
# required fields:
# 	name			= Monitoring Line Item (don't use)
# 	status			= Pending (??)
# 	buying_model_id		= 5 (house)
# 	delivery_medium_id	= 2 (web)
# 	start_date		= now in yyyy-mm-dd
# 	order_id		= $ (order id just created)
#	end_date		= null

my $lineitem_args = {
 	name			=> "Monitoring Line Item (don't use)",
 	status			=> "Pending",
 	buying_model_id		=> 5, # house
 	delivery_medium_id	=> 2, # web
	start_date		=> now(),
 	order_id		=> $order->{id}, # order id for order just created
	end_date		=> 'null',
};
my $lineitem = rest({
	url => "$base_url/a/lineitem/",
	success => "created lineitem",
	post_args => $lineitem_args,
});

# create rules
#
# POST /a/rule/
#
# required fields:
# 	dimension		= content
# 	attribute		= adunit_size
# 	operator		= INTERSECTS
# 	value			= 8 (IAB Full Banner 468x60)
# 	lineitem_id		= $ (lineitem id just created)

my $rule1_args = {
 	dimension		=> 'content',
 	attribute		=> 'adunit_size',
 	operator		=> 'INTERSECTS',
 	value			=> $iab486x60, # IAB Full Banner 468x60
 	lineitem_id		=> $lineitem->{id}, # lineitem id for lineitem just created
};
my $rule1 = rest({
	url => "$base_url/a/rule/",
	success => "created rule1",
	post_args => $rule1_args,
});

# required fields:
# 	dimension		= dimension
# 	attribute		= _operator
# 	operator		= AND
# 	value			= NO_VALUE
# 	lineitem_id		= $ (lineitem id just created)
#
# I'm not sure what the second one does

my $rule2_args = {
 	dimension		=> 'dimension',
 	attribute		=> '_operator',
 	operator		=> 'AND',
 	value			=> 'NO_VALUE', # IAB Full Banner 468x60
 	lineitem_id		=> $lineitem->{id}, # lineitem id for lineitem just created
};
my $rule2 = rest({
	url => "$base_url/a/rule/",
	success => "created rule2",
	post_args => $rule2_args,
});

# there was a "POST /a/ad/TypeLimiter" but it doesn't seem to create anything. 
# And it doesn't return anything different regardless of the values passed in.

# upload creative
#
# POST /a/creative/uploadCreative
#
# required fields:
# 	name			= Monitoring Ad Creative (don't use)
# 	account_id		= ??? (advertiser account id)
# 	userfile		= binary file in multipart with filename
upload_creative:
#$advertiser = { id => 9091 };
#$lineitem = { id => 43033 };

my $creative_upload_args = {
 	name			=> "Monitoring Ad Creative (don't use)",
 	account_id		=> $advertiser->{id} # advertiser account id
};
my $creative_upload = rest({
	url => "$base_url/a/creative/uploadCreative",
	success => "uploaded creative",
	post_args => $creative_upload_args,
	upload_file_field => 'userfile',
	upload_file => $creative_path,
});

# create creative
#
# POST /a/creative/
#
# required fields:
# 	name			= Monitoring Ad Creative (don't use)
# 	ad_type_id		= 1
# 	uri			= from creative upload
# 	account_id		= $ (advertiser account id)

my $creative_args = {
 	name			=> "Monitoring Ad Creative (don't use)",
 	ad_type_id		=> 1,
	uri			=> $creative_upload->{uri},
 	account_id		=> $advertiser->{id} # advertiser account id
};
my $creative = rest({
	url => "$base_url/a/creative/",
	success => "created creative",
	post_args => $creative_args,
});

create_ad:
#my $lineitem = {id => 19899};

# create ad
#
# POST /a/ad/
#
# required fields:
# 	name			= Monitoring Ad
# 	status			= Active
# 	ad_type_id		= 1
# 	lineitem_id		= $ (line item id from above)

my $ad_args = {
 	name			=> "Monitoring Ad (don't use)",
 	status			=> "Active",
 	ad_type_id		=> 1,
 	lineitem_id		=> $lineitem->{id}, # lineitem id for lineitem just created
 	size_id			=> $iab486x60, # IAB Full Banner 468x60
	click_url		=> 'http://openx.org',
	click_target_window	=> '_blank',
};
my $ad = rest({
	url => "$base_url/a/ad/",
	success => "created ad",
	post_args => $ad_args,
});


## 
## SUBroutines
##

# make a rest post or get call and deal with errors
sub rest {
	my ($args) = @_;

	# read arguments
	my $url = $args->{url};
	die "bad url: $url" unless $url =~ qr{^https?://};
	my $success = $args->{success} || "$url succeeded";
	my $post_args = $args->{post_args};
	my $debug = $args->{debug} || 0;

	my $decode_json = 1;
	$decode_json = $args->{decode_json} if defined $args->{decode_json};

	my $upload_file = $args->{upload_file};
	my $upload_file_field = $args->{upload_file_field};

	# web hit
	my $response;
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
	} elsif (defined $post_args) {
		$response = $ua->post($url,$post_args);
	} else {
		$response = $ua->get($url);
	}

	# how did it go?
	if ($response->is_success) { # TODO: log this as well
		my $content = $response->content;

		if ($debug) {
			print "$success\n";
			print "sent: " . Dumper($post_args) . "\n";
			jsondump($content);
			die "debug";
		}
		my $href;
		if ($decode_json) {
			$href = jsondecode($content);
		} else {
			$href = {
				content => $content,
				status_line => $response->status_line,
			}
		}
		if ( ref($href) eq 'HASH' and defined $href->{id} ) {
			print "$success id " . $href->{id} . "\n";
		} else {
			print "$success\n";
		}
		return $href;
	} else {
		die "$url failed: " . $response->status_line . "\n" . $response->content . "\nsent:" . Dumper($post_args);
	}
}

