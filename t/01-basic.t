#!perl -T

# pragma
use warnings;
use strict;

#use Test::More tests => 1;
use Test::More qw(no_plan);
#use Data::Dumper;

#BEGIN {
#    use_ok( 'OX::OAuth' );
#}
#
#diag( "Testing OX::OAuth $OX::OAuth::VERSION, Perl $], $^X" );

use OX::OAuth;

my $empty_config = {
	api_url => 'http://blah.example.com/',
	sso_url => 'http://blah.example.com/',
	realm => 'blah',
	email => 'blah',
	password => 'blah',
	api_key => 'blah',
	api_secret => 'blah',
};

ok( OX::OAuth->new($empty_config), 'new empty' );

SKIP: {
	unless ( defined $ENV{OX3AUTH} ) {
		diag ("define OX3AUTH to get more and better tests");
		skip (": define OX3AUTH to get more and better tests", 6);
	}

	my $config = OX::OAuth->find_config();
	ok( $config, 'found config' );

	my $oauth = OX::OAuth->new($config);
	ok( $oauth, 'new oauth object' );
	isa_ok( $oauth, "OX::OAuth" );

	my $timezones = $oauth->rest({
		relative_url => "/a/account/timezoneOptions",
		quiet => 1,
	});
	ok( $timezones, 'get timezones');

	my $login_ret = $oauth->login();
	ok( $login_ret, 'log in' );

	ok( $oauth->token, 'get token');
}

__END__
