#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'OX::OAuth' );
}

diag( "Testing OX::OAuth $OX::OAuth::VERSION, Perl $], $^X" );
