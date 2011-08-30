use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'OX::OAuth',
    AUTHOR              => q{Christopher Hicks <chris.hicks@openx.org>},
    VERSION_FROM        => 'lib/OX/OAuth.pm',
    ABSTRACT_FROM       => 'lib/OX/OAuth.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
        'JSON' => 0,
        'Net::OAuth' => 0,
        'Data::Dumper' => 0,
        'HTTP::Request::Common' => 0,
        'Sub::Override' => 0,
        'LWP::UserAgent' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'OX-OAuth-*' },
);
