# OX3-Perl-API-Client

The OX::OAuth module provides a convenient wrapper to Net::OAuth
to be able to access OpenX's oauth-compliant sso and authenticate
yourself.  Convenience functions are also provided to access the rest
API and read config files for oauth.

## INSTALLATION

To install this module, run the following commands:

```
perl Makefile.PL
make
make test
make install
```

## REQUIRED PERL MODULES

```
Test::More
JSON
Net::OAuth
HTTP::Request
Sub::Override
LWP::UserAgent from libwww-perl
File::Slurp
```

## SUPPORT AND DOCUMENTATION

After installing, you can find documentation for this module with the
perldoc command.

```
perldoc OX::OAuth
```

You can also look for information at:

* RT, CPAN's request tracker http://rt.cpan.org/NoAuth/Bugs.html?Dist=OX-OAuth
* AnnoCPAN, Annotated CPAN documentation, http://annocpan.org/dist/OX-OAuth
* CPAN Ratings,  http://cpanratings.perl.org/d/OX-OAuth
* Search CPAN,  http://search.cpan.org/dist/OX-OAuth/


## COPYRIGHT AND LICENCE

Copyright (C) 2011 Christopher Hicks

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License 2.0 as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.
